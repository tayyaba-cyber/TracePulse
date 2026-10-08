#!/usr/bin/env python3
"""
TracePulse Dashboard - a simple GUI for TracePulse
===================================================

Runs a small web app on YOUR computer (nothing is uploaded to the internet).
Pick a log file in the browser and get:
  * KPI cards, bar charts, an outcome donut, a timeline
  * Top attacking IPs, scanner tools, recommended actions
  * A searchable / filterable incident list
  * A "Download PDF" button that produces a report with charts

All detection logic comes from tracepulse.py (keep it in the same folder).
No extra packages needed beyond what tracepulse.py already uses (reportlab).

Usage:
    python tracepulse_gui.py
    python tracepulse_gui.py --port 9000 --no-browser
"""

import argparse
import csv
import html
import io
import json
import math
import os
import re
import sys
import tempfile
import threading
import uuid
import webbrowser
from collections import Counter, OrderedDict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote
from xml.sax.saxutils import escape as xml_escape

# --- import the analyzer (tracepulse.py, or the uploaded tracepulse_1_.py) ---
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
try:
    import tracepulse as tp
except ImportError:
    try:
        import tracepulse_1_ as tp  # type: ignore
    except ImportError:
        sys.exit(
            "[ERROR] Could not find tracepulse.py next to this file.\n"
            "Put tracepulse.py (your analyzer) in the same folder as tracepulse_gui.py."
        )

from reportlab.graphics.charts.barcharts import HorizontalBarChart, VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

MAX_UPLOAD_BYTES = 4 * 1024 * 1024 * 1024   # 4 GB safety limit (streamed to disk)
MAX_TABLE_ROWS = None                  # None = show ALL incidents (set a number to cap)
MAX_STORED_RESULTS = 10                # analyses kept in memory for PDF download

# ---------------------------------------------------------------------------
# 1. SUMMARY (shared by the web dashboard and the PDF)
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
PALETTE = ["#ff5c7a", "#ffa94d", "#b388ff", "#4dabf7", "#3ddc97",
           "#ffd43b", "#f783ac", "#66d9e8", "#a9e34b", "#ced4da"]
OUTCOME_COLORS = {
    "possible_success": "#ff5c7a",
    "server_error": "#ffa94d",
    "redirect": "#ffd43b",
    "unknown": "#8b98a9",
    "failed": "#4dabf7",
    "blocked": "#3ddc97",
    "info": "#66d9e8",
}
SEVERITY_COLORS = {
    "CRITICAL": "#ff5c7a", "HIGH": "#ffa94d", "MEDIUM": "#ffd43b",
    "LOW": "#4dabf7", "INFO": "#8b98a9",
}


def parse_timestamp(text):
    """Best-effort parse of both supported timestamp styles (naive datetime)."""
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=None)
        except (ValueError, TypeError):
            continue
    return None


def build_timeline(incidents):
    """Bucket incidents by hour (or by day if the log spans > 3 days)."""
    stamps = [parse_timestamp(i["timestamp"]) for i in incidents]
    stamps = [s for s in stamps if s]
    if not stamps:
        return [], "hour"
    span_hours = (max(stamps) - min(stamps)).total_seconds() / 3600
    unit = "hour" if span_hours <= 72 else "day"
    fmt = "%d %b %H:00" if unit == "hour" else "%d %b %Y"
    key = (lambda d: d.replace(minute=0, second=0, microsecond=0)) if unit == "hour" \
        else (lambda d: d.replace(hour=0, minute=0, second=0, microsecond=0))
    counts = Counter(key(s) for s in stamps)
    ordered = sorted(counts.items())
    if len(ordered) > 60:  # keep the chart readable
        ordered = ordered[-60:]
    return [(k.strftime(fmt), v) for k, v in ordered], unit


def build_summary(incidents, stats):
    type_counts = Counter(i["attack_type"] for i in incidents).most_common()
    ip_counts = Counter(i["attacker_ip"] for i in incidents)
    outcomes = tp.summarize_outcomes(incidents)
    sev_counter = Counter(str(i.get("severity", "N/A")).upper() for i in incidents)
    sev_counter.pop("N/A", None)
    severities = [(s, sev_counter[s]) for s in SEVERITY_ORDER if s in sev_counter]
    severities += [(s, c) for s, c in sev_counter.items() if s not in SEVERITY_ORDER]
    timeline, unit = build_timeline(incidents)
    return {
        "total": len(incidents),
        "type_counts": type_counts,
        "top_ips": tp.compute_top_ips(incidents, top_n=10),
        "unique_sources": len(ip_counts),
        "repeat_offenders": sum(1 for c in ip_counts.values() if c >= 3),
        "outcomes": outcomes,
        "needs_review": outcomes.get("possible_success", 0) + outcomes.get("server_error", 0),
        "scanners": tp.summarize_scanners(incidents),
        "severities": severities,
        "crit_high": sev_counter.get("CRITICAL", 0) + sev_counter.get("HIGH", 0),
        "timeline": timeline,
        "timeline_unit": unit,
        "unparsed_warning": bool(stats["total_lines"] > 0 and stats["parsed_lines"] == 0),
    }


# ---------------------------------------------------------------------------
# 2. HTML DASHBOARD RENDERING
# ---------------------------------------------------------------------------

def e(value):
    return html.escape(str(value), quote=True)


def type_color_map(type_counts):
    return {name: PALETTE[i % len(PALETTE)] for i, (name, _c) in enumerate(type_counts)}


def html_bars(items, color_for):
    """Horizontal bar list. items = [(label, value)]"""
    if not items:
        return '<div class="empty">No data</div>'
    peak = max(v for _l, v in items) or 1
    rows = []
    for label, value in items:
        width = max(2.0, 100.0 * value / peak)
        rows.append(
            f'<div class="bar-row"><div class="bar-label" title="{e(label)}">{e(label)}</div>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{width:.1f}%;'
            f'background:{color_for(label)}"></div></div>'
            f'<div class="bar-val">{value}</div></div>'
        )
    return "".join(rows)


def html_donut(pairs, total_label):
    """pairs = [(label, value, color)] with value > 0"""
    total = sum(v for _l, v, _c in pairs)
    if total == 0:
        return '<div class="empty">No data</div>'
    circles, offset = [], 25.0
    for _label, value, color in pairs:
        pct = 100.0 * value / total
        circles.append(
            f'<circle cx="21" cy="21" r="15.91549" fill="none" stroke="{color}" '
            f'stroke-width="6" stroke-dasharray="{pct:.3f} {100 - pct:.3f}" '
            f'stroke-dashoffset="{offset:.3f}"></circle>'
        )
        offset -= pct
    legend = "".join(
        f'<div class="leg"><span class="dot" style="background:{c}"></span>'
        f'<span class="leg-name">{e(l)}</span><b>{v}</b></div>'
        for l, v, c in pairs
    )
    return (
        '<div class="donut-wrap"><svg viewBox="0 0 42 42" class="donut">'
        '<circle cx="21" cy="21" r="15.91549" fill="none" stroke="rgba(255,255,255,.06)" '
        'stroke-width="6"></circle>' + "".join(circles) +
        f'<text x="21" y="21.5" text-anchor="middle" class="donut-num">{total}</text>'
        f'<text x="21" y="26" text-anchor="middle" class="donut-sub">{e(total_label)}</text>'
        f'</svg><div class="legend">{legend}</div></div>'
    )


def html_timeline(timeline, unit):
    if len(timeline) < 1:
        return '<div class="empty">No parsable timestamps</div>'
    w, h, pad_l, pad_b, pad_t = 640.0, 190.0, 34.0, 30.0, 14.0
    peak = max(v for _l, v in timeline) or 1
    plot_w, plot_h = w - pad_l - 8, h - pad_b - pad_t
    slot = plot_w / len(timeline)
    bar_w = max(2.0, min(34.0, slot * 0.7))
    parts = []
    for frac in (0, 0.5, 1):
        y = pad_t + plot_h * (1 - frac)
        parts.append(f'<line x1="{pad_l}" x2="{w - 8}" y1="{y:.1f}" y2="{y:.1f}" class="grid"/>')
        parts.append(f'<text x="{pad_l - 6}" y="{y + 3:.1f}" text-anchor="end" class="axis">'
                     f'{peak * frac:.0f}</text>')
    for idx, (label, value) in enumerate(timeline):
        bh = plot_h * value / peak
        x = pad_l + idx * slot + (slot - bar_w) / 2
        y = pad_t + plot_h - bh
        parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{bh:.1f}" '
                     f'rx="2" class="tbar"><title>{e(label)}: {value}</title></rect>')
    step = max(1, math.ceil(len(timeline) / 8))
    for idx in range(0, len(timeline), step):
        x = pad_l + idx * slot + slot / 2
        parts.append(f'<text x="{x:.1f}" y="{h - 10}" text-anchor="middle" class="axis">'
                     f'{e(timeline[idx][0])}</text>')
    return (f'<svg viewBox="0 0 {w:.0f} {h:.0f}" class="timeline" role="img" '
            f'aria-label="Alerts per {unit}">' + "".join(parts) + "</svg>")


def badge(text, color):
    return f'<span class="badge" style="--c:{color}">{e(text)}</span>'


def render_dashboard(filename, incidents, stats, summary):
    s = summary
    tcolors = type_color_map(s["type_counts"])
    fmt_label = tp.FORMAT_LABELS.get(stats["format"], stats["format"])
    out = []

    out.append(
        '<div class="result-head"><div><h2>Analysis results</h2>'
        f'<div class="meta"><b>{e(filename)}</b> &middot; {e(fmt_label)} &middot; '
        f'{stats["parsed_lines"]}/{stats["total_lines"]} lines parsed '
        f'({stats["skipped_lines"]} skipped) &middot; {e(datetime.now().strftime("%d %b %Y, %H:%M"))}'
        '</div></div>'
        '<div class="head-actions"><a class="btn primary" id="pdfBtn" href="#">&#11015; Download PDF report</a></div></div>'
    )

    if s["unparsed_warning"]:
        out.append('<div class="banner bad"><b>Warning:</b> none of the '
                   f'{stats["total_lines"]} lines matched a known log format. '
                   '"0 alerts" here does <b>not</b> mean the log is clean &mdash; it could not be parsed.</div>')
    elif s["total"] == 0:
        out.append('<div class="banner good"><b>All clear:</b> no known attack signatures were detected in this log.</div>')
    elif s["needs_review"]:
        out.append(f'<div class="banner bad"><b>{s["needs_review"]} alert(s) need review first</b> '
                   '&mdash; the server did not block them (possible success / server error).</div>')
    else:
        out.append('<div class="banner warn">Attacks were detected, but none appear to have succeeded '
                   '(status-code triage is a heuristic &mdash; always verify).</div>')

    kpis = [
        ("Total alerts", s["total"], "#4dabf7"),
        ("Unique sources", s["unique_sources"], "#b388ff"),
        ("Need review first", s["needs_review"], "#ff5c7a"),
        ("Repeat offenders", s["repeat_offenders"], "#ffa94d"),
        ("Scanner tools", len({t for _ip, t in s["scanners"]}), "#3ddc97"),
    ]
    if s["severities"]:
        kpis.insert(3, ("Critical / High", s["crit_high"], "#ff5c7a"))
    out.append('<div class="kpis">' + "".join(
        f'<div class="kpi" style="--c:{c}"><div class="kpi-num">{v}</div>'
        f'<div class="kpi-lbl">{e(l)}</div></div>' for l, v, c in kpis) + "</div>")

    if s["total"]:
        outcome_pairs = [(tp.OUTCOME_CLASS_TITLES[k], v, OUTCOME_COLORS[k])
                         for k, v in s["outcomes"].items() if v]
        out.append('<div class="grid2">')
        out.append('<section class="card"><h3>Attacks by type</h3>' +
                   html_bars(s["type_counts"], lambda l: tcolors.get(l, "#4dabf7")) + "</section>")
        out.append('<section class="card"><h3>What did the server do? (outcome triage)</h3>' +
                   html_donut(outcome_pairs, "triaged") +
                   '<div class="hint">Scanner roll-up incidents are not triaged, so this total can be lower than "Total alerts".</div></section>')
        ip_items = [(ip, c) for ip, c, _t, _r in s["top_ips"]]
        repeat_ips = {ip for ip, _c, _t, r in s["top_ips"] if r}
        out.append('<section class="card"><h3>Top attacking sources</h3>' +
                   html_bars(ip_items, lambda l: "#ff5c7a" if l in repeat_ips else "#4dabf7") +
                   '<div class="hint"><span class="dot" style="background:#ff5c7a"></span> repeat offender (3+ incidents)</div></section>')
        if s["severities"]:
            sev_pairs = [(n, c, SEVERITY_COLORS.get(n, "#8b98a9")) for n, c in s["severities"]]
            out.append('<section class="card"><h3>Severity levels</h3>' +
                       html_donut(sev_pairs, "with severity") + "</section>")
        else:
            out.append('<section class="card"><h3>Severity levels</h3><div class="empty">'
                       'This log format has no severity field.</div></section>')
        out.append("</div>")

        out.append(f'<section class="card wide"><h3>Alerts over time (per {s["timeline_unit"]})</h3>' +
                   html_timeline(s["timeline"], s["timeline_unit"]) + "</section>")

        if s["scanners"]:
            rows = "".join(f"<tr><td>{e(ip)}</td><td>{e(tool)}</td></tr>" for ip, tool in s["scanners"])
            out.append('<section class="card wide"><h3>Scanner / attack tools detected (from User-Agent)</h3>'
                       f'<table class="mini"><thead><tr><th>Source</th><th>Tool</th></tr></thead><tbody>{rows}</tbody></table></section>')

        type_options = "".join(f'<option value="{e(n)}">{e(n)} ({c})</option>' for n, c in s["type_counts"])
        outcome_options = "".join(
            f'<option value="{k}">{e(tp.OUTCOME_CLASS_TITLES[k])}</option>'
            for k, v in s["outcomes"].items() if v)
        shown = incidents if MAX_TABLE_ROWS is None else incidents[:MAX_TABLE_ROWS]
        trs = []
        for n, inc in enumerate(shown, start=1):
            oc = inc.get("outcome_class") or "unknown"
            sev = str(inc.get("severity", "N/A"))
            sev_html = badge(sev, SEVERITY_COLORS.get(sev.upper(), "#8b98a9")) if sev != "N/A" else '<span class="dim">N/A</span>'
            tool = f'<div class="tool">Tool: {e(inc["scanner"])}</div>' if inc.get("scanner") and inc["attack_type"] != tp.SCANNER_LABEL else ""
            trs.append(
                f'<tr data-type="{e(inc["attack_type"])}" data-outcome="{e(oc)}">'
                f"<td>{n}</td>"
                f'<td>{badge(inc["attack_type"], tcolors.get(inc["attack_type"], "#4dabf7"))}</td>'
                f"<td>{sev_html}</td>"
                f'<td class="mono">{e(inc["attacker_ip"])}</td>'
                f'<td class="nowrap">{e(inc["timestamp"])}</td>'
                f'<td>{badge(inc.get("outcome") or "N/A", OUTCOME_COLORS.get(oc, "#8b98a9"))}</td>'
                f'<td class="detail mono">{e(inc["target_uri"])}{tool}</td>'
                f'<td>{inc["line_no"]}</td>'
                f'<td><details><summary>View</summary><div class="action">{e(inc.get("recommended_action") or tp.DEFAULT_ACTION)}</div></details></td>'
                "</tr>"
            )
        note = (f'<div class="hint">Showing the first {MAX_TABLE_ROWS} of {len(incidents)} incidents. '
                'Use "Download all incidents (CSV)" for the full list.</div>'
                if MAX_TABLE_ROWS is not None and len(incidents) > MAX_TABLE_ROWS else "")
        out.append(
            '<section class="card wide"><h3>Incident list</h3>'
            '<div class="filters">'
            '<input id="fSearch" type="search" placeholder="Search IP, URI, detail...">'
            f'<select id="fType"><option value="">All attack types</option>{type_options}</select>'
            f'<select id="fOutcome"><option value="">All outcomes</option>{outcome_options}</select>'
            '<a class="btn" id="csvBtn" href="#">&#11015; All incidents (CSV)</a>'
            '<span id="fCount" class="hint"></span></div>'
            '<div class="table-wrap"><table class="inc" id="incTable"><thead><tr>'
            "<th>#</th><th>Attack type</th><th>Severity</th><th>Source</th><th>Timestamp</th>"
            "<th>Outcome</th><th>Target / detail</th><th>Line</th><th>Action</th></tr></thead>"
            f'<tbody>{"".join(trs)}</tbody></table></div>'
            '<div class="pager"><button class="btn" id="pgPrev">&larr; Prev</button>'
            '<span id="pgInfo" class="hint"></span><button class="btn" id="pgNext">Next &rarr;</button>'
            '<label class="hint">Rows per page <select id="pgSize"><option>50</option><option selected>100</option>'
            f'<option>250</option><option>500</option></select></label></div>{note}</section>'
        )

        action_rows = "".join(
            f'<tr><td>{badge(n, tcolors.get(n, "#4dabf7"))}</td><td>{c}</td>'
            f'<td>{e(tp.RECOMMENDED_ACTIONS.get(n, tp.DEFAULT_ACTION))}</td></tr>'
            for n, c in s["type_counts"])
        out.append('<section class="card wide"><h3>Recommended actions</h3><div class="table-wrap">'
                   '<table class="mini"><thead><tr><th>Attack type</th><th>Count</th><th>Recommended action</th></tr></thead>'
                   f"<tbody>{action_rows}</tbody></table></div></section>")
    return "".join(out)


# ---------------------------------------------------------------------------
# 3. PDF REPORT (with charts)
# ---------------------------------------------------------------------------

DARK = colors.HexColor("#1A1A1A")


def pdf_text(value):
    """Make text safe for reportlab's built-in Helvetica (Latin-1) + XML markup."""
    text = str(value)
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", text)
    text = text.encode("latin-1", "replace").decode("latin-1")
    return xml_escape(text)


def short(text, n):
    text = str(text)
    return text if len(text) <= n else text[: n - 1] + "\u2026"


def styled_table(rows, col_widths, valign="MIDDLE", font=8.5, repeat=1):
    table = Table(rows, colWidths=col_widths, repeatRows=repeat)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), font),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F4F6F8")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("VALIGN", (0, 0), (-1, -1), valign),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def drawing_title(d, text, width):
    d.add(String(0, d.height - 10, text, fontName="Helvetica-Bold", fontSize=9.5,
                 fillColor=colors.HexColor("#333333")))


def pdf_bar_chart(title, items, width=250, vertical=False, bar_colors=None):
    """items = [(label, value)]. Returns a reportlab Drawing."""
    n = max(1, len(items))
    height = 40 + (105 if vertical else 20 * n)
    d = Drawing(width, height)
    drawing_title(d, title, width)
    if not items:
        d.add(String(0, height - 40, "No data", fontSize=8, fillColor=colors.grey))
        return d
    peak = max(v for _l, v in items) or 1
    step = max(1, math.ceil(peak / 5))
    if vertical:
        chart = VerticalBarChart()
        chart.x, chart.y, chart.width, chart.height = 28, 34, width - 36, height - 60
        chart.categoryAxis.labels.angle = 30
        chart.categoryAxis.labels.boxAnchor = "ne"
        chart.categoryAxis.labels.dy = -2
        chart.data = [[v for _l, v in items]]
        chart.categoryAxis.categoryNames = [short(l, 12) for l, _v in items]
    else:
        ordered = list(reversed(items))  # HorizontalBarChart draws bottom-up
        chart = HorizontalBarChart()
        chart.x, chart.y, chart.width, chart.height = 138, 8, width - 172, height - 34
        chart.data = [[v for _l, v in ordered]]
        chart.categoryAxis.categoryNames = [short(l, 30) for l, _v in ordered]
        chart.categoryAxis.labels.boxAnchor = "e"
        chart.categoryAxis.labels.dx = -4
        items = ordered
    chart.categoryAxis.labels.fontName = "Helvetica"
    chart.categoryAxis.labels.fontSize = 7
    chart.categoryAxis.visibleTicks = 0
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = peak + step
    chart.valueAxis.valueStep = step
    chart.valueAxis.labels.fontSize = 7
    chart.valueAxis.visibleGrid = 1
    chart.valueAxis.gridStrokeColor = colors.HexColor("#E3E6EA")
    chart.groupSpacing = 4
    chart.barSpacing = 1
    chart.bars[0].fillColor = colors.HexColor("#4dabf7")
    chart.bars.strokeColor = None
    if bar_colors:
        for idx, (label, _v) in enumerate(items):
            chart.bars[(0, idx)].fillColor = colors.HexColor(bar_colors(label))
    chart.barLabelFormat = "%d"
    chart.barLabels.fontSize = 7
    chart.barLabels.nudge = 7 if vertical else 8
    chart.barLabels.boxAnchor = "s" if vertical else "w"
    if not vertical:
        chart.barLabels.nudge = 2
    d.add(chart)
    return d


def pdf_pie(title, pairs, width=250):
    """pairs = [(label, value, hex)] with value > 0."""
    height = 40 + max(120, 14 * len(pairs))
    d = Drawing(width, height)
    drawing_title(d, title, width)
    total = sum(v for _l, v, _c in pairs)
    if total == 0:
        d.add(String(0, height - 40, "No data", fontSize=8, fillColor=colors.grey))
        return d
    pie = Pie()
    pie.x, pie.y, pie.width, pie.height = 4, height - 30 - 100, 100, 100
    pie.data = [v for _l, v, _c in pairs]
    pie.labels = None
    pie.sideLabels = 0
    pie.slices.strokeColor = colors.white
    pie.slices.strokeWidth = 1
    for idx, (_l, _v, hexcol) in enumerate(pairs):
        pie.slices[idx].fillColor = colors.HexColor(hexcol)
    d.add(pie)
    y = height - 38
    for label, value, hexcol in pairs:
        d.add(Rect(116, y - 1, 7, 7, fillColor=colors.HexColor(hexcol), strokeColor=None))
        d.add(String(128, y, f"{short(label, 30)}: {value}", fontName="Helvetica", fontSize=7))
        y -= 14
    return d


def generate_dashboard_pdf(filename, incidents, stats, summary):
    """Build the PDF report in memory and return the bytes."""
    s = summary
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("T", parent=styles["Title"], textColor=DARK, spaceAfter=4)
    meta_style = ParagraphStyle("M", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#444444"))
    section = ParagraphStyle("S", parent=styles["Heading2"], fontSize=12, spaceBefore=14,
                             spaceAfter=6, keepWithNext=1)
    cell = ParagraphStyle("C", parent=styles["Normal"], fontSize=8, leading=10.5)
    cell_wrap = ParagraphStyle("CW", parent=cell, wordWrap="CJK")  # breaks long URIs anywhere
    kpi_num = ParagraphStyle("KN", parent=styles["Normal"], fontSize=20, leading=24, alignment=1,
                             fontName="Helvetica-Bold")
    kpi_lbl = ParagraphStyle("KL", parent=styles["Normal"], fontSize=8, leading=10, alignment=1,
                             textColor=colors.HexColor("#555555"))

    def P(text, style=cell):
        return Paragraph(pdf_text(text), style)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch,
                            leftMargin=0.6 * inch, rightMargin=0.6 * inch,
                            title="TracePulse SOC Incident Summary")
    full_w = 7.3 * inch
    story = [Paragraph("TracePulse SOC Incident Summary", title_style)]
    fmt_label = tp.FORMAT_LABELS.get(stats["format"], stats["format"])
    story.append(Paragraph(
        pdf_text(f"Source Log: {filename}  |  Format: {fmt_label}  |  "
                 f"Generated: {datetime.now().strftime('%d %b %Y, %H:%M:%S')}  |  "
                 f"Lines parsed: {stats['parsed_lines']}/{stats['total_lines']}"), meta_style))
    story.append(Spacer(1, 10))

    if s["unparsed_warning"]:
        story.append(Paragraph(
            pdf_text(f"WARNING: none of the {stats['total_lines']} lines matched a known log format. "
                     "\"0 alerts\" does NOT mean this log is clean - it could not be parsed."),
            ParagraphStyle("W", parent=styles["Normal"], textColor=colors.HexColor("#B00020"), fontSize=9.5)))
    if s["total"] == 0:
        if not s["unparsed_warning"]:
            story.append(Paragraph("No known attack signatures were detected in this log.", styles["Normal"]))
        doc.build(story)
        return buffer.getvalue()

    # KPI strip
    kpis = [("Total alerts", s["total"]), ("Unique sources", s["unique_sources"]),
            ("Need review first", s["needs_review"]), ("Repeat offenders", s["repeat_offenders"]),
            ("Scanner tools", len({t for _ip, t in s["scanners"]}))]
    if s["severities"]:
        kpis.insert(3, ("Critical / High", s["crit_high"]))
    kw = full_w / len(kpis)
    kpi_table = Table([[Paragraph(str(v), kpi_num) for _l, v in kpis],
                       [Paragraph(pdf_text(l), kpi_lbl) for l, _v in kpis]], colWidths=[kw] * len(kpis))
    kpi_table.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E3E6EA")),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F4F6F8")),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 10))

    # Charts
    tcolors = type_color_map(s["type_counts"])
    outcome_pairs = [(tp.OUTCOME_CLASS_TITLES[k].split(" (")[0], v, OUTCOME_COLORS[k]) for k, v in s["outcomes"].items() if v]
    half = 3.55 * inch

    def two_up(left, right):
        t = Table([[left, right]], colWidths=[half, half])
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
        return t

    story.append(Paragraph("Dashboard", section))
    story.append(two_up(
        pdf_bar_chart("Attacks by type", s["type_counts"][:8], width=250,
                      bar_colors=lambda l: tcolors.get(l, "#4dabf7")),
        pdf_pie("Outcome triage", outcome_pairs, width=250)))
    story.append(Spacer(1, 6))
    repeat_ips = {ip for ip, _c, _t, r in s["top_ips"] if r}
    ip_chart = pdf_bar_chart("Top attacking sources", [(ip, c) for ip, c, _t, _r in s["top_ips"][:8]],
                             width=250, bar_colors=lambda l: "#E03B5A" if l in repeat_ips else "#4dabf7")
    if s["severities"]:
        sev_chart = pdf_pie("Severity levels", [(n, c, SEVERITY_COLORS.get(n, "#8b98a9")) for n, c in s["severities"]], width=250)
    else:
        sev_chart = Drawing(250, 20)
    story.append(two_up(ip_chart, sev_chart))
    if len(s["timeline"]) >= 2:
        story.append(Spacer(1, 6))
        story.append(pdf_bar_chart(f"Alerts over time (per {s['timeline_unit']})", s["timeline"],
                                   width=520, vertical=True))

    # Top IPs
    story.append(Paragraph("Top Attacking Sources", section))
    rows = [["Source (IP/Host)", "Incidents", "Attack types", "Flag"]]
    for ip, count, types, is_repeat in s["top_ips"]:
        rows.append([P(ip), str(count), P(", ".join(types)), P("REPEAT OFFENDER" if is_repeat else "")])
    story.append(styled_table(rows, [1.5 * inch, 0.8 * inch, 3.6 * inch, 1.4 * inch]))

    # Triage
    triage = [["Outcome", "Count"]] + [[tp.OUTCOME_CLASS_TITLES[k], str(v)] for k, v in s["outcomes"].items() if v]
    if len(triage) > 1:
        story.append(Paragraph("Triage Summary (what did the server do?)", section))
        story.append(styled_table(triage, [4.6 * inch, 1.2 * inch]))

    # Scanners
    if s["scanners"]:
        story.append(Paragraph("Scanner / Attack Tools Detected", section))
        rows = [["Source (IP/Host)", "Tool"]] + [[P(ip), P(t)] for ip, t in s["scanners"]]
        story.append(styled_table(rows, [2.6 * inch, 3.4 * inch]))

    # Recommended actions
    story.append(Paragraph("Recommended Actions", section))
    rows = [["Attack type", "Count", "Recommended action"]]
    for name, count in s["type_counts"]:
        rows.append([P(name), str(count), P(tp.RECOMMENDED_ACTIONS.get(name, tp.DEFAULT_ACTION))])
    story.append(styled_table(rows, [1.7 * inch, 0.6 * inch, 5.0 * inch], valign="TOP"))

    # Incident detail
    story.append(Paragraph("Incident Detail", section))
    rows = [["#", "Attack type", "Sev.", "Source", "Timestamp", "Outcome", "Target / detail", "Line"]]
    pdf_rows = incidents if MAX_TABLE_ROWS is None else incidents[:MAX_TABLE_ROWS]
    for n, inc in enumerate(pdf_rows, start=1):
        hexcol = "#" + tp.get_row_color(inc).hexval()[2:]
        detail = pdf_text(short(inc["target_uri"], 300))
        if inc.get("scanner") and inc["attack_type"] != tp.SCANNER_LABEL:
            detail += f"<br/><i>Tool: {pdf_text(inc['scanner'])}</i>"
        outcome = pdf_text(inc.get("outcome") or "N/A")
        if inc.get("outcome_class") == "possible_success":
            outcome = f'<font color="#B00020"><b>{outcome}</b></font>'
        rows.append([
            str(n),
            Paragraph(f'<font color="{hexcol}">{pdf_text(inc["attack_type"])}</font>', cell),
            Paragraph(f'<font color="{hexcol}"><b>{pdf_text(inc.get("severity", "N/A"))}</b></font>', cell),
            P(inc["attacker_ip"]), P(inc["timestamp"]),
            Paragraph(outcome, cell), Paragraph(detail, cell_wrap), str(inc["line_no"]),
        ])
    detail_table = styled_table(
        rows, [0.3 * inch, 1.0 * inch, 0.6 * inch, 0.95 * inch, 1.2 * inch, 1.0 * inch, 1.8 * inch, 0.45 * inch],
        font=8)
    detail_table.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3)]))
    story.append(detail_table)
    if MAX_TABLE_ROWS is not None and len(incidents) > MAX_TABLE_ROWS:
        story.append(Spacer(1, 4))
        story.append(P(f"Showing the first {MAX_TABLE_ROWS} of {len(incidents)} incidents.", meta_style))

    def footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#777777"))
        canvas.drawString(0.6 * inch, 0.35 * inch, "TracePulse SOC Incident Summary")
        canvas.drawRightString(letter[0] - 0.6 * inch, 0.35 * inch, f"Page {doc_.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# 4. WEB SERVER
# ---------------------------------------------------------------------------

RESULTS = OrderedDict()   # id -> {"filename", "incidents", "stats", "summary", "pdf"}
RESULTS_LOCK = threading.Lock()


def run_analysis(data_path, display_name):
    """Run TracePulse on a saved file; returns (incidents, stats)."""
    try:
        return tp.analyze_log(data_path)
    except SystemExit:  # analyze_log calls sys.exit() on a missing file
        raise RuntimeError("Log file could not be read.")


INDEX_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TracePulse Dashboard</title>
<style>
:root{--bg:#0b1220;--panel:#121b2e;--panel2:#18233a;--line:#243452;--text:#e6edf7;--dim:#8b98a9;
--accent:#4dabf7;--red:#ff5c7a;--green:#3ddc97;--amber:#ffa94d}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 10% -10%,#16264a 0,var(--bg) 60%);color:var(--text);
font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;min-height:100vh}
.wrap{max-width:1200px;margin:0 auto;padding:24px 20px 60px}
header{display:flex;align-items:center;gap:14px;margin-bottom:22px}
.logo{width:42px;height:42px;border-radius:12px;background:linear-gradient(135deg,#4dabf7,#b388ff);
display:grid;place-items:center;font-weight:800;font-size:20px;color:#0b1220}
h1{margin:0;font-size:22px;letter-spacing:.3px}
.sub{color:var(--dim);font-size:13px}
#drop{border:2px dashed var(--line);border-radius:16px;padding:34px 20px;text-align:center;background:var(--panel);
transition:.15s;cursor:pointer}
#drop.over{border-color:var(--accent);background:var(--panel2)}
#drop .big{font-size:17px;font-weight:600;margin-bottom:6px}
#drop .small{color:var(--dim);font-size:13px}
.btn{display:inline-block;border:1px solid var(--line);background:var(--panel2);color:var(--text);
padding:9px 16px;border-radius:10px;text-decoration:none;font-weight:600;cursor:pointer;font-size:14px}
.btn.primary{background:linear-gradient(135deg,#4dabf7,#7c6cf0);border:0;color:#fff}
.btn:hover{filter:brightness(1.12)}
#status{margin:14px 0;color:var(--dim);min-height:20px}
#status.err{color:var(--red)}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid var(--line);border-top-color:var(--accent);
border-radius:50%;animation:sp .8s linear infinite;vertical-align:-2px;margin-right:8px}
@keyframes sp{to{transform:rotate(360deg)}}
.result-head{display:flex;justify-content:space-between;align-items:flex-end;gap:12px;flex-wrap:wrap;margin:26px 0 14px}
.result-head h2{margin:0;font-size:20px}
.meta{color:var(--dim);font-size:13px;margin-top:2px;word-break:break-all}
.banner{padding:12px 16px;border-radius:12px;margin-bottom:16px;border:1px solid}
.banner.bad{background:rgba(255,92,122,.1);border-color:rgba(255,92,122,.5)}
.banner.warn{background:rgba(255,169,77,.1);border-color:rgba(255,169,77,.5)}
.banner.good{background:rgba(61,220,151,.1);border-color:rgba(61,220,151,.5)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.kpi{background:var(--panel);border:1px solid var(--line);border-top:3px solid var(--c);border-radius:14px;padding:14px 16px}
.kpi-num{font-size:30px;font-weight:800;color:var(--c);line-height:1.1}
.kpi-lbl{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.6px;margin-top:4px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:14px;margin-bottom:14px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px 18px;min-width:0}
.card.wide{margin-bottom:14px}
.card h3{margin:0 0 12px;font-size:14px;color:#c9d6ea;letter-spacing:.3px}
.bar-row{display:grid;grid-template-columns:minmax(90px,38%) 1fr 36px;gap:10px;align-items:center;margin:7px 0}
.bar-label{font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar-track{background:rgba(255,255,255,.06);border-radius:8px;height:14px;overflow:hidden}
.bar-fill{height:100%;border-radius:8px}
.bar-val{text-align:right;font-weight:700;font-size:13px}
.donut-wrap{display:flex;align-items:center;gap:20px;flex-wrap:wrap}
.donut{width:170px;height:170px;transform:rotate(0deg)}
.donut-num{fill:var(--text);font-size:7px;font-weight:800}
.donut-sub{fill:var(--dim);font-size:2.6px}
.legend{flex:1;min-width:170px}
.leg{display:flex;align-items:center;gap:8px;margin:5px 0;font-size:13px}
.leg-name{flex:1}
.dot{display:inline-block;width:10px;height:10px;border-radius:3px}
.hint{color:var(--dim);font-size:12px;margin-top:8px}
.empty{color:var(--dim);padding:14px 0}
.timeline{width:100%;height:auto}
.timeline .grid{stroke:rgba(255,255,255,.08)}
.timeline .axis{fill:var(--dim);font-size:10px}
.timeline .tbar{fill:#4dabf7}
.filters{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
input[type=search],select{background:var(--panel2);border:1px solid var(--line);color:var(--text);
padding:8px 10px;border-radius:9px;font-size:13px}
input[type=search]{min-width:240px}
.table-wrap{overflow-x:auto;max-height:620px;overflow-y:auto;border-radius:10px;border:1px solid var(--line)}
table{border-collapse:collapse;width:100%}
th{position:sticky;top:0;background:#1d2a45;text-align:left;font-size:12px;text-transform:uppercase;
letter-spacing:.5px;color:#b8c7de;padding:9px 10px;white-space:nowrap}
td{padding:8px 10px;border-top:1px solid var(--line);vertical-align:top;font-size:13px}
tr:hover td{background:rgba(255,255,255,.025)}
table.mini th{position:static}
.mono{font-family:ui-monospace,Consolas,Menlo,monospace;font-size:12px}
.detail{max-width:340px;word-break:break-all}
.nowrap{white-space:nowrap}
.tool{color:var(--dim);font-style:italic;margin-top:3px;font-family:inherit}
.dim{color:var(--dim)}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600;
color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent);border:1px solid color-mix(in srgb,var(--c) 45%,transparent)}
details summary{cursor:pointer;color:var(--accent);font-weight:600}
.action{margin-top:6px;max-width:320px;color:#c9d6ea}
.pager{display:flex;gap:12px;align-items:center;justify-content:center;margin-top:12px;flex-wrap:wrap}
.btn:disabled{opacity:.4;cursor:default}
footer{color:var(--dim);font-size:12px;margin-top:30px;text-align:center}
</style></head>
<body><div class="wrap">
<header><div class="logo">TP</div><div><h1>TracePulse Dashboard</h1>
<div class="sub">Malicious log analyzer &middot; runs locally on your computer</div></div></header>

<div id="drop">
  <div class="big">Drop a log file here, or click to choose one</div>
  <div class="small">Apache/Nginx combined access logs and Wazuh-style key=value logs (.log, .txt)</div>
  <input id="file" type="file" hidden>
</div>
<div id="status"></div>
<div id="result"></div>
<footer>TracePulse &middot; results are heuristic triage aids &mdash; always verify before acting.</footer>
</div>
<script>
const drop=document.getElementById('drop'),fileInput=document.getElementById('file'),
      statusEl=document.getElementById('status'),resultEl=document.getElementById('result');
drop.addEventListener('click',()=>fileInput.click());
fileInput.addEventListener('change',()=>{if(fileInput.files[0])upload(fileInput.files[0]);});
['dragenter','dragover'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.add('over');}));
['dragleave','drop'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.remove('over');}));
drop.addEventListener('drop',e=>{const f=e.dataTransfer.files[0];if(f)upload(f);});

function setStatus(html,err){statusEl.className=err?'err':'';statusEl.innerHTML=html;}

async function upload(file){
  resultEl.innerHTML='';
  setStatus('<span class="spinner"></span>Analyzing '+file.name.replace(/</g,'&lt;')+' ...');
  try{
    const resp=await fetch('/analyze',{method:'POST',
      headers:{'X-Filename':encodeURIComponent(file.name)},body:file});
    let data;
    try{data=await resp.json();}catch(_){throw new Error('Server returned an unexpected response (HTTP '+resp.status+').');}
    if(!data.ok)throw new Error(data.error||'Analysis failed.');
    statusEl.textContent='';statusEl.className='';
    resultEl.innerHTML=data.html;
    document.getElementById('pdfBtn').href='/pdf/'+data.id;
    const cb=document.getElementById('csvBtn');if(cb)cb.href='/csv/'+data.id;
    setupPdf(data.id);
    setupFilters();
    resultEl.scrollIntoView({behavior:'smooth'});
  }catch(err){
    statusEl.className='err';statusEl.textContent='Error: '+err.message;
  }finally{fileInput.value='';}
}

function setupPdf(id){
  const btn=document.getElementById('pdfBtn');
  btn.addEventListener('click',async ev=>{
    ev.preventDefault();
    if(btn.dataset.busy)return;
    btn.dataset.busy='1';const label=btn.innerHTML;
    btn.innerHTML='<span class="spinner"></span>Generating PDF (large logs can take a minute)...';
    try{
      const r=await fetch('/pdf/'+id);
      if(!r.ok)throw new Error(await r.text());
      const blob=await r.blob();
      const cd=r.headers.get('Content-Disposition')||'';
      const m=/filename="([^"]+)"/.exec(cd);
      const a=document.createElement('a');
      a.href=URL.createObjectURL(blob);a.download=m?m[1]:'tracepulse_report.pdf';
      document.body.appendChild(a);a.click();a.remove();
      setTimeout(()=>URL.revokeObjectURL(a.href),10000);
    }catch(err){alert('PDF failed: '+err.message);}
    finally{btn.innerHTML=label;delete btn.dataset.busy;}
  });
}

function setupFilters(){
  const t=document.getElementById('incTable');if(!t)return;
  const s=document.getElementById('fSearch'),ty=document.getElementById('fType'),
        oc=document.getElementById('fOutcome'),cnt=document.getElementById('fCount'),
        prev=document.getElementById('pgPrev'),next=document.getElementById('pgNext'),
        info=document.getElementById('pgInfo'),size=document.getElementById('pgSize');
  const rows=Array.from(t.tBodies[0].rows);
  rows.forEach(r=>{r._txt=r.textContent.toLowerCase();r.style.display='none';});
  let matches=rows,page=0;
  function render(){
    const ps=parseInt(size.value,10),pages=Math.max(1,Math.ceil(matches.length/ps));
    if(page>=pages)page=pages-1;if(page<0)page=0;
    const from=page*ps,to=from+ps;
    rows.forEach(r=>{r.style.display='none';});
    for(let i=from;i<Math.min(to,matches.length);i++)matches[i].style.display='';
    cnt.textContent='Matching '+matches.length+' of '+rows.length;
    info.textContent='Page '+(page+1)+' of '+pages;
    prev.disabled=page<=0;next.disabled=page>=pages-1;
  }
  function filter(){
    const q=s.value.trim().toLowerCase();
    matches=rows.filter(r=>(!ty.value||r.dataset.type===ty.value)&&(!oc.value||r.dataset.outcome===oc.value)&&
                           (!q||r._txt.includes(q)));
    page=0;render();
  }
  [s,ty,oc].forEach(el=>el.addEventListener('input',filter));
  size.addEventListener('change',()=>{page=0;render();});
  prev.addEventListener('click',()=>{page--;render();});
  next.addEventListener('click',()=>{page++;render();});
  filter();
}
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "TracePulseGUI/1.0"

    def log_message(self, fmt, *args):  # keep the console quiet
        pass

    def _send(self, code, body, ctype, extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, payload):
        self._send(code, json.dumps(payload), "application/json; charset=utf-8")

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send(200, INDEX_HTML, "text/html; charset=utf-8")
        elif path.startswith("/pdf/"):
            rid = path[len("/pdf/"):]
            with RESULTS_LOCK:
                res = RESULTS.get(rid)
            if not res:
                self._send(404, "Report not found. Please analyze the log again.", "text/plain; charset=utf-8")
                return
            try:
                if res["pdf"] is None:
                    res["pdf"] = generate_dashboard_pdf(res["filename"], res["incidents"], res["stats"], res["summary"])
            except Exception as exc:  # pragma: no cover
                self._send(500, f"PDF generation failed: {exc}", "text/plain; charset=utf-8")
                return
            base = os.path.splitext(res["filename"])[0] or "report"
            safe = re.sub(r"[^A-Za-z0-9._-]+", "_", base)[:60] or "report"
            self._send(200, res["pdf"], "application/pdf",
                       {"Content-Disposition": f'attachment; filename="{safe}_tracepulse_report.pdf"'})
        elif path.startswith("/csv/"):
            rid = path[len("/csv/"):]
            with RESULTS_LOCK:
                res = RESULTS.get(rid)
            if not res:
                self._send(404, "Report not found. Please analyze the log again.", "text/plain; charset=utf-8")
                return
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["#", "attack_type", "severity", "source", "timestamp", "outcome",
                        "http_status", "scanner_tool", "target_detail", "log_line", "recommended_action"])
            for n, inc in enumerate(res["incidents"], start=1):
                w.writerow([n, inc["attack_type"], inc.get("severity", "N/A"), inc["attacker_ip"],
                            inc["timestamp"], inc.get("outcome") or "", inc.get("status") or "",
                            inc.get("scanner") or "", inc["target_uri"], inc["line_no"],
                            inc.get("recommended_action") or ""])
            base = re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.splitext(res["filename"])[0])[:60] or "report"
            self._send(200, "\ufeff" + buf.getvalue(), "text/csv; charset=utf-8",
                       {"Content-Disposition": f'attachment; filename="{base}_incidents.csv"'})
        elif path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
        else:
            self._send(404, "Not found", "text/plain; charset=utf-8")

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/analyze":
            self._send(404, "Not found", "text/plain; charset=utf-8")
            return
        tmp_path = None
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                self._json(400, {"ok": False, "error": "The selected file is empty."})
                return
            if length > MAX_UPLOAD_BYTES:
                self.close_connection = True
                self._json(413, {"ok": False, "error": "File is too large (limit 4 GB)."})
                return
            raw_name = unquote(self.headers.get("X-Filename") or "uploaded.log")
            filename = os.path.basename(raw_name.replace("\\", "/")) or "uploaded.log"

            fd, tmp_path = tempfile.mkstemp(prefix="tracepulse_", suffix=".log")
            remaining = length
            with os.fdopen(fd, "wb") as tmp:
                while remaining > 0:
                    chunk = self.rfile.read(min(1 << 20, remaining))
                    if not chunk:
                        break
                    tmp.write(chunk)
                    remaining -= len(chunk)
            if remaining > 0:
                self._json(400, {"ok": False, "error": "Upload was interrupted. Please try again."})
                return

            incidents, stats = run_analysis(tmp_path, filename)
            summary = build_summary(incidents, stats)
            page = render_dashboard(filename, incidents, stats, summary)
            rid = uuid.uuid4().hex
            with RESULTS_LOCK:
                RESULTS[rid] = {"filename": filename, "incidents": incidents, "stats": stats,
                                "summary": summary, "pdf": None}
                while len(RESULTS) > MAX_STORED_RESULTS:
                    RESULTS.popitem(last=False)
            self._json(200, {"ok": True, "id": rid, "html": page})
        except Exception as exc:
            self._json(500, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass


def main():
    parser = argparse.ArgumentParser(description="TracePulse Dashboard (local web GUI)")
    parser.add_argument("--port", type=int, default=8765, help="Port to listen on (default 8765)")
    parser.add_argument("--no-browser", action="store_true", help="Do not open the browser automatically")
    args = parser.parse_args()

    server = None
    for port in range(args.port, args.port + 20):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            break
        except OSError:
            continue
    if server is None:
        sys.exit(f"[ERROR] Could not open a port between {args.port} and {args.port + 19}.")

    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"TracePulse Dashboard running at {url}")
    print("Press Ctrl+C to stop.")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
