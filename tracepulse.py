#!/usr/bin/env python3
"""
TracePulse - Malicious Log Analyzer & Incident Summary Generator
==================================================================

Reads either (a) raw HTTP server access logs in Apache/Nginx combined
log format and flags known VAPT-style attack signatures (SQL Injection,
XSS, Directory Traversal) found in request URIs, or (b) Wazuh-style
"timestamp key=value ..." SIEM/HIDS event logs, using each line's own
event= label to identify incidents. The log format is auto-detected.
For every match it extracts the attacker IP/host, timestamp, target/
detail, severity (where available) and attack type, then renders a
clean SOC Incident Summary for analyst triage — including a "Top
Attacking IPs" repeat-offender rollup that correlates multiple
incidents back to the same source.

Triage features:
  * HTTP outcome triage  - each web alert is tagged with what the server
    did (blocked / not found / server error / possible success) using the
    response status code, so "attempted" can be told apart from "may have
    worked". Wazuh-style logs use their own action= field instead.
  * Scanner detection    - the User-Agent is checked for known attack/scan
    tools (sqlmap, Nikto, Nmap, Gobuster, ...). Scanner traffic is rolled
    up into one incident per (IP, tool) and also tagged on attack alerts.
  * Recommended action   - every alert carries a concrete next step,
    adjusted by outcome, instead of a generic "flagged for review".

Usage:
    python tracepulse.py --log sample_access.log
    python tracepulse.py --log sample_access.log --output report.txt
    python tracepulse.py --log sample_access.log --pdf report.pdf
    python tracepulse.py --log sample_access.log --json report.json

    # Or, run with no arguments and TracePulse will prompt you for the
    # path to the log file interactively:
    python tracepulse.py
"""

import argparse
import json
import os
import re
import sys
import textwrap
from collections import Counter
from datetime import datetime
from urllib.parse import unquote
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

# ---------------------------------------------------------------------------
# 1. SIGNATURE DEFINITIONS
# ---------------------------------------------------------------------------
# Each signature is a (label, compiled regex) pair. Regexes are matched
# against the *decoded* request URI (path + query string) taken from each
# log line. Patterns are intentionally broad/representative — tune them
# to your own VAPT payload set as needed.

SIGNATURES = [
    (
        "SQL Injection",
        re.compile(
            r"(\%27)|(\')|(--)|(\%23)|(#)|"
            r"(\b(select|union|insert|update|delete|drop|or|and)\b.{0,20}"
            r"(\b(from|where|table|by)\b|=|--|\%27|\'))",
            re.IGNORECASE,
        ),
    ),
    (
        "Cross-Site Scripting (XSS)",
        re.compile(
            r"(<script.*?>)|(%3Cscript)|(javascript:)|(onerror\s*=)|"
            r"(onload\s*=)|(<img[^>]+src)|(alert\s*\()",
            re.IGNORECASE,
        ),
    ),
    (
        "Directory Traversal",
        re.compile(
            r"(\.\./)|(\.\.\\)|(%2e%2e%2f)|(%2e%2e/)|(\.\.%2f)|"
            r"(/etc/passwd)|(boot\.ini)|(win\.ini)",
            re.IGNORECASE,
        ),
    ),
]

# ---------------------------------------------------------------------------
# 2. LOG LINE PARSER
# ---------------------------------------------------------------------------
# Matches standard Apache/Nginx "combined" log format:
# 127.0.0.1 - - [12/Sep/2026:10:00:00 +0000] "GET /path?x=1 HTTP/1.1" 200 512 "-" "Mozilla/5.0"
# The trailing "referrer" "user-agent" pair is optional, so older/common-format
# lines without it still parse (user_agent is simply None for those).

LOG_LINE_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<uri>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)


def parse_log_line(line):
    """Parse a single access-log line into a dict of fields, or None."""
    match = LOG_LINE_RE.search(line)
    if not match:
        return None
    return match.groupdict()


def classify_uri(uri):
    """Return the first matching attack signature label for a URI, or None.

    The URI is percent-decoded (up to twice, to catch double-encoding)
    before matching, since payloads are commonly sent %-encoded (e.g.
    %20 for a space, %27 for a quote) and matching the raw encoded text
    alone causes real false negatives — e.g. 'id=1%20UNION%20SELECT...'
    would not match a signature written against raw keywords, because
    each %20 eats 3 characters instead of 1, silently pushing the
    following keyword outside the regex's lookahead window.
    """
    decoded = uri
    for _ in range(2):
        new_decoded = unquote(decoded)
        if new_decoded == decoded:
            break
        decoded = new_decoded

    for label, pattern in SIGNATURES:
        if pattern.search(decoded) or pattern.search(uri):
            return label
    return None


# ---------------------------------------------------------------------------
# 2a. OUTCOME TRIAGE, SCANNER DETECTION, RECOMMENDED ACTIONS
# ---------------------------------------------------------------------------
# A signature match only says "someone TRIED something". What a SOC analyst
# needs next is "did it work?". These helpers add that context.
#
# NOTE: status-code triage is a heuristic, not proof. HTTP 200 does not
# guarantee an attack succeeded (many apps return 200 with an error page),
# and a 403/404 does not guarantee nothing leaked. Treat the label as a
# prioritisation aid: review "Possible success" and "Server error" first.

OUTCOME_CLASS_TITLES = {
    "possible_success": "Possible success (review first)",
    "server_error": "Server error (payload may have reached app)",
    "blocked": "Blocked / denied",
    "failed": "Failed / not found",
    "redirect": "Redirected (inconclusive)",
    "unknown": "Unknown (no status/action in log)",
}


def assess_http_outcome(status):
    """Map an HTTP status code to (outcome_class, human-readable label)."""
    try:
        code = int(status)
    except (TypeError, ValueError):
        return "unknown", "Unknown (no HTTP status in log)"
    if 200 <= code < 300:
        return "possible_success", f"Possible success (HTTP {code})"
    if 300 <= code < 400:
        return "redirect", f"Redirected (HTTP {code}) - inconclusive"
    if code in (400, 401, 403, 406, 429):
        return "blocked", f"Blocked/denied (HTTP {code})"
    if code in (404, 410):
        return "failed", f"Failed - not found (HTTP {code})"
    if 500 <= code < 600:
        return "server_error", f"Server error (HTTP {code}) - payload may have reached app"
    return "unknown", f"Unclassified (HTTP {code})"


# Wazuh-style logs carry their own action= verdict instead of an HTTP code.
BLOCKED_ACTIONS = {"BLOCKED", "DENIED", "DROPPED", "REJECTED", "PREVENTED"}
ALLOWED_ACTIONS = {"ALLOWED", "PERMITTED", "ACCEPTED", "PASSED"}


def assess_action_outcome(action):
    """Map a Wazuh-style action= value to (outcome_class, label)."""
    value = (action or "").strip().upper()
    if value in BLOCKED_ACTIONS:
        return "blocked", f"Blocked (action={value})"
    if value in ALLOWED_ACTIONS:
        return "possible_success", f"Allowed / not blocked (action={value})"
    if value:
        return "unknown", f"Unknown (action={value})"
    return "unknown", "Unknown (no action reported)"


# Known attack / scanning tools identified by their User-Agent string.
# Caveat: tools like Burp Suite and OWASP ZAP send a normal browser-style
# User-Agent by default, so they only show up here if the tester customised
# it. Absence of a match therefore does NOT prove traffic is human.
SCANNER_SIGNATURES = [
    ("sqlmap", re.compile(r"sqlmap", re.IGNORECASE)),
    ("Nikto", re.compile(r"nikto", re.IGNORECASE)),
    ("Nmap Scripting Engine", re.compile(r"nmap", re.IGNORECASE)),
    ("Masscan", re.compile(r"masscan", re.IGNORECASE)),
    ("Gobuster", re.compile(r"gobuster", re.IGNORECASE)),
    ("DirBuster", re.compile(r"dirbuster", re.IGNORECASE)),
    ("dirb", re.compile(r"\bdirb\b", re.IGNORECASE)),
    ("Wfuzz", re.compile(r"wfuzz", re.IGNORECASE)),
    ("ffuf", re.compile(r"\bffuf\b|fuzz faster u fool", re.IGNORECASE)),
    ("Hydra", re.compile(r"hydra", re.IGNORECASE)),
    ("Nuclei", re.compile(r"nuclei", re.IGNORECASE)),
    ("WPScan", re.compile(r"wpscan", re.IGNORECASE)),
    ("Acunetix", re.compile(r"acunetix", re.IGNORECASE)),
    ("Nessus", re.compile(r"nessus", re.IGNORECASE)),
    ("OpenVAS", re.compile(r"openvas", re.IGNORECASE)),
    ("w3af", re.compile(r"w3af", re.IGNORECASE)),
    ("Arachni", re.compile(r"arachni", re.IGNORECASE)),
    ("Metasploit", re.compile(r"metasploit", re.IGNORECASE)),
    ("Burp Suite", re.compile(r"\bburp", re.IGNORECASE)),
    ("OWASP ZAP", re.compile(r"zaproxy|owasp zap", re.IGNORECASE)),
]

SCANNER_LABEL = "Automated Scanner Detected"


def detect_scanner(user_agent):
    """Return the name of a known scanner/attack tool in a User-Agent, or None."""
    if not user_agent or user_agent == "-":
        return None
    for name, pattern in SCANNER_SIGNATURES:
        if pattern.search(user_agent):
            return name
    return None


def record_scanner_hit(scanner_hits, tool, fields, line_no):
    """Accumulate scanner traffic per (IP, tool) so a 5,000-request scan
    becomes ONE rolled-up incident instead of 5,000 alerts."""
    key = (fields["ip"], tool)
    hit = scanner_hits.get(key)
    if hit is None:
        hit = {
            "line_no": line_no,
            "first_ts": fields["timestamp"],
            "last_ts": fields["timestamp"],
            "count": 0,
            "statuses": Counter(),
            "sample_uri": fields["uri"],
            "user_agent": fields.get("user_agent"),
        }
        scanner_hits[key] = hit
    hit["count"] += 1
    hit["last_ts"] = fields["timestamp"]
    hit["statuses"][fields["status"]] += 1


# Base recommended action per attack type. The outcome prefix below is
# added on top so the same attack gets different urgency depending on
# whether it was blocked or may have succeeded.
RECOMMENDED_ACTIONS = {
    "SQL Injection": (
        "Review DB and application logs for the same timeframe, confirm the "
        "endpoint uses parameterized queries, add/verify a WAF rule, and "
        "block the source IP if it is not an authorized tester."
    ),
    "SQL Injection Attempt": (
        "Review DB and application logs for the same timeframe, confirm the "
        "endpoint uses parameterized queries, add/verify a WAF rule, and "
        "block the source IP if it is not an authorized tester."
    ),
    "Cross-Site Scripting (XSS)": (
        "Check whether the parameter is reflected or stored in any page, "
        "verify output encoding and Content-Security-Policy, and block the "
        "source IP if repeated."
    ),
    "Directory Traversal": (
        "Verify the server rejects path traversal, confirm the web root is "
        "properly confined, check that no sensitive file (e.g. /etc/passwd) "
        "was served, and block the source IP."
    ),
    "SSH Brute Force": (
        "Block the source IP, enforce key-based auth or rate limiting "
        "(fail2ban), and check auth logs for any successful login from it."
    ),
    "RDP Brute Force": (
        "Block the source IP, restrict RDP exposure (VPN/NLA), and check for "
        "any successful logon from the same source."
    ),
    "Port Scan": (
        "Block or rate-limit the source IP, review firewall rules for "
        "unnecessarily exposed ports, and watch for follow-up exploitation."
    ),
    "Windows Failed Logon": (
        "Check for repeated failures against the same account (possible "
        "password guessing), verify lockout policy, and confirm the user."
    ),
    "Suspicious PowerShell Activity": (
        "Isolate the host if unexplained, capture the command line and parent "
        "process, and check for persistence or downloaded payloads."
    ),
    "Web Shell Activity": (
        "Treat as likely compromise: isolate the server, locate and preserve "
        "the shell file, review recent uploads, and begin incident response."
    ),
    "Suspicious Successful Login (Geo Anomaly)": (
        "Contact the account owner to verify, force a password reset and "
        "session revocation if unconfirmed, and review post-login activity."
    ),
    "Privilege Escalation": (
        "Isolate the host, identify the account and method used, review "
        "changes to privileged groups/sudoers, and begin incident response."
    ),
    "Suspicious Outbound Connection (Possible C2)": (
        "Block the destination at the firewall, isolate the host, and hunt "
        "for the process making the connection (possible command-and-control)."
    ),
    "Suspicious File Created (Possible Malware)": (
        "Quarantine the file, hash it and check reputation (VirusTotal), and "
        "scan the host for related artifacts and persistence."
    ),
    "DNS Tunneling Indicator": (
        "Inspect the queried domains for long/high-entropy names, block the "
        "domain, and identify the host generating the queries."
    ),
    SCANNER_LABEL: (
        "Confirm whether this scan was authorized (e.g. your own VAPT "
        "engagement). If not, block the source IP and review which requests "
        "returned HTTP 200."
    ),
}

DEFAULT_ACTION = (
    "Verify the event against related logs, determine whether it is "
    "authorized or malicious, and escalate per the SOC runbook."
)

OUTCOME_PREFIX = {
    "possible_success": (
        "PRIORITY - the request was not blocked; check whether data was "
        "exposed or the payload executed. "
    ),
    "server_error": (
        "The payload may have triggered an application/DB error; review "
        "application error logs first. "
    ),
    "blocked": "Attempt appears blocked (lower urgency). ",
    "failed": "Attempt appears to have failed (lower urgency). ",
    "redirect": "Outcome inconclusive (redirect); verify the destination response. ",
}


def recommend_action(incident):
    """Build a concrete next step for an incident, adjusted by its outcome."""
    base = RECOMMENDED_ACTIONS.get(incident["attack_type"], DEFAULT_ACTION)
    return OUTCOME_PREFIX.get(incident.get("outcome_class"), "") + base


def build_web_incident(fields, line_no, attack_type, scanner=None):
    """Assemble an incident dict for a matched Apache/Nginx log line."""
    outcome_class, outcome = assess_http_outcome(fields.get("status"))
    incident = {
        "line_no": line_no,
        "attack_type": attack_type,
        "attacker_ip": fields["ip"],
        "timestamp": fields["timestamp"],
        "target_uri": fields["uri"],
        "severity": "N/A",
        "status": fields.get("status"),
        "outcome": outcome,
        "outcome_class": outcome_class,
        "scanner": scanner,
        "user_agent": fields.get("user_agent"),
    }
    incident["recommended_action"] = recommend_action(incident)
    return incident


def build_scanner_incident(ip, tool, hit):
    """Assemble the rolled-up incident for one (IP, scanner tool) pair."""
    mix = ", ".join(f"{code}x{n}" for code, n in hit["statuses"].most_common(4))
    incident = {
        "line_no": hit["line_no"],
        "attack_type": SCANNER_LABEL,
        "attacker_ip": ip,
        "timestamp": hit["first_ts"],
        "target_uri": (
            f"tool={tool}  requests={hit['count']}  status_mix={mix}  "
            f"first_uri={hit['sample_uri']}  last_seen={hit['last_ts']}"
        ),
        "severity": "N/A",
        "status": None,
        "outcome": f"Scan traffic - status mix: {mix}",
        "outcome_class": "info",
        "scanner": tool,
        "user_agent": hit.get("user_agent"),
    }
    incident["recommended_action"] = recommend_action(incident)
    return incident


def summarize_outcomes(incidents):
    """Count incidents per outcome class (scanner roll-ups excluded)."""
    counts = Counter(
        inc.get("outcome_class") for inc in incidents if inc.get("outcome_class") != "info"
    )
    return {key: counts.get(key, 0) for key in OUTCOME_CLASS_TITLES}


def summarize_scanners(incidents):
    """Return sorted unique (ip, tool) pairs for every scanner-tagged incident."""
    return sorted({(inc["attacker_ip"], inc["scanner"]) for inc in incidents if inc.get("scanner")})


# ---------------------------------------------------------------------------
# 2b. WAZUH-STYLE KEY=VALUE LOG PARSER
# ---------------------------------------------------------------------------
# Some SIEM/HIDS tools (e.g. Wazuh sample/training exports) emit a simpler,
# space-delimited "timestamp  key=value key=value ..." format instead of the
# Apache/Nginx combined format, e.g.:
#
#   2026-09-28 14:50:00 host=WEB-SRV01 service=nginx level=CRITICAL
#     event=SQL_INJECTION_ATTEMPT srcip=45.155.205.17 dstport=443 method=GET
#     uri=/login payload="' OR '1'='1" action=BLOCKED
#
# Unlike the combined format, these lines already carry an explicit event
# label (event=...), so no regex signature matching is needed — TracePulse
# instead treats every event that is NOT in BENIGN_WAZUH_EVENTS as an
# incident, and uses the event name itself (humanized) as the attack type.

WAZUH_LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<rest>.+)$"
)

# Matches key=value pairs where the value is either a "double-quoted string
# (which may contain spaces)" or a single whitespace-free token.
KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')

# Event labels considered routine/administrative — excluded from incidents.
BENIGN_WAZUH_EVENTS = {"NORMAL_ACTIVITY", "ANALYST_ACTIVITY"}

# Friendlier display labels for known event codes. Anything not listed here
# falls back to humanize_event()'s generic "Title Case With Spaces" output.
EVENT_LABEL_OVERRIDES = {
    "SQL_INJECTION_ATTEMPT": "SQL Injection Attempt",
    "DIRECTORY_TRAVERSAL": "Directory Traversal",
    "SSH_BRUTE_FORCE": "SSH Brute Force",
    "RDP_BRUTE_FORCE": "RDP Brute Force",
    "PORT_SCAN": "Port Scan",
    "WINDOWS_FAILED_LOGON": "Windows Failed Logon",
    "SUSPICIOUS_POWERSHELL": "Suspicious PowerShell Activity",
    "WEB_SHELL_ACTIVITY": "Web Shell Activity",
    "SUSPICIOUS_SUCCESSFUL_LOGIN": "Suspicious Successful Login (Geo Anomaly)",
    "PRIVILEGE_ESCALATION": "Privilege Escalation",
    "SUSPICIOUS_OUTBOUND_CONNECTION": "Suspicious Outbound Connection (Possible C2)",
    "SUSPICIOUS_FILE_CREATED": "Suspicious File Created (Possible Malware)",
    "DNS_TUNNELING_INDICATOR": "DNS Tunneling Indicator",
}


def humanize_event(event_code):
    """Turn an EVENT_CODE into a friendly label, preferring known overrides."""
    if event_code in EVENT_LABEL_OVERRIDES:
        return EVENT_LABEL_OVERRIDES[event_code]
    words = event_code.replace("_", " ").title().split()
    # Keep common security acronyms uppercase after title-casing.
    acronyms = {"Ssh": "SSH", "Rdp": "RDP", "Dns": "DNS", "Sql": "SQL", "Ip": "IP"}
    return " ".join(acronyms.get(w, w) for w in words)


def parse_wazuh_line(line):
    """Parse one Wazuh-style 'timestamp key=value ...' line into a dict, or None."""
    match = WAZUH_LINE_RE.match(line)
    if not match:
        return None
    fields = {"timestamp": match.group("timestamp")}
    for key, quoted_val, bare_val in KV_RE.findall(match.group("rest")):
        fields[key] = quoted_val if quoted_val or bare_val == "" else bare_val
    return fields


def detect_log_format(log_path):
    """Peek at the first few non-comment, non-blank lines to decide the
    log format: 'combined', 'wazuh_kv', or 'unknown'."""
    try:
        with open(log_path, "r", errors="ignore") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if LOG_LINE_RE.search(line):
                    return "combined"
                if WAZUH_LINE_RE.match(line):
                    return "wazuh_kv"
                return "unknown"
    except FileNotFoundError:
        return "unknown"
    return "unknown"


# ---------------------------------------------------------------------------
# 3. INGESTION + DETECTION
# ---------------------------------------------------------------------------

def analyze_log(log_path):
    """Read the log file line by line and return (incidents, stats).

    Auto-detects whether the file is a standard Apache/Nginx combined
    access log or a Wazuh-style 'timestamp key=value ...' log, and parses
    it accordingly. `stats` reports how many lines were read, parsed, and
    skipped, so a silent format mismatch (e.g. "Total Alerts: 0") can be
    told apart from a genuinely clean log — see Section 8 of the project
    report for why this matters from a false-negative standpoint.

    Each incident also carries an HTTP/action outcome, an optional scanner
    tool name (from the User-Agent), and a recommended next step.
    """
    incidents = []
    scanner_hits = {}  # (ip, tool) -> rolled-up scanner traffic stats
    stats = {"total_lines": 0, "parsed_lines": 0, "skipped_lines": 0, "format": "unknown"}

    log_format = detect_log_format(log_path)
    stats["format"] = log_format

    try:
        with open(log_path, "r", errors="ignore") as f:
            for line_no, raw_line in enumerate(f, start=1):
                raw_line = raw_line.strip()
                if not raw_line or raw_line.startswith("#"):
                    continue
                stats["total_lines"] += 1

                if log_format in ("combined", "unknown"):
                    # An 'unknown' format falls back to a best-effort
                    # combined-log parse per line (backward compatibility).
                    fields = parse_log_line(raw_line)
                    if not fields:
                        stats["skipped_lines"] += 1
                        continue
                    stats["parsed_lines"] += 1

                    # Scanner detection runs on EVERY parsed line, so a tool
                    # like Nikto is caught even when none of its requests
                    # match an attack signature.
                    scanner = detect_scanner(fields.get("user_agent"))
                    if scanner:
                        record_scanner_hit(scanner_hits, scanner, fields, line_no)

                    attack_type = classify_uri(fields["uri"])
                    if attack_type:
                        incidents.append(
                            build_web_incident(fields, line_no, attack_type, scanner)
                        )

                elif log_format == "wazuh_kv":
                    fields = parse_wazuh_line(raw_line)
                    if not fields:
                        stats["skipped_lines"] += 1
                        continue
                    stats["parsed_lines"] += 1

                    event = fields.get("event")
                    if not event or event in BENIGN_WAZUH_EVENTS:
                        continue  # benign / administrative — not an incident

                    # Prefer the most attack-specific fields first (an
                    # injected payload or command is more informative for
                    # triage than a repeated endpoint URI), then fall back
                    # to whatever other contextual fields the event carries
                    # (ports, user, attempt count, etc.) so events like
                    # SSH_BRUTE_FORCE or PORT_SCAN — which have no uri/
                    # payload/command field at all — still show useful
                    # detail instead of "N/A".
                    priority_keys = [
                        "payload", "uri", "command", "path", "query",
                        "user", "attempts", "dstport", "srcport", "dstip",
                        "protocol", "logon_type", "status", "result",
                        "connection", "bytes_out", "sha256", "signed",
                        "entropy", "authentication", "geo_anomaly",
                        "event_id", "action",
                    ]
                    detail_parts = []
                    for key in priority_keys:
                        if fields.get(key) and len(detail_parts) < 5:
                            detail_parts.append(f"{key}={fields[key]}")
                    detail = "  ".join(detail_parts) if detail_parts else "N/A"
                    # Not every event is network-sourced: an endpoint/host
                    # detection (e.g. SUSPICIOUS_POWERSHELL) has no srcip at
                    # all. Fall back to the hostname in that case, but tag it
                    # so it isn't mistaken for an attacker's network address.
                    if fields.get("srcip"):
                        attacker_ip = fields["srcip"]
                    elif fields.get("dstip"):
                        attacker_ip = fields["dstip"]
                    elif fields.get("host"):
                        attacker_ip = f"{fields['host']} (host)"
                    else:
                        attacker_ip = "N/A"

                    # Outcome comes from Wazuh's own action= verdict, and a
                    # scanner tool is tagged only if the event happens to
                    # carry a user-agent field.
                    outcome_class, outcome = assess_action_outcome(fields.get("action"))
                    user_agent = (
                        fields.get("user_agent") or fields.get("useragent") or fields.get("ua")
                    )
                    incident = {
                        "line_no": line_no,
                        "attack_type": humanize_event(event),
                        "attacker_ip": attacker_ip,
                        "timestamp": fields["timestamp"],
                        "target_uri": detail,
                        "severity": fields.get("level", "N/A"),
                        "status": None,
                        "outcome": outcome,
                        "outcome_class": outcome_class,
                        "scanner": detect_scanner(user_agent),
                        "user_agent": user_agent,
                    }
                    incident["recommended_action"] = recommend_action(incident)
                    incidents.append(incident)
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    # One rolled-up incident per (IP, scanner tool), then restore log order.
    for (ip, tool), hit in scanner_hits.items():
        incidents.append(build_scanner_incident(ip, tool, hit))
    incidents.sort(key=lambda inc: inc["line_no"])

    return incidents, stats


# ---------------------------------------------------------------------------
# 4. REPORT GENERATION
# ---------------------------------------------------------------------------

def compute_top_ips(incidents, top_n=5, repeat_threshold=3):
    """Aggregate incidents by attacker IP.

    This is a lightweight behavioral layer on top of the per-line
    signature/event matching above: an IP responsible for several
    incidents (e.g. a brute-force or scanning source hitting many
    lines) is flagged as a likely automated / high-priority source,
    independent of which specific signature each individual line
    matched. Returns a list of (ip, count, attack_types_set, is_repeat)
    tuples sorted by descending incident count.
    """
    counter = Counter(inc["attacker_ip"] for inc in incidents)
    types_by_ip = {}
    for inc in incidents:
        types_by_ip.setdefault(inc["attacker_ip"], set()).add(inc["attack_type"])

    ranked = counter.most_common(top_n)
    return [
        (ip, count, sorted(types_by_ip.get(ip, [])), count >= repeat_threshold)
        for ip, count in ranked
    ]


FORMAT_LABELS = {
    "combined": "Apache/Nginx combined access log",
    "wazuh_kv": "Wazuh-style key=value event log",
    "unknown": "Unrecognized (best-effort combined-log parsing attempted)",
}


def generate_report(incidents, log_path, stats=None):
    width = 62
    lines = []
    lines.append("=" * width)
    lines.append("TRACEPULSE SOC INCIDENT SUMMARY".center(width))
    lines.append("=" * width)
    lines.append(f"Source Log     : {log_path}")
    lines.append(f"Generated      : {datetime.now().strftime('%d/%b/%Y:%H:%M:%S')}")
    if stats:
        lines.append(f"Detected Format: {FORMAT_LABELS.get(stats['format'], stats['format'])}")
        lines.append(f"Lines Read     : {stats['total_lines']}")
        lines.append(f"Lines Parsed   : {stats['parsed_lines']}  (Skipped: {stats['skipped_lines']})")
    lines.append(f"Total Alerts   : {len(incidents)}")
    lines.append("=" * width)

    # Coverage warning: 0 alerts on a file where most/all lines failed to
    # parse is very different from 0 alerts on a fully-parsed clean log.
    if stats and stats["total_lines"] > 0 and stats["parsed_lines"] == 0:
        lines.append("[WARN] 0 of {0} lines matched a known log format.".format(stats["total_lines"]))
        lines.append("[WARN] This log may use a format TracePulse doesn't recognize yet.")
        lines.append("[WARN] 'Total Alerts: 0' here does NOT mean the log is clean.")
        lines.append("=" * width)

    if not incidents:
        lines.append("[INFO] No known attack signatures detected in this log.")
        lines.append("=" * width)
        return "\n".join(lines)

    top_ips = compute_top_ips(incidents)
    if top_ips:
        lines.append("TOP ATTACKING IPs (by incident count)".center(width))
        lines.append("-" * width)
        for ip, count, types, is_repeat in top_ips:
            tag = "  [REPEAT OFFENDER — likely automated]" if is_repeat else ""
            lines.append(f"  {ip:<18} {count:>3} incident(s)  {', '.join(types)}{tag}")
        lines.append("=" * width)

    # Outcome triage: "attempted" vs "may have worked".
    outcome_counts = summarize_outcomes(incidents)
    if any(outcome_counts.values()):
        lines.append("TRIAGE SUMMARY (what did the server do?)".center(width))
        lines.append("-" * width)
        for key, title in OUTCOME_CLASS_TITLES.items():
            if outcome_counts[key]:
                lines.append(f"  {outcome_counts[key]:>4}  {title}")
        lines.append("=" * width)

    scanner_pairs = summarize_scanners(incidents)
    if scanner_pairs:
        lines.append("SCANNER / ATTACK TOOLS DETECTED (from User-Agent)".center(width))
        lines.append("-" * width)
        for ip, tool in scanner_pairs:
            lines.append(f"  {ip:<18} {tool}")
        lines.append("=" * width)

    action_prefix = "[INFO]  Action       : "
    for idx, inc in enumerate(incidents):
        lines.append(f"[ALERT] Attack Type : {inc['attack_type']}")
        lines.append(f"[INFO]  Severity     : {inc.get('severity', 'N/A')}")
        lines.append(f"[INFO]  Source (IP/Host): {inc['attacker_ip']}")
        lines.append(f"[INFO]  Timestamp    : {inc['timestamp']}")
        lines.append(f"[INFO]  Target/Detail: {inc['target_uri']}")
        lines.append(f"[INFO]  Outcome      : {inc.get('outcome', 'N/A')}")
        if inc.get("scanner"):
            lines.append(f"[INFO]  Scanner Tool : {inc['scanner']}")
        lines.append(f"[INFO]  Log Line #   : {inc['line_no']}")
        lines.extend(
            textwrap.wrap(
                inc.get("recommended_action") or DEFAULT_ACTION,
                width=width,
                initial_indent=action_prefix,
                subsequent_indent=" " * len(action_prefix),
            )
        )
        if idx != len(incidents) - 1:
            lines.append("-" * width)

    lines.append("=" * width)
    return "\n".join(lines)


# Colors used to visually flag attack types in the PDF report.
ATTACK_COLORS = {
    "SQL Injection": colors.HexColor("#B00020"),
    "Cross-Site Scripting (XSS)": colors.HexColor("#B36B00"),
    "Directory Traversal": colors.HexColor("#7A1FA2"),
}
# Fallback color-coding by severity level, used for formats (like the Wazuh
# key=value log) whose attack types aren't in ATTACK_COLORS above.
SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#B00020"),
    "HIGH": colors.HexColor("#D9534F"),
    "MEDIUM": colors.HexColor("#B36B00"),
    "LOW": colors.HexColor("#5A6B7B"),
    "INFO": colors.HexColor("#5A6B7B"),
}
DEFAULT_ALERT_COLOR = colors.HexColor("#B00020")


def get_row_color(inc):
    """Pick a display color for an incident row: by known attack type first,
    then by severity level, then a default alert color."""
    if inc["attack_type"] in ATTACK_COLORS:
        return ATTACK_COLORS[inc["attack_type"]]
    severity = str(inc.get("severity", "")).upper()
    if severity in SEVERITY_COLORS:
        return SEVERITY_COLORS[severity]
    return DEFAULT_ALERT_COLOR


def generate_pdf_report(incidents, log_path, pdf_path, stats=None):
    """Render the SOC incident summary as a formatted PDF file."""
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TPTitle",
        parent=styles["Title"],
        textColor=colors.HexColor("#1A1A1A"),
        spaceAfter=4,
    )
    meta_style = ParagraphStyle(
        "TPMeta",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#444444"),
    )
    section_style = ParagraphStyle(
        "TPSection",
        parent=styles["Heading2"],
        fontSize=12,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=1,
    )
    cell_style = ParagraphStyle(
        "TPCell", parent=styles["Normal"], fontSize=8.5, leading=11
    )

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
        leftMargin=0.6 * inch,
        rightMargin=0.6 * inch,
        title="TracePulse SOC Incident Summary",
    )

    story = []
    story.append(Paragraph("TracePulse SOC Incident Summary", title_style))
    meta_bits = [
        f"Source Log: {log_path}",
        f"Generated: {datetime.now().strftime('%d %b %Y, %H:%M:%S')}",
        f"Total Alerts: {len(incidents)}",
    ]
    if stats:
        meta_bits.insert(1, f"Format: {FORMAT_LABELS.get(stats['format'], stats['format'])}")
        meta_bits.append(f"Lines Parsed: {stats['parsed_lines']}/{stats['total_lines']}")
    story.append(Paragraph(" &nbsp;|&nbsp; ".join(meta_bits), meta_style))
    story.append(Spacer(1, 12))

    if stats and stats["total_lines"] > 0 and stats["parsed_lines"] == 0:
        warn_style = ParagraphStyle(
            "TPWarn", parent=styles["Normal"], fontSize=9.5,
            textColor=colors.HexColor("#B00020"),
        )
        story.append(Paragraph(
            "WARNING: 0 of {0} lines matched a known log format. "
            "\u201cTotal Alerts: 0\u201d below does NOT mean this log is clean \u2014 "
            "it means TracePulse could not parse it. Verify the log format.".format(stats["total_lines"]),
            warn_style,
        ))
        story.append(Spacer(1, 10))

    if not incidents:
        story.append(
            Paragraph(
                "No known attack signatures were detected in this log.",
                styles["Normal"],
            )
        )
    else:
        # Summary counts by attack type
        counts = {}
        for inc in incidents:
            counts[inc["attack_type"]] = counts.get(inc["attack_type"], 0) + 1

        story.append(Paragraph("Alert Breakdown", section_style))
        summary_rows = [["Attack Type", "Count"]]
        for attack_type, count in sorted(counts.items(), key=lambda x: -x[1]):
            summary_rows.append([attack_type, str(count)])
        summary_table = Table(summary_rows, colWidths=[4.2 * inch, 1.5 * inch])
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A1A1A")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F2F2")]),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(summary_table)

        top_ips = compute_top_ips(incidents)
        if top_ips:
            story.append(Paragraph("Top Attacking IPs", section_style))
            ip_rows = [["Source (IP/Host)", "Incidents", "Attack Types", "Flag"]]
            for ip, count, types, is_repeat in top_ips:
                ip_rows.append([
                    Paragraph(xml_escape(ip), cell_style),
                    str(count),
                    Paragraph(xml_escape(", ".join(types)), cell_style),
                    Paragraph("REPEAT OFFENDER" if is_repeat else "", cell_style),
                ])
            ip_table = Table(ip_rows, colWidths=[1.3 * inch, 0.8 * inch, 3.0 * inch, 1.4 * inch])
            ip_style_cmds = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A1A1A")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F2F2")]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
            for row_idx, (ip, count, types, is_repeat) in enumerate(top_ips, start=1):
                if is_repeat:
                    ip_style_cmds.append(("TEXTCOLOR", (3, row_idx), (3, row_idx), colors.HexColor("#B00020")))
                    ip_style_cmds.append(("FONTNAME", (3, row_idx), (3, row_idx), "Helvetica-Bold"))
            ip_table.setStyle(TableStyle(ip_style_cmds))
            story.append(ip_table)
            story.append(Spacer(1, 10))

        # --- Triage summary (outcome of each attempt) ---
        outcome_counts = summarize_outcomes(incidents)
        if any(outcome_counts.values()):
            story.append(Paragraph("Triage Summary (what did the server do?)", section_style))
            triage_rows = [["Outcome", "Count"]]
            for key, title in OUTCOME_CLASS_TITLES.items():
                if outcome_counts[key]:
                    triage_rows.append([title, str(outcome_counts[key])])
            triage_table = Table(triage_rows, colWidths=[4.2 * inch, 1.5 * inch])
            triage_style_cmds = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A1A1A")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F2F2")]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
            for row_idx, row in enumerate(triage_rows[1:], start=1):
                if row[0] == OUTCOME_CLASS_TITLES["possible_success"]:
                    triage_style_cmds.append(("TEXTCOLOR", (0, row_idx), (-1, row_idx), colors.HexColor("#B00020")))
                    triage_style_cmds.append(("FONTNAME", (0, row_idx), (-1, row_idx), "Helvetica-Bold"))
            triage_table.setStyle(TableStyle(triage_style_cmds))
            story.append(triage_table)

        # --- Scanner / attack tools detected ---
        scanner_pairs = summarize_scanners(incidents)
        if scanner_pairs:
            story.append(Paragraph("Scanner / Attack Tools Detected (from User-Agent)", section_style))
            scanner_rows = [["Source (IP/Host)", "Tool"]]
            for ip, tool in scanner_pairs:
                scanner_rows.append([Paragraph(xml_escape(ip), cell_style), Paragraph(xml_escape(tool), cell_style)])
            scanner_table = Table(scanner_rows, colWidths=[2.5 * inch, 3.2 * inch])
            scanner_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A1A1A")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F2F2")]),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            story.append(scanner_table)

        # --- Recommended actions, one row per attack type ---
        story.append(Paragraph("Recommended Actions", section_style))
        action_rows = [["Attack Type", "Count", "Recommended Action"]]
        for attack_type, count in sorted(counts.items(), key=lambda x: -x[1]):
            action_rows.append(
                [
                    Paragraph(xml_escape(attack_type), cell_style),
                    str(count),
                    Paragraph(xml_escape(RECOMMENDED_ACTIONS.get(attack_type, DEFAULT_ACTION)), cell_style),
                ]
            )
        action_table = Table(action_rows, colWidths=[1.7 * inch, 0.6 * inch, 4.9 * inch], repeatRows=1)
        action_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A1A1A")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 8.5),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F2F2")]),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(action_table)
        story.append(Spacer(1, 10))

        story.append(Paragraph("Incident Detail", section_style))
        detail_rows = [["#", "Attack Type", "Sev.", "Source (IP/Host)", "Timestamp", "Outcome", "Target / Detail", "Line"]]
        for idx, inc in enumerate(incidents, start=1):
            outcome_text = xml_escape(inc.get("outcome") or "N/A")
            if inc.get("outcome_class") == "possible_success":
                outcome_text = f'<font color="#B00020"><b>{outcome_text}</b></font>'
            detail_text = xml_escape(inc["target_uri"])
            row_hex = "#" + get_row_color(inc).hexval()[2:]
            type_text = f'<font color="{row_hex}">{xml_escape(inc["attack_type"])}</font>'
            sev_text = f'<font color="{row_hex}"><b>{xml_escape(str(inc.get("severity", "N/A")))}</b></font>'
            if inc.get("scanner") and inc["attack_type"] != SCANNER_LABEL:
                detail_text += f"<br/><i>Tool: {xml_escape(inc['scanner'])}</i>"
            detail_rows.append(
                [
                    str(idx),
                    Paragraph(type_text, cell_style),
                    Paragraph(sev_text, cell_style),
                    Paragraph(xml_escape(inc["attacker_ip"]), cell_style),
                    Paragraph(xml_escape(inc["timestamp"]), cell_style),
                    Paragraph(outcome_text, cell_style),
                    Paragraph(detail_text, cell_style),
                    str(inc["line_no"]),
                ]
            )

        detail_table = Table(
            detail_rows,
            colWidths=[0.25 * inch, 0.95 * inch, 0.65 * inch, 0.95 * inch, 1.25 * inch, 1.0 * inch, 1.85 * inch, 0.4 * inch],
            repeatRows=1,
        )
        table_style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A1A1A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8.5),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F7F7")]),
        ]
        # Color-code the attack type + severity columns per row.
        # (Per-row attack-type / severity colouring is applied via <font> markup
        # in the cells above, because Paragraph cells ignore TableStyle colours.)

        detail_table.setStyle(TableStyle(table_style_cmds))
        story.append(detail_table)

    doc.build(story)
    return pdf_path


def generate_json_report(incidents, log_path, stats, json_path):
    """Export incidents + run metadata as machine-readable JSON.

    This makes TracePulse's output pluggable into other tooling (a
    ticketing system, a SIEM ingest pipeline, a dashboard) rather than
    being locked into human-only text/PDF output — the kind of
    integration point a real SOC/Red-Team toolchain is expected to have.
    """
    payload = {
        "source_log": log_path,
        "generated": datetime.now().isoformat(),
        "detected_format": stats.get("format") if stats else None,
        "lines_read": stats.get("total_lines") if stats else None,
        "lines_parsed": stats.get("parsed_lines") if stats else None,
        "lines_skipped": stats.get("skipped_lines") if stats else None,
        "total_alerts": len(incidents),
        "top_attacking_ips": [
            {"ip": ip, "incident_count": count, "attack_types": types, "repeat_offender": is_repeat}
            for ip, count, types, is_repeat in compute_top_ips(incidents)
        ],
        "outcome_summary": summarize_outcomes(incidents),
        "scanner_tools": [
            {"ip": ip, "tool": tool} for ip, tool in summarize_scanners(incidents)
        ],
        "incidents": incidents,
    }
    with open(json_path, "w") as f:
        json.dump(payload, f, indent=2)
    return json_path


# ---------------------------------------------------------------------------
# 5. CLI ENTRY POINT
# ---------------------------------------------------------------------------

def prompt_for_log_path():
    """Interactively ask the user for a log file path until a valid one is given."""
    while True:
        try:
            user_path = input("Enter path to the access log file to analyze: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[ERROR] No log file provided. Exiting.", file=sys.stderr)
            sys.exit(1)

        # Strip accidental surrounding quotes (common when paths are pasted)
        user_path = user_path.strip('"').strip("'")

        if not user_path:
            print("[WARN] Path cannot be empty. Please try again.")
            continue
        if not os.path.isfile(user_path):
            print(f"[WARN] File not found: {user_path}. Please try again.")
            continue

        return user_path


def prompt_yes_no(question, default=False):
    """Ask a yes/no question interactively and return a bool."""
    suffix = " [Y/n]: " if default else " [y/N]: "
    try:
        answer = input(question + suffix).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    if not answer:
        return default
    return answer.startswith("y")


def main():
    parser = argparse.ArgumentParser(
        description="TracePulse - Malicious Log Analyzer & Incident Summary Generator"
    )
    parser.add_argument(
        "--log",
        required=False,
        help="Path to the access log file to analyze. If omitted, TracePulse "
        "will prompt for a path interactively.",
    )
    parser.add_argument(
        "--output", help="Optional file path to save the text report (in addition to printing it)"
    )
    parser.add_argument(
        "--pdf",
        nargs="?",
        const="__PROMPT__",
        default=None,
        metavar="PDF_PATH",
        help="Save the SOC incident summary as a PDF. Optionally pass a file "
        "path (e.g. --pdf report.pdf); if omitted, defaults to "
        "<log_name>_soc_report.pdf",
    )
    parser.add_argument(
        "--json",
        nargs="?",
        const="__PROMPT__",
        default=None,
        metavar="JSON_PATH",
        help="Save the incident data as machine-readable JSON (for SIEM/"
        "ticketing integration). Optionally pass a file path; if omitted, "
        "defaults to <log_name>_soc_report.json",
    )
    args = parser.parse_args()

    # Resolve the log file: use --log if given and valid, otherwise prompt.
    log_path = args.log
    if not log_path or not os.path.isfile(log_path):
        if log_path:
            print(f"[WARN] File not found: {log_path}")
        log_path = prompt_for_log_path()

    incidents, stats = analyze_log(log_path)
    report = generate_report(incidents, log_path, stats)

    print(report)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report + "\n")
        print(f"\n[INFO] Report saved to {args.output}")

    # Resolve PDF output path. --pdf with no value prompts the user (or, if
    # --pdf was never passed at all, offer it as an interactive option).
    pdf_path = None
    if args.pdf == "__PROMPT__":
        default_name = f"{os.path.splitext(os.path.basename(log_path))[0]}_soc_report.pdf"
        try:
            typed = input(
                f"Enter PDF output path [{default_name}]: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            typed = ""
        pdf_path = typed or default_name
    elif args.pdf:
        pdf_path = args.pdf
    elif args.pdf is None and sys.stdin.isatty():
        if prompt_yes_no("\nSave this SOC report as a PDF?"):
            default_name = f"{os.path.splitext(os.path.basename(log_path))[0]}_soc_report.pdf"
            try:
                typed = input(f"Enter PDF output path [{default_name}]: ").strip()
            except (EOFError, KeyboardInterrupt):
                typed = ""
            pdf_path = typed or default_name

    if pdf_path:
        generate_pdf_report(incidents, log_path, pdf_path, stats)
        print(f"[INFO] PDF report saved to {pdf_path}")

    # Resolve JSON output path (same optional-value pattern as --pdf).
    json_path = None
    if args.json == "__PROMPT__":
        default_name = f"{os.path.splitext(os.path.basename(log_path))[0]}_soc_report.json"
        try:
            typed = input(f"Enter JSON output path [{default_name}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            typed = ""
        json_path = typed or default_name
    elif args.json:
        json_path = args.json

    if json_path:
        generate_json_report(incidents, log_path, stats, json_path)
        print(f"[INFO] JSON report saved to {json_path}")


if __name__ == "__main__":
    main()
