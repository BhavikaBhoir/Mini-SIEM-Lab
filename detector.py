"""
detector.py — Advanced threat detection engine for Mini SIEM
"""

import re
import os

# ==============================
# THREAT SIGNATURES
# ==============================

THREAT_SIGNATURES = [
    {
        "pattern":     r"Failed login|authentication failure|invalid password",
        "type":        "Brute Force Attempt",
        "severity":    "High",
        "description": "Repeated failed authentication detected — possible credential stuffing",
    },
    {
        "pattern":     r"SQL Injection|UNION SELECT|' OR '1'='1|--\s*$|DROP TABLE|EXEC\s*\(",
        "type":        "SQL Injection",
        "severity":    "Critical",
        "description": "SQL injection payload detected in request — database at risk",
    },
    {
        "pattern":     r"Port scan(ning)?|nmap|masscan|SYN flood",
        "type":        "Port Scan",
        "severity":    "Medium",
        "description": "Network reconnaissance activity detected from source IP",
    },
    {
        "pattern":     r"Malware|trojan|ransomware|backdoor|rootkit|exploit\.kit",
        "type":        "Malware Detection",
        "severity":    "Critical",
        "description": "Malware signature matched in traffic or file hash",
    },
    {
        "pattern":     r"Unauthorized admin|privilege escalation|sudo.*failed|access denied.*root",
        "type":        "Unauthorized Access",
        "severity":    "High",
        "description": "Unauthorized privilege escalation or admin access attempt",
    },
    {
        "pattern":     r"XSS|<script|javascript:|onerror=|onload=",
        "type":        "XSS Attack",
        "severity":    "Medium",
        "description": "Cross-Site Scripting payload identified in user input",
    },
    {
        "pattern":     r"DDoS|volumetric attack|traffic spike|flood detected",
        "type":        "DDoS Attack",
        "severity":    "Critical",
        "description": "Distributed Denial-of-Service traffic pattern detected",
    },
    {
        "pattern":     r"C2|command.and.control|beacon|exfiltration|data leak",
        "type":        "C2 Communication",
        "severity":    "Critical",
        "description": "Possible command-and-control beacon or data exfiltration attempt",
    },
    {
        "pattern":     r"phishing|suspicious link|fake login|credential harvest",
        "type":        "Phishing Attempt",
        "severity":    "High",
        "description": "Phishing indicator detected — suspicious URL or form submission",
    },
    {
        "pattern":     r"lateral movement|pass.the.hash|mimikatz|kerberoast",
        "type":        "Lateral Movement",
        "severity":    "Critical",
        "description": "Lateral movement technique detected — attacker may be inside network",
    },
]

# ==============================
# IP EXTRACTOR
# ==============================

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def extract_ip(log_line: str) -> str:
    match = _IP_RE.search(log_line)
    return match.group() if match else "Unknown"

# ==============================
# LOG READER
# ==============================

LOG_PATH = os.path.join(os.path.dirname(__file__), "logs", "auth.log")

def read_logs() -> list[str]:
    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as fh:
            return fh.readlines()
    except FileNotFoundError:
        return []
    except Exception as exc:
        print(f"[log_reader] ERROR: {exc}")
        return []

# ==============================
# THREAT DETECTION
# ==============================

def detect_threats() -> list[dict]:
    """
    Parse log lines and match against THREAT_SIGNATURES.
    Returns a list of threat dicts ready for DB insertion.
    """
    logs = read_logs()
    detected: list[dict] = []

    compiled = [
        (re.compile(sig["pattern"], re.IGNORECASE), sig)
        for sig in THREAT_SIGNATURES
    ]

    for line in logs:
        line = line.strip()
        if not line:
            continue
        ip = extract_ip(line)
        for pattern, sig in compiled:
            if pattern.search(line):
                detected.append({
                    "type":        sig["type"],
                    "severity":    sig["severity"],
                    "ip":          ip,
                    "description": sig["description"],
                })
                break  # one threat per log line

    return detected
