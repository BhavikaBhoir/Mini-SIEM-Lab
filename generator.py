"""
generator.py — Simulated log generator for Mini SIEM Lab
Run as standalone: python generator.py
Or import generate_batch() from app/settings.
"""

import os
import random
import time
from datetime import datetime

LOG_PATH = os.path.join(os.path.dirname(__file__), "logs", "auth.log")

IPS = [
    "192.168.1.10",  "45.67.22.11",   "172.16.0.15",
    "103.45.67.89",  "91.23.44.55",   "11.45.222.90",
    "198.51.100.42", "203.0.113.77",  "10.0.0.254",
    "185.220.101.5", "66.240.236.119","37.120.131.201",
]

LOG_TEMPLATES = [
    "Failed login attempt from {ip}",
    "SQL Injection payload detected in request from {ip}",
    "Port scanning activity detected from {ip}",
    "Malware signature matched — source {ip}",
    "Unauthorized admin access attempt from {ip}",
    "XSS payload found in form submission from {ip}",
    "DDoS traffic spike detected originating {ip}",
    "User login successful from {ip}",
    "C2 beacon communication detected to {ip}",
    "Phishing URL accessed from {ip}",
    "Lateral movement detected — host {ip}",
    "authentication failure for user root from {ip}",
    "UNION SELECT injection attempt from {ip}",
    "Pass-the-hash attack detected from {ip}",
    "SYN flood attack detected from {ip}",
    "Ransomware file rename pattern detected on host {ip}",
]


def generate_line() -> str:
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip  = random.choice(IPS)
    msg = random.choice(LOG_TEMPLATES).format(ip=ip)
    return f"[{ts}] {msg}"


def generate_batch(n: int = 10) -> int:
    """Write n log lines to auth.log. Returns n."""
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        for _ in range(n):
            fh.write(generate_line() + "\n")
    return n


# ---- Standalone continuous mode ----
if __name__ == "__main__":
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    print("[generator] Starting continuous log generation (Ctrl+C to stop)...")
    try:
        while True:
            line = generate_line()
            with open(LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            print(f"[+] {line}")
            time.sleep(3)
    except KeyboardInterrupt:
        print("\n[generator] Stopped.")
