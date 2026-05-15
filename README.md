# 🛡️ Mini SIEM Lab — SOC Monitoring Platform

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat-square&logo=flask)
![SQLite](https://img.shields.io/badge/SQLite-Database-blue?style=flat-square&logo=sqlite)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

A professional **Security Information and Event Management (SIEM)** system built with Python and Flask that simulates real **SOC (Security Operations Center)** workflows. Designed for cybersecurity students, analysts, and anyone learning about threat detection and incident response.

---

## ✨ Features

### 🔍 Threat Detection
- Real-time log monitoring and parsing
- 10 built-in attack signature rules using regex pattern matching
- Automatic severity classification — Critical / High / Medium / Low
- Deduplication to prevent false repeated alerts

### 📊 Dashboard
- Live statistics with auto-refresh every 15 seconds (no page reload)
- Bar chart — threat type distribution
- Doughnut chart — severity breakdown
- Recent threat activity table

### 📋 Threat Logs
- Full paginated log viewer (20 records per page)
- Search by threat type or source IP address
- Filter by severity level
- Delete individual records or clear all with one click

### 🚨 Alerts
- Active alert feed showing only Critical and High severity open alerts
- One-click **Acknowledge** and **Resolve** with AJAX (no page reload)
- SOC SLA reference guide built in

### 📈 Reports
- Complete threat report with status breakdown charts
- One-click **PDF export** with professional formatting via ReportLab
- Timestamped filenames for every download

### ⚙️ Settings
- System status indicators
- View all 10 active detection signatures with regex patterns
- Generate sample log lines instantly for testing
- Audit log showing last 30 analyst actions
- Danger zone — clear entire threat database

### 🔐 Security
- Login authentication with two roles (Admin / Analyst)
- Session protection with 8-hour timeout
- Audit trail for all user actions
- Login attempt logging

---

## 🎯 Detected Threat Types

| # | Threat Type | Severity | Detection Pattern |
|---|-------------|----------|-------------------|
| 1 | Brute Force Attempt | High | Failed login, auth failure |
| 2 | SQL Injection | Critical | UNION SELECT, DROP TABLE |
| 3 | Port Scan | Medium | nmap, masscan, SYN flood |
| 4 | Malware Detection | Critical | ransomware, rootkit, trojan |
| 5 | Unauthorized Access | High | Privilege escalation, sudo |
| 6 | XSS Attack | Medium | `<script>`, onerror= |
| 7 | DDoS Attack | Critical | Traffic spike, flood |
| 8 | C2 Communication | Critical | Beacon, exfiltration |
| 9 | Phishing Attempt | High | Credential harvest |
| 10 | Lateral Movement | Critical | Pass-the-hash, mimikatz |

---

## 🗂️ Project Structure

```
MiniSIEM/
├── app.py                  # Flask app — routes, API endpoints, auth
├── detector.py             # Threat detection engine (regex signatures)
├── generator.py            # Log simulator for testing
├── requirements.txt        # Python dependencies
├── logs/
│   └── auth.log            # Simulated security log file (auto-created)
├── instance/
│   └── siem.db             # SQLite database (auto-created)
├── static/
│   └── css/
│       └── style.css       # Dark SOC cybersecurity theme
└── templates/
    ├── base.html           # Shared layout with sidebar
    ├── login.html          # Login page
    ├── index.html          # Dashboard
    ├── logs.html           # Threat logs
    ├── alerts.html         # Active alerts
    ├── reports.html        # Reports + PDF export
    └── settings.html       # Settings + audit log
```

---

## ⚙️ Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/BhavikaBhoir/Mini-SIEM-Lab.git
cd Mini-SIEM-Lab
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the application
```bash
python app.py
```

### 4. Open in browser
```
http://127.0.0.1:5000
```

### 5. Generate sample data
After logging in, go to **Settings → Generate 20 Sample Log Lines**

Or run the log generator in a second terminal:
```bash
python generator.py
```

---

## 🔑 Demo Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Admin |
| analyst | analyst456 | Analyst |

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Python 3.10+, Flask 3.x |
| Database | SQLite + SQLAlchemy |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Charts | Chart.js 4.x |
| PDF Generation | ReportLab |
| Authentication | Flask Sessions |
| Log Simulation | Custom Python Generator |

---

## 🚀 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Returns live threat counts |
| `/api/recent_threats` | GET | Returns last 10 threats as JSON |
| `/api/threat_distribution` | GET | Returns threat type counts |
| `/alerts/acknowledge/<id>` | POST | Acknowledge an alert |
| `/alerts/resolve/<id>` | POST | Resolve an alert |
| `/threats/delete/<id>` | POST | Delete a threat record |
| `/threats/clear_all` | POST | Clear all threat records |
| `/download_report` | GET | Download PDF report |

---

## 📚 Concepts Demonstrated

- SIEM architecture and log ingestion pipeline
- Regex-based threat signature detection
- Incident lifecycle management (Open → Acknowledged → Resolved)
- Role-based access control (RBAC)
- REST API design with Flask
- Real-time dashboard with JavaScript polling
- Audit logging for analyst accountability
- PDF report generation for incident documentation

---

## 👩‍💻 Author

**Bhavika Bhoir And Samyak Jadhav**

---

## 📄 License

This project is licensed under the MIT License — free to use for academic and portfolio purposes.
