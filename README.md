# 🛡️ Firewall & Router Log Analyzer

**Policy Violation Detection System**

A comprehensive Blue Team security monitoring prototype that analyzes firewall and router logs to automatically detect policy violations, compliance issues, and acceptable use standard breaches.

---

## 📋 Project Information

| Field | Value |
|-------|-------|
| **Author** | Sam John |
| **Course** | CY376 - Network Monitoring, Security & Auditing |
| **Team** | 🔵 Blue Team |
| **Project Type** | End-of-Semester Project |
| **Language** | Python 3.14 |
| **Framework** | Flask |

---

## 🎯 Project Overview

This project addresses a critical challenge in modern network security: manually monitoring thousands of firewall and router log entries for policy violations is impractical. This system automates that process by:

- **Parsing** firewall and router log files
- **Analyzing** traffic against defined security policies
- **Detecting** 10+ types of policy violations
- **Prioritizing** alerts by severity (CRITICAL / HIGH / MEDIUM / LOW)
- **Presenting** findings through an interactive web dashboard
- **Storing** all alerts in a searchable SQLite database

---

## 🔍 Detected Violations

The system automatically identifies the following policy violations:

| # | Violation Type | Severity | Description |
|---|----------------|----------|-------------|
| 1 | Blacklisted IP Traffic | 🔴 CRITICAL | Connections to/from known malicious IPs |
| 2 | Brute Force Attempts | 🔴 CRITICAL | Multiple failed login attempts |
| 3 | Router Brute Force | 🔴 CRITICAL | Failed router authentication attempts |
| 4 | Blocked Port Access | 🟡 HIGH | Traffic on prohibited ports (Telnet, RDP, etc.) |
| 5 | Large Data Transfers | 🟡 HIGH | Potential data exfiltration attempts |
| 6 | Suspicious Ports | 🟡 HIGH | Traffic on known malware/backdoor ports |
| 7 | Excessive Denials | 🟡 HIGH | Possible port scanning or DDoS |
| 8 | Unauthorized Config Changes | 🟡 HIGH | Router configuration modifications |
| 9 | After-Hours Access | 🔵 MEDIUM | Network access outside business hours |
| 10 | Protocol Violations | 🔵 MEDIUM | Use of forbidden protocols (FTP, Telnet) |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    LOG SOURCES                              │
│  ┌──────────────┐          ┌──────────────┐                 │
│  │ Firewall Log │          │ Router Log   │                 │
│  └──────┬───────┘          └──────┬───────┘                 │
└─────────┼─────────────────────────┼─────────────────────────┘
          │                         │
          ▼                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    LOG PARSER                               │
│           (Reads & normalizes log entries)                  │
└─────────────────────────┬───────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  POLICY ANALYZER                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  8 Security Checks (Blocked Ports, IPs, etc.)       │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────┬───────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   ALERT ENGINE                              │
│         (Generates & prioritizes alerts)                    │
└─────────────────────────┬───────────────────────────────────┘
                          ▼
          ┌───────────────┴────────────────┐
          ▼                                ▼
┌──────────────────┐              ┌──────────────────┐
│  SQLite Database │              │  Flask Dashboard │
│   (Storage)      │              │  (Visualization) │
└──────────────────┘              └──────────────────┘
```

---

## 🛠️ Technologies Used

- **Python 3.14** — Core programming language
- **Flask 3.1** — Web framework for dashboard
- **Pandas 3.0** — Data analysis and log processing
- **SQLAlchemy 2.0** — Database ORM
- **SQLite** — Lightweight database
- **Chart.js** — Interactive charts and graphs
- **Bootstrap 5.3** — Responsive UI framework
- **Colorama** — Colored terminal output

---

## 📁 Project Structure

```
firewall_analyzer/
│
├── README.md                    # Project documentation
├── requirements.txt             # Python dependencies
├── .gitignore                   # Git ignore rules
│
├── src/                         # Main source code
│   ├── app.py                   # Flask web application
│   ├── analyzer.py              # Policy analyzer engine
│   ├── log_parser.py            # Log parsing module
│   ├── alert_engine.py          # Alert generation
│   └── database.py              # Database layer
│
├── scripts/                     # Utility scripts
│   ├── generate_logs.py         # Sample log generator
│   └── test_prototype.py        # Terminal test runner
│
├── configs/                     # Configuration files
│   └── security_policies.json   # Security policies definition
│
├── templates/                   # HTML templates
│   ├── index.html               # Main dashboard
│   ├── alerts.html              # Alerts management page
│   └── reports.html             # Analytics reports
│
├── logs/                        # Sample log files
│   ├── sample_firewall.log
│   └── sample_router.log
│
├── evidence/                    # Screenshots & evidence
│   └── screenshots/
│
└── docs/                        # Documentation
    └── report.pdf               # Full project report
```

---

## 🚀 Installation & Usage

### Prerequisites

- Python 3.11 or newer
- pip (Python package manager)
- Git

### Setup Steps

**1. Clone the repository:**
```bash
git clone https://github.com/dinger/firewall-analyzer.git
cd firewall-analyzer
```

**2. Create virtual environment:**
```bash
python -m venv venv
```

**3. Activate virtual environment:**
```bash
# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

**4. Install dependencies:**
```bash
pip install -r requirements.txt
```

**5. Generate sample logs:**
```bash
python scripts/generate_logs.py
```

**6. Run terminal test (optional):**
```bash
python scripts/test_prototype.py
```

**7. Launch web dashboard:**
```bash
python src/app.py
```

**8. Open browser:**
```
http://localhost:5000
```

---

## 🖥️ Dashboard Features

### Main Dashboard
- Real-time statistics (Total, Critical, High, Medium, Low alerts)
- Interactive doughnut chart (violations by type)
- Bar chart (severity breakdown)
- Recent alerts table
- One-click analysis trigger

### Alerts Page
- Complete alerts listing
- Filter by severity (CRITICAL / HIGH / MEDIUM / LOW)
- Filter by status (OPEN / RESOLVED)
- Alert resolution management
- Color-coded severity badges

### Reports Page
- Violations breakdown by type (with progress bars)
- Severity distribution
- Top 10 offending IP addresses
- Risk visualization

---

## 📊 Sample Results

During testing, the system successfully detected:

- **1,060 total policy violations** from 1,004 log entries
- **665 CRITICAL** severity alerts
- **213 HIGH** severity alerts
- **182 MEDIUM** severity alerts

---

## 🔐 Security Policies Configuration

Policies are defined in `configs/security_policies.json`:

```json
{
  "blocked_ports": [23, 69, 135, 137, 138, 139, 445, 3389],
  "blocked_ips": ["185.220.101.45", "194.165.16.72"],
  "suspicious_ports": [4444, 1337, 31337, 8080, 9090],
  "max_connections_per_minute": 50,
  "max_data_transfer_mb": 500,
  "max_failed_logins": 5,
  "allowed_hours": {"start": 8, "end": 18}
}
```

---

## 📚 Standards & Frameworks Referenced

- **MITRE ATT&CK** — Adversary tactics and techniques
- **CIS Benchmarks** — Configuration security standards
- **NIST SP 800-92** — Guide to Computer Security Log Management
- **OWASP Top 10** — Application security risks

---

## 🎓 Academic Context

This project was developed as the end-of-semester submission for **CY376: Network Monitoring, Security and Auditing**, focusing on the Blue Team (defensive security) approach to identifying policy violations in network traffic logs.

---

## 📄 License

This project is developed for academic purposes as part of coursework.

---

## 👤 Author

**Sam John**
- GitHub: [@dinger](https://github.com/dinger)
- Course: CY376
- Team: 🔵 Blue Team

---

## ⚠️ Disclaimer

All log data used in this project is **simulated for educational purposes**. No real network data, credentials, or third-party systems were used or tested.

---

*Last Updated: August 2025*