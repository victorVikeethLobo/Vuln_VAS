# 🛡️ VulnVAS – AI-Assisted Vulnerability Assessment System

VulnVAS is an AI-assisted Command Line Interface (CLI) vulnerability assessment tool that automates reconnaissance, vulnerability detection, exploit analysis, and risk prioritization. It integrates multiple open-source security tools and vulnerability intelligence sources to help security professionals quickly identify and prioritize security risks.

---

## 🚀 Features

- 🔍 Network reconnaissance using Nmap
- 🌐 Service and version detection
- 🛡️ CVE lookup using the National Vulnerability Database (NVD) API
- ⚡ Vulnerability scanning using Nuclei
- 💥 Exploit availability detection via Exploit-DB
- 🤖 Machine Learning-based risk prioritization
- 📊 Risk summary and severity visualization
- 🛠️ Automated remediation suggestions
- 📈 Vulnerability graphs
- ⚙️ Parallel vulnerability scanning for improved performance
- 📄 JSON report generation

---

# 🏗️ System Architecture

```
                 Target Host
                      │
                      ▼
              Nmap Reconnaissance
                      │
                      ▼
          Service & Version Detection
                      │
        ┌─────────────┴─────────────┐
        ▼                           ▼
   NVD CVE Lookup              Nuclei Scan
        │                           │
        └─────────────┬─────────────┘
                      ▼
            Vulnerability Correlation
                      │
                      ▼
           Exploit-DB Availability Check
                      │
                      ▼
      AI Risk Prioritization (Decision Tree)
                      │
                      ▼
     Remediation + Risk Summary + Graphs
                      │
                      ▼
              JSON Report Generation
```

---

# 🛠️ Tech Stack

| Category | Technologies |
|----------|--------------|
| Language | Python |
| Network Scanning | Nmap |
| Vulnerability Scanner | Nuclei |
| CVE Intelligence | NVD API |
| Exploit Detection | Exploit-DB |
| Machine Learning | Scikit-learn (Decision Tree Classifier) |
| Data Processing | Pandas |
| Visualization | Matplotlib |
| HTTP Requests | Requests |
| Parallel Processing | ThreadPoolExecutor |
| CLI | argparse |
| Progress Tracking | tqdm |

---

# 🤖 AI Component

VulnVAS uses a Decision Tree Classifier built with Scikit-learn to prioritize vulnerabilities automatically.

### Features used by the model

- CVSS Score
- Exploit Availability
- Port Exposure

### Prediction Output

- Immediate
- High
- Medium
- Low

This helps security teams focus on the most critical vulnerabilities first.

---

# 📂 Project Structure

```
vulnvas_package/
│
├── cli.py
├── main.py
│
├── modules/
│   ├── recon_module.py
│   ├── vulnerability_module.py
│   ├── cve_lookup.py
│   ├── exploit_lookup.py
│   ├── nuclei_module.py
│   ├── ml_module.py
│   ├── remediation_module.py
│   ├── report_summary.py
│   ├── graph_module.py
│   └── train_model.py
│
├── reports/
│
├── requirements.txt
└── setup.py
```

---

# ⚙️ Installation

Clone the repository

```bash
git clone https://github.com/victorVikeethLobo/Vuln_VAS.git

cd Vuln_VAS
```

Install using pipx (recommended)

```bash
pipx install .
```

Or install manually

```bash
python3 -m venv venv

source venv/bin/activate

pip install -r requirements.txt

pip install .
```

---

# 🚀 Usage

Basic scan

```bash
vulnvas -t 192.168.56.103
```

Quick scan

```bash
vulnvas -t 192.168.56.103 --quick
```

Scan a domain

```bash
vulnvas -t scanme.nmap.org
```

---

# 📊 Sample Output

```
Recon Complete

↓

Vulnerability Mapping

↓

Nuclei Scan

↓

Exploit Detection

↓

ML Risk Prioritization

↓

Risk Summary

↓

Graph Generation

↓

JSON Report
```

---

# 📄 Report

VulnVAS automatically generates:

- JSON report
- Risk summary
- Vulnerability severity graph
- Remediation recommendations

---

# 📌 Future Enhancements

- HTML Dashboard
- PDF Report Generation
- CVSS v4 Support
- Wazuh Integration
- OWASP Top 10 Mapping
- MITRE ATT&CK Mapping
- Docker Support
- Multi-target Scanning
- Web Dashboard (Streamlit)

---

# 👨‍💻 Author

**Victor Vikeeth Lobo**

B.Tech Computer Science Engineering (Cybersecurity)

Alliance University, Bengaluru

GitHub:
https://github.com/victorVikeethLobo

---

# ⭐ If you found this project useful, consider giving it a Star!
