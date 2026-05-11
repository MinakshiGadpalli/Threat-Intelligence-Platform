# 🚀 Threat Detection Platform

A Cybersecurity Threat Detection Platform that collects, processes, and analyzes threat intelligence data using external APIs and stores it in a structured format for further analysis and visualization.This project is a beginner-friendly Threat Intelligence Platform (TIP) built using Python, MongoDB, and VirusTotal.It collects threat intelligence from VirusTotal, extracts malicious IP reputation data, removes duplicate entries, stores clean threat records, and performs risk scoring for security analysis.

The project is being developed in phases as part of an internship.

---

## 📌 Project Overview

This project builds a complete threat intelligence pipeline:

- Fetches malicious IP data from VirusTotal API
- Stores threat data in MongoDB
- Assigns risk levels based on threat severity
- Normalizes and structures data
- Generates dashboard-ready output

---

## 🛠️ Tech Stack

- **Language:** Python  
- **Database:** MongoDB  
- **API:** VirusTotal  
- **Tools:** Git, VS Code  
- **Libraries:** requests, pymongo, python-dotenv  

---

## ⚙️ Features

### Week 1: Data Collection
- Fetch threat intelligence from VirusTotal
- Extract malicious IP reputation data
- Store structured threat records in MongoDB
- Secure API key using environment variables

### Week 2: Processing & Analysis
- Risk scoring engine (LOW / MEDIUM / HIGH)
- Threat normalization
- Dashboard-ready data output
- Structured threat intelligence generation

### Week 3: Alerting & Response Automation
- Alert generation for suspicious IPs
- Automated response simulation
- Alert logging system
- Threat response automation
- MongoDB alert storage
- SOC-style alert monitoring

---

## 📂 Project Structure

```
Threat_detection/
│── venv/
│── config.py
│── db.py
│── fetch_threats.py
│── risk_analysis.py
│── normalize_data.py
│── dashboard_data.py
│── app.py
│── alert_engine.py
│── log_alerts.py
│── requirements.txt
│── .env
```

---

## 🚀 Installation & Setup

### 1. Clone Repository
```bash
git clone https://github.com/your-username/threat-detection-platform.git
cd threat-detection-platform
```

### 2. Create virtual environment 
```bash
python -m venv venv
venv\Scripts\activate
```
### 3.Install Dependencies
```bash
pip install -r requirements.txt
```

## 🔑 Environment Setup

```
VT_API_KEY=your_api_key_here
```
### 🗄️MongoDB Setup
- Install MongoDB Community Server
- Start MongoDB service:
```bash
net start MongoDB
```
```bash
- Default connection URL:mongodb://localhost:27017
```

## ▶️ how to run
**Step 1: Fetch Threat Data**
```bash
python fetch_threats.py
```
**Step 2: Run Risk Analysis**
```bash
python fetch_threats.py
```
**Step 3: Normalize Data**
```bash
python normalize_data.py
```
**Step 4: Export Dashboard Data**
```bash
python dashboard_data.py
```
**📊 Sample Output**
{
  "ip": "8.8.8.8",
  "malicious_score": 0,
  "risk_level": "LOW",
  "timestamp": "2026-xx-xx"
}

**🧠 Risk Scoring Logic**

| Malicious Score | Risk Level |
| --------------- | ---------- |
| ≥ 5             | HIGH       |
| ≥ 2             | MEDIUM     |
| < 2             | LOW        |

**✅ Completion Checklist**

- ✅Python environment setup
- ✅MongoDB installed and running
- ✅API integration working
- ✅Threat data stored successfully
- ✅Risk scoring implemented
- ✅Data normalized
- ✅Dashboard-ready output generated


**🎯 Future Improvements**

- Add frontend dashboard 
- Integrate more threat intelligence sources
- Real-time threat monitoring
- Alert/notification system



**PROJECT IN UBUNTU**
# 🛡️ Threat Intelligence Platform (TIP)

An end-to-end, automated Threat Intelligence Platform designed to fetch, process, and actively enforce security policies against malicious IPs. This project integrates OSINT feeds, a robust ELK Stack (Elasticsearch, Kibana) for SIEM visualization, MongoDB for raw data storage, and Linux `iptables` for active firewall enforcement.

## 🚀 Features

* **Automated OSINT Ingestion (Week 1):** Fetches real-time threat data from external feeds (e.g., AlienVault, AbuseIPDB).
* **Data Normalization & SIEM Push (Week 2):** Parses raw JSON data and pushes it to Elasticsearch and MongoDB.
* **Active Policy Enforcement (Week 3):** A background daemon that continuously scans for new threats and actively injects `DROP` rules into the Ubuntu firewall (`iptables`).
* **Audit & Rollback Management (Week 4):** Live Kibana dashboards for visualization, alert management, and a CLI tool to manually unblock IPs with audit logging.

---

## ⚡ Quick Start

### Prerequisites To run this project, you will need:
- Ubuntu 
- Docker + Docker Compose
- Python 3.8 or higher version
- 4GB RAM minimum (for Elasticsearch)

Root Privileges: Required to modify iptables firewall rules.

## 🏗️ System Architecture

<img width="1402" height="953" alt="system architecture" src="https://github.com/user-attachments/assets/55bc4d62-bc41-4a9c-9dcc-7cfd14c5aaa7" />




**🛠️ Installation & Setup**

1. Clone the Repository
Bash
git clone [https://github.com/yourusername/Threat-Intelligence-Platform-TIP-.git](https://github.com/yourusername/Threat-Intelligence-Platform-TIP-.git)
cd Threat-Intelligence-Platform-TIP-
2. Setup Docker Infrastructure
The platform relies on MongoDB and the Elastic Stack. Run these commands to spin up the required containers:

Add your free API keys to `config/config.yaml`:

```bash
nano config/config.yaml
```

Fill in the following API keys (see `docs/API_SETUP.md` for full registration instructions):

| API | Key field in config.yaml | Where to get it | Required |
|-----|--------------------------|-----------------|----------|
| AlienVault OTX | `apis.alienvault_otx.api_key` | https://otx.alienvault.com | ✅ Yes |
| AbuseIPDB | `apis.abuseipdb.api_key` | https://www.abuseipdb.com/api | ✅ Yes |
| VirusTotal | `apis.virustotal.api_key` | https://www.virustotal.com | ⚪ Optional |
| URLhaus | No key needed | https://urlhaus.abuse.ch | ⚪ Free/No key |


Bash
# 1. Start Elasticsearch
sudo docker run -d --name tip_elasticsearch -p 9200:9200 -p 9300:9300 -e "discovery.type=single-node" -e "xpack.security.enabled=false" docker.elastic.co/elasticsearch/elasticsearch:8.11.1

# 2. Start Kibana (Linked to Elasticsearch)
sudo docker run -d --name tip_kibana -p 5601:5601 --link tip_elasticsearch:elasticsearch docker.elastic.co/kibana/kibana:8.11.1

# 3. Start MongoDB
sudo docker run -d --name tip_mongodb -p 27017:27017 mongo:6.0

3. Setup Python Virtual Environment
Bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

4. Configure File Permissions
Ensure the system can write logs properly:

Bash
mkdir -p logs
sudo chmod -R 777 logs/
chmod +x run_auto_tip.sh

💻 Usage
Starting the Platform
You can run the entire platform (from Data Collection to Firewall Enforcement) using the provided master script:

Bash
./run_auto_tip.sh
Note: This script will launch the background daemons in separate terminal windows for live monitoring.

Accessing the Dashboard
Once the script is running, open your web browser and navigate to:

Kibana Dashboard: http://localhost:5601

Rollback / Unblocking an IP
If you need to manually unblock a falsely flagged IP, use the Rollback Manager:

Bash
source venv/bin/activate
python3 week4_dashboard/rollback_manager.py unblock <IP_ADDRESS> --actor "Admin" --reason "False Positive Investigation"
Example: python3 week4_dashboard/rollback_manager.py unblock 100.29.192.86 --actor "Mitesh" --reason "Safe IP"


---

### Run the pipeline

**Important: Always run all commands from the project root directory.**

```bash
# Week 1 — Collect threat indicators from OSINT feeds (~2-3 minutes)
python3 feed_collector.py

# Week 2 — Normalize and risk-score all indicators
python3 normalizer.py

# Week 2 — Push data to Elasticsearch for Kibana
python3 elk_pusher.py

# Week 3 — Start the policy enforcement daemon (Ctrl+C to stop)
python3 policy_daemon.py

# Week 4 — List all blocked IPs
python3 rollback_manager.py list

# Week 4 — Unblock a specific IP (example)
python3 rollback_manager.py unblock 105.247.69.196 --actor "SOC_Analyst"

# Week 4 — View full audit history
python3 rollback_manager.py history
```

---

### Open Kibana

Navigate to: **http://localhost:5601**

1. Click ☰ → **Discover** → **Create data view**
2. Name: `TIP Threats` | Index pattern: `tip-threats` | Timestamp: `@timestamp`
3. Click **Save data view to Kibana**
4. Search `severity: HIGH` to see high-risk indicators
5. If no results appear, change the time range to **Last 7 days**

---

## 🧪 Run Tests

```bash
pytest tests/test_all.py -v
```

Expected output: **27 passed, 9 subtests passed**

---

## 🔧 Quick Reference

| Command | Description |
|---------|-------------|
| `docker-compose up -d` | Start MongoDB + Elasticsearch + Kibana |
| `docker-compose down` | Stop containers (data is preserved) |
| `docker-compose down -v` | Stop containers and delete all data |
| `python3 feed_collector.py` | Collect threat indicators |
| `python3 normalizer.py` | Normalize and risk-score indicators |
| `python3 elk_pusher.py` | Sync data to Elasticsearch/Kibana |
| `sudo python3 policy_daemon.py` | Start firewall enforcement daemon |
| `python3 rollback_manager.py list` | List all blocked IPs |
| `python3 rollback_manager.py unblock 105.247.69.196 --actor "SOC_Analyst"` | Unblock a specific IP |
| `python3 rollback_manager.py history` | View full audit history |
| `python3 rollback_manager.py reblock <IP> --actor "Name"` | Re-block an IP |
| `python3 rollback_manager.py flush --actor "Name" --confirm` | Emergency unblock all IPs |
| `pytest tests/test_all.py -v` | Run all unit tests |

---

## 🏗️ Architecture

```
[AlienVault OTX]  ──┐
[AbuseIPDB]       ──┼──► [feed_collector.py] ──► [MongoDB]
[URLhaus]         ──┤                                │
[VirusTotal]      ──┘                         [normalizer.py]
                                                      │
                                          [elk_pusher.py] ──► [Elasticsearch] ──► [Kibana :5601]
                                                      │
                                      [policy_daemon.py] ──► [iptables firewall rules]
                                                      │
                          [rollback_manager.py] + [alert_manager.py]
```

---

## 📊 Expected Results

| Metric | Value |
|--------|-------|
| Indicators collected | ~7,500–8,500 |
| HIGH severity IPs | ~500 |
| Unit tests passing | 27/27 |
| Kibana dashboard | http://localhost:5601 |

---

📁 Folder Structure
Plaintext
threat-intelligence-platform/
├── config/
│   ├── config.yaml          # Central configuration — add your API keys here
│   └── mongo-init.js        # MongoDB collection and index initialization
├── feed_collector.py        # OSINT collectors: AlienVault OTX, AbuseIPDB, URLhaus
├── db_handler.py            # MongoDB interface with deduplication and audit logging
├── normalizer.py            # Risk scoring engine (0–10, CVSS v3 aligned)
├── elk_pusher.py            # MongoDB → Elasticsearch sync for Kibana
├── rule_engine.py           # iptables rule engine with whitelist and dry-run support
├── policy_daemon.py         # Continuous enforcement daemon with signal handling
├── rollback_manager.py      # CLI: list / unblock / reblock / flush / history
├── alert_manager.py         # Email + Slack alerting with daily summaries
├── kibana_dashboard.ndjson    # Import-ready Kibana 8.x dashboard
├── tests/
│   └── test_all.py            # 27 unit tests across all 4 weeks (all passing)
├── docs/
│   └── API_SETUP.md         # Free API registration guide
├── docker-compose.yml       # MongoDB + Elasticsearch + Kibana stack
├── logs/                    # Automated execution and error logs
├── run_auto_tip.sh          # Master Execution Script
├── requirements.txt         # Python dependencies
└── README.md
```


## 🔒 Security Notes

- The policy daemon runs in `dry_run: true` mode by default — logs what would be blocked without applying real iptables rules
- To enable live blocking, set `dry_run: false` in `config/config.yaml` and run with `sudo`
- All block and unblock actions are recorded in a PCI-DSS compliant audit log
- Private IP ranges (`10.x.x.x`, `192.168.x.x`, `172.16.x.x`, `127.x.x.x`) are always whitelisted

---

⚠️ Disclaimer
This project modifies host firewall rules (iptables). It is highly recommended to run this in an isolated Virtual Machine (VM) rather than a primary host operating system to avoid accidental network lockouts.



## 📄 License

MIT License — free for educational and commercial use.









