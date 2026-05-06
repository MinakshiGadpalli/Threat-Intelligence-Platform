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
