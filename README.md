# Threat Intelligence Platform (Week 1 & Week 2)

## Overview
This project is a beginner-friendly Threat Intelligence Platform (TIP) built using Python, MongoDB, and VirusTotal.

It collects threat intelligence from VirusTotal, extracts malicious IP reputation data, removes duplicate entries, stores clean threat records, and performs risk scoring for security analysis.

The project is being developed in phases as part of an internship.

---

## Features

### Week 1
- VirusTotal API integration
- Fetch malicious IP intelligence
- Duplicate IP filtering
- MongoDB threat storage
- Modular Python code structure

### Week 2
- Risk scoring engine
- Threat normalization
- Severity classification (LOW / MEDIUM / HIGH)
- Dashboard-ready structured output

---

## Tech Stack
- Python
- MongoDB
- VirusTotal API
- Git & GitHub

---

## Project Structure

```text
Threat_detection/
│
├── config.py
├── db.py
├── fetch_threats.py
├── utils.py
├── risk_analysis.py
├── normalize_data.py
├── dashboard_data.py
├── .env.example
├── .gitignore
└── README.md


Setup for project

1. Clone the repository
git clone https://github.com/MinakshiGadpalli/Threat-Intelligence-Platform.git
cd Threat_detection

2. Install dependencies
pip install requests pymongo python-dotenv

3. Create .env
VT_API_KEY=your_api_key_here

4. Start MongoDB
Make sure MongoDB server is running on:
mongodb://localhost:27017

5. Run Week 1
python fetch_threats.py
6. Run

Week 2
python risk_analysis.py
python normalize_data.py
python dashboard_data.py
