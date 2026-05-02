# Threat Intelligence Platform (Week 1)

## Overview
This project is the Week 1 implementation of an Advanced Threat Intelligence Platform (TIP).

It collects threat intelligence from VirusTotal, extracts malicious IP reputation data, removes duplicate entries, and stores clean threat records for later analysis.

## Features
- VirusTotal API integration
- Fetch malicious IP intelligence
- Duplicate IP filtering
- Structured threat storage
- Modular Python codebase

## Tech Stack
- Python
- MongoDB
- VirusTotal API
- Git & GitHub

## Project Structure
```text
Threat_detection/
│
├── config.py
├── db.py
├── fetch_threats.py
├── utils.py
├── .env.example
├── .gitignore
└── README.md
