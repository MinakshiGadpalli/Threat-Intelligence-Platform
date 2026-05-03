import requests
from datetime import datetime
from config import VT_API_KEY
from db import collection
from utils import is_duplicate

def fetch_ip_data(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "ip": ip,
            "malicious_score": stats["malicious"]
        }
    else:
        print("Error:", response.status_code)
        return None

ips_to_check = ["8.8.8.8", "1.1.1.1", "142.250.182.14"]

for ip in ips_to_check:
    result = fetch_ip_data(ip)

    if result:
        if not is_duplicate(collection, result["ip"]):
            result["timestamp"] = datetime.utcnow()
            collection.insert_one(result)
            print("Inserted:", result)
        else:
            print("Duplicate skipped:", ip)