from db import db
from alert_engine import detect_suspicious_threats
from datetime import datetime

alerts_collection = db["alerts"]

def store_alerts():
    alerts = detect_suspicious_threats()

    for alert in alerts:
        alert["timestamp"] = datetime.utcnow()
        alerts_collection.insert_one(alert)
        print(f"Stored alert for {alert['ip']}")

if _name_ == "_main_":
    store_alerts()
