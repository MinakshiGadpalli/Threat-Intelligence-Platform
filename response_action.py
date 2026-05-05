from db import db

alerts_collection = db["alerts"]

def simulate_response():
    alerts = alerts_collection.find({}, {"_id": 0})

    for alert in alerts:
        print(f"[ACTION] Blocking suspicious IP: {alert['ip']} ({alert['risk_level']})")

if __name__ == "__main__":
    simulate_response()