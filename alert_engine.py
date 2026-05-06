from db import collection

def detect_suspicious_threats():
    threats = collection.find({"risk_level": {"$in": ["HIGH", "MEDIUM"]}}, {"_id": 0})
    
    alerts = []
    for threat in threats:
        alert = {
            "ip": threat["ip"],
            "risk_level": threat["risk_level"],
            "message": f"Suspicious activity detected from {threat['ip']} ({threat['risk_level']})"
        }
        alerts.append(alert)
        print(alert)

    return alerts

if _name_ == "_main_":
    detect_suspicious_threats()
