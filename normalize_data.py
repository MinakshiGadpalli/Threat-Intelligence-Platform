from db import collection

def normalize_threats():
    threats = collection.find()

    for threat in threats:
        normalized = {
            "ip": threat.get("ip"),
            "malicious_score": threat.get("malicious_score", 0),
            "risk_level": threat.get("risk_level", "LOW"),
            "timestamp": threat.get("timestamp")
        }

        collection.update_one(
            {"_id": threat["_id"]},
            {"$set": normalized}
        )

        print(f"Normalized: {threat['ip']}")

normalize_threats()