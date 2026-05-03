from db import collection

def calculate_risk(score):
    if score >= 5:
        return "HIGH"
    elif score >= 2:
        return "MEDIUM"
    else:
        return "LOW"

def update_risk_levels():
    threats = collection.find()

    for threat in threats:
        risk_level = calculate_risk(threat["malicious_score"])

        collection.update_one(
            {"_id": threat["_id"]},
            {"$set": {"risk_level": risk_level}}
        )

        print(f"Updated {threat['ip']} -> {risk_level}")

update_risk_levels()