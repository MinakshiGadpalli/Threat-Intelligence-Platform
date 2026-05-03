from db import collection

def export_dashboard_data():
    threats = collection.find({}, {"_id": 0})

    for threat in threats:
        print(threat)

export_dashboard_data()