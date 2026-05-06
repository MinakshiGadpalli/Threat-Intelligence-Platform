from flask import Flask, render_template
from db import collection, db

app = Flask(_name_)

alerts_collection = db["alerts"]

@app.route("/")
def dashboard():
    threats = list(collection.find({}, {"_id": 0}))
    alerts = list(alerts_collection.find({}, {"_id": 0}))
    return render_template("dashboard.html", threats=threats, alerts=alerts)

if _name_ == "_main_":
    app.run(debug=True)
