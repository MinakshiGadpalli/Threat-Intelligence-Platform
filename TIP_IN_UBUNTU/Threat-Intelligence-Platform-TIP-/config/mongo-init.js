// MongoDB initialization script for TIP Platform
db = db.getSiblingDB('threat_intel');

db.createCollection('raw_indicators');
db.createCollection('normalized_indicators');
db.createCollection('blocked_ips');
db.createCollection('audit_log');

db.raw_indicators.createIndex({ "indicator": 1 }, { unique: true });
db.normalized_indicators.createIndex({ "indicator": 1 }, { unique: true });
db.normalized_indicators.createIndex({ "risk_score": -1 });
db.normalized_indicators.createIndex({ "severity": 1 });
db.normalized_indicators.createIndex({ "status": 1 });
db.blocked_ips.createIndex({ "ip": 1 }, { unique: true });
db.blocked_ips.createIndex({ "status": 1 });
db.audit_log.createIndex({ "timestamp": -1 });

print("✅ MongoDB threat_intel database initialized");
