"""
db_handler.py - MongoDB interface for TIP Platform
Week 1: Handles all database operations with deduplication and audit logging
"""

import logging
from datetime import datetime, timezone
from typing import Optional
import yaml
from pymongo import MongoClient, UpdateOne, errors
from pymongo.collection import Collection

logger = logging.getLogger(__name__)


def load_config(path: str = "config/config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


class TIPDatabase:
    """
    Central database handler for the Threat Intelligence Platform.
    Manages raw indicators, normalized data, blocked IPs, and audit logs.
    """

    def __init__(self, config_path: str = "config/config.yaml"):
        cfg = load_config(config_path)
        mongo_cfg = cfg["mongodb"]
        self.client = MongoClient(mongo_cfg["host"], mongo_cfg["port"])
        self.db = self.client[mongo_cfg["database"]]

        # Collection handles
        self.raw: Collection = self.db[mongo_cfg["collections"]["raw_indicators"]]
        self.normalized: Collection = self.db[mongo_cfg["collections"]["normalized"]]
        self.blocked: Collection = self.db[mongo_cfg["collections"]["blocked_ips"]]
        self.audit: Collection = self.db[mongo_cfg["collections"]["audit_log"]]

        logger.info("✅ Connected to MongoDB: %s", mongo_cfg["database"])

    # ── Raw Indicator Ingestion ────────────────────────────────────────────────

    def upsert_raw_indicators(self, indicators: list[dict]) -> dict:
        """
        Bulk upsert raw indicators with deduplication on the indicator value.
        Returns counts of inserted vs updated documents.
        """
        if not indicators:
            return {"inserted": 0, "updated": 0}

        operations = []
        for item in indicators:
            operations.append(
                UpdateOne(
                    {"indicator": item["indicator"]},
                    {
                        "$set": {
                            "indicator": item["indicator"],
                            "type": item.get("type", "unknown"),
                            "source": item.get("source", "unknown"),
                            "tags": item.get("tags", []),
                            "raw_data": item.get("raw_data", {}),
                            "last_seen": datetime.now(timezone.utc),
                        },
                        "$setOnInsert": {
                            "created_at": datetime.now(timezone.utc),
                        },
                        "$inc": {"seen_count": 1},
                    },
                    upsert=True,
                )
            )

        try:
            result = self.raw.bulk_write(operations, ordered=False)
            inserted = result.upserted_count
            updated = result.modified_count
            logger.info(
                "Raw indicators — inserted: %d, updated: %d", inserted, updated
            )
            return {"inserted": inserted, "updated": updated}
        except errors.BulkWriteError as e:
            logger.error("Bulk write error: %s", e.details)
            return {"inserted": 0, "updated": 0, "error": str(e)}

    def get_raw_indicators(
        self,
        indicator_type: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 1000,
    ) -> list[dict]:
        """Fetch raw indicators with optional filtering."""
        query = {}
        if indicator_type:
            query["type"] = indicator_type
        if source:
            query["source"] = source
        return list(self.raw.find(query, {"_id": 0}).limit(limit))

    # ── Normalized Indicators ─────────────────────────────────────────────────

    def upsert_normalized(self, indicators: list[dict]) -> dict:
        """
        Upsert normalized, risk-scored indicators. Used by Week 2 normalizer.
        """
        if not indicators:
            return {"inserted": 0, "updated": 0}

        operations = []
        for item in indicators:
            operations.append(
                UpdateOne(
                    {"indicator": item["indicator"]},
                    {
                        "$set": {
                            **{k: v for k, v in item.items() if k != "status"},
                            "last_updated": datetime.now(timezone.utc),
                        },
                        "$setOnInsert": {
                            "created_at": datetime.now(timezone.utc),
                            "status": item.get("status", "active"),
                        },
                    },
                    upsert=True,
                )
            )

        result = self.normalized.bulk_write(operations, ordered=False)
        return {
            "inserted": result.upserted_count,
            "updated": result.modified_count,
        }

    def get_high_risk_indicators(self, min_score: float = 7.0) -> list[dict]:
        """
        Retrieve active indicators above the risk threshold. Used by the
        policy enforcer daemon in Week 3.
        """
        return list(
            self.normalized.find(
                {
                    "risk_score": {"$gte": min_score},
                    "type": "ip",
                    "status": "active",
                    "enforced": {"$ne": True},
                },
                {"_id": 0},
            ).sort("risk_score", -1)
        )

    # ── Blocked IPs ───────────────────────────────────────────────────────────

    def record_blocked_ip(self, ip: str, risk_score: float, rule_id: str) -> bool:
        """Record a newly blocked IP for audit and rollback purposes."""
        try:
            self.blocked.update_one(
                {"ip": ip},
                {
                    "$set": {
                        "ip": ip,
                        "risk_score": risk_score,
                        "rule_id": rule_id,
                        "status": "active",
                        "blocked_at": datetime.now(timezone.utc),
                    }
                },
                upsert=True,
            )
            # Mark as enforced in normalized collection
            self.normalized.update_one(
                {"indicator": ip}, {"$set": {"enforced": True}}
            )
            return True
        except Exception as e:
            logger.error("Failed to record blocked IP %s: %s", ip, e)
            return False

    def get_active_blocks(self) -> list[dict]:
        """Get all currently active firewall blocks."""
        return list(self.blocked.find({"status": "active"}, {"_id": 0}))

    def unblock_ip(self, ip: str, actor: str = "system") -> bool:
        """Mark an IP as unblocked (used by rollback manager)."""
        result = self.blocked.update_one(
            {"ip": ip},
            {
                "$set": {
                    "status": "unblocked",
                    "unblocked_at": datetime.now(timezone.utc),
                    "unblocked_by": actor,
                }
            },
        )
        if result.modified_count:
            self.normalized.update_one(
                {"indicator": ip}, {"$set": {"enforced": False, "status": "whitelisted"}}
            )
            return True
        return False

    # ── Audit Log ─────────────────────────────────────────────────────────────

    def log_audit(
        self,
        action: str,
        target: str,
        actor: str = "system",
        details: Optional[dict] = None,
        success: bool = True,
    ):
        """
        Write an immutable audit log entry. Required for PCI-DSS compliance.
        Every firewall change, block, and unblock must be recorded here.
        """
        entry = {
            "timestamp": datetime.now(timezone.utc),
            "action": action,
            "target": target,
            "actor": actor,
            "success": success,
            "details": details or {},
        }
        self.audit.insert_one(entry)
        logger.debug("Audit: %s → %s by %s", action, target, actor)

    def get_audit_log(self, limit: int = 500) -> list[dict]:
        """Retrieve recent audit entries for compliance reporting."""
        return list(
            self.audit.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit)
        )

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        return {
            "raw_indicators": self.raw.count_documents({}),
            "normalized_indicators": self.normalized.count_documents({}),
            "active_blocks": self.blocked.count_documents({"status": "active"}),
            "audit_entries": self.audit.count_documents({}),
            "high_risk_pending": self.normalized.count_documents(
                {"risk_score": {"$gte": 7}, "enforced": {"$ne": True}, "status": "active"}
            ),
        }

    def close(self):
        self.client.close()
