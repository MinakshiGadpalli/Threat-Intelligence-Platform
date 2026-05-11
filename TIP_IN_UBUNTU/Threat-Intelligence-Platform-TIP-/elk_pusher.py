"""
elk_pusher.py - Elasticsearch SIEM Integration
Week 2: Syncs normalized threat indicators from MongoDB -> Elasticsearch
        for Kibana visualization and SIEM querying
"""

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml
from elasticsearch import Elasticsearch, helpers

sys.path.insert(0, str(Path(__file__).parent.parent))
from week1_osint.db_handler import TIPDatabase

logger = logging.getLogger("elk_pusher")


def load_config(path: str = "config/config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


# ── Index Templates ───────────────────────────────────────────────────────────

THREAT_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "indicator":              {"type": "keyword"},
            "type":                   {"type": "keyword"},
            "risk_score":             {"type": "float"},
            "severity":               {"type": "keyword"},
            "sources":                {"type": "keyword"},
            "source_count":           {"type": "integer"},
            "tags":                   {"type": "keyword"},
            "status":                 {"type": "keyword"},
            "enforced":               {"type": "boolean"},
            "last_seen":              {"type": "date"},
            "last_updated":           {"type": "date"},
            "created_at":             {"type": "date"},
            "@timestamp":             {"type": "date"},
            "abuse_confidence_score": {"type": "float"},
            "score_breakdown":        {"type": "object", "enabled": False},
        }
    },
    "settings": {
        "number_of_shards":   1,
        "number_of_replicas": 0,
        "refresh_interval":   "10s",
    },
}

BLOCKED_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "ip":           {"type": "keyword"},
            "risk_score":   {"type": "float"},
            "rule_id":      {"type": "keyword"},
            "status":       {"type": "keyword"},
            "blocked_at":   {"type": "date"},
            "unblocked_at": {"type": "date"},
            "unblocked_by": {"type": "keyword"},
            "@timestamp":   {"type": "date"},
        }
    },
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
}

AUDIT_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "timestamp":  {"type": "date"},
            "@timestamp": {"type": "date"},
            "action":     {"type": "keyword"},
            "target":     {"type": "keyword"},
            "actor":      {"type": "keyword"},
            "success":    {"type": "boolean"},
            "details":    {"type": "object", "enabled": False},
        }
    },
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
}


# ── ELK Pusher ────────────────────────────────────────────────────────────────

class ELKPusher:
    CHUNK_SIZE = 500

    def __init__(self, config_path: str = "config/config.yaml"):
        self.cfg = load_config(config_path)
        elk_cfg = self.cfg["elasticsearch"]

        host = elk_cfg.get("host", "localhost")
        port = elk_cfg.get("port", 9200)
        scheme = elk_cfg.get("scheme", "http")

        self.es = Elasticsearch(
            f"{scheme}://{host}:{port}",
            request_timeout=30,
            verify_certs=False,
            ssl_show_warn=False,
        )

        self.index_threats = elk_cfg["indices"]["threats"]
        self.index_blocked = elk_cfg["indices"]["blocked"]
        self.index_audit   = elk_cfg["indices"]["audit"]
        self.db = TIPDatabase(config_path)
        self._ensure_indices()

    def _ensure_indices(self):
        indices = {
            self.index_threats: THREAT_INDEX_MAPPING,
            self.index_blocked: BLOCKED_INDEX_MAPPING,
            self.index_audit:   AUDIT_INDEX_MAPPING,
        }
        for index_name, mapping in indices.items():
            try:
                exists = self.es.indices.exists(index=index_name)
                if not exists:
                    self.es.indices.create(index=index_name, body=mapping)
                    logger.info("Created ES index: %s", index_name)
                else:
                    logger.info("ES index already exists: %s", index_name)
            except Exception as e:
                logger.warning("Could not check/create index %s: %s", index_name, e)

    def _doc_to_es(self, doc: dict, index: str) -> dict:
        doc = dict(doc)
        doc.pop("_id", None)

        # Convert datetime objects to ISO strings
        for field in ("last_seen", "last_updated", "created_at", "blocked_at",
                       "unblocked_at", "timestamp"):
            if field in doc and hasattr(doc[field], "isoformat"):
                doc[field] = doc[field].isoformat()

        doc["@timestamp"] = datetime.now(timezone.utc).isoformat()
        return {"_index": index, "_source": doc}

    def push_threats(self) -> dict:
        logger.info("Pushing normalized indicators to ES...")
        col = self.db.db["normalized_indicators"]
        cursor = col.find({"status": "active"})
        actions = [self._doc_to_es(d, self.index_threats) for d in cursor]

        if not actions:
            logger.info("No normalized indicators to push.")
            return {"indexed": 0, "errors": 0}

        success, errors = helpers.bulk(
            self.es, actions,
            chunk_size=self.CHUNK_SIZE,
            raise_on_error=False,
            stats_only=False,
        )
        logger.info("Threats pushed — success: %d, errors: %d", success, len(errors))
        return {"indexed": success, "errors": len(errors)}

    def push_blocked(self) -> dict:
        logger.info("Pushing blocked IPs to ES...")
        col = self.db.db["blocked_ips"]
        cursor = col.find({})
        actions = [self._doc_to_es(d, self.index_blocked) for d in cursor]

        if not actions:
            logger.info("No blocked IPs to push.")
            return {"indexed": 0, "errors": 0}

        success, errors = helpers.bulk(
            self.es, actions,
            chunk_size=self.CHUNK_SIZE,
            raise_on_error=False,
            stats_only=False,
        )
        logger.info("Blocked IPs pushed — success: %d, errors: %d", success, len(errors))
        return {"indexed": success, "errors": len(errors)}

    def push_audit(self) -> dict:
        logger.info("Pushing audit log to ES...")
        col = self.db.db["audit_log"]
        cursor = col.find({})
        actions = [self._doc_to_es(d, self.index_audit) for d in cursor]

        if not actions:
            logger.info("No audit entries to push.")
            return {"indexed": 0, "errors": 0}

        success, errors = helpers.bulk(
            self.es, actions,
            chunk_size=self.CHUNK_SIZE,
            raise_on_error=False,
            stats_only=False,
        )
        logger.info("Audit log pushed — success: %d, errors: %d", success, len(errors))
        return {"indexed": success, "errors": len(errors)}

    def run(self):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )
        logger.info("=" * 60)
        logger.info("  TIP Platform — ELK Pusher (Week 2)")
        logger.info("=" * 60)

        info = self.es.info()
        logger.info("Connected to Elasticsearch %s", info["version"]["number"])

        results = {}
        results["threats"] = self.push_threats()
        results["blocked"] = self.push_blocked()
        results["audit"]   = self.push_audit()

        total = sum(r["indexed"] for r in results.values())
        logger.info("=" * 60)
        logger.info("ELK sync complete — total docs indexed: %d", total)
        logger.info("Open Kibana at http://localhost:5601")
        return results


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    pusher = ELKPusher()
    pusher.run()
