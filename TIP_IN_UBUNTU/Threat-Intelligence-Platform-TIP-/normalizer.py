"""
normalizer.py - Threat Indicator Normalization & Risk Scoring Engine
Week 2: Reads raw indicators from MongoDB, calculates risk scores,
        and writes normalized records back to MongoDB
"""

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))
from week1_osint.db_handler import TIPDatabase

logger = logging.getLogger("normalizer")


def load_config(path: str = "config/config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


# ── Risk Scoring Engine ───────────────────────────────────────────────────────

class RiskScorer:
    """
    Assigns a risk score (0.0–10.0) to each indicator based on:
      - Source credibility weight
      - Indicator type
      - Number of sources that reported it (corroboration)
      - Malicious tags and threat categories
      - AbuseIPDB confidence scores when available
    Aligned with CVSS v3 severity bands.
    """

    # Source credibility weights (0–1)
    SOURCE_WEIGHTS = {
        "alienvault_otx": 0.75,
        "abuseipdb": 0.90,
        "urlhaus": 0.85,
        "urlhaus_host": 0.80,
        "virustotal": 0.95,
        "unknown": 0.40,
    }

    # Indicator type base scores
    TYPE_BASE = {
        "ip": 6.0,
        "domain": 5.0,
        "url": 7.0,
        "hash": 8.0,
        "email": 4.0,
        "unknown": 3.0,
    }

    # Tag multipliers — add to base score
    HIGH_RISK_TAGS = {
        "malware": 1.5,
        "ransomware": 2.0,
        "botnet": 1.5,
        "c2": 2.0,
        "command-and-control": 2.0,
        "phishing": 1.2,
        "exploit": 1.8,
        "apt": 2.0,
        "cryptomining": 1.0,
        "spam": 0.5,
        "scanner": 0.7,
        "bruteforce": 0.8,
        "ddos": 1.0,
        "trojan": 1.5,
    }

    def calculate(self, raw_docs: list[dict]) -> Optional[dict]:
        """
        Given a list of raw documents for the SAME indicator (from different
        sources), compute a unified normalized record with a risk score.
        """
        if not raw_docs:
            return None

        indicator = raw_docs[0]["indicator"]
        itype = raw_docs[0].get("type", "unknown")

        # Aggregate data across all source documents
        all_tags = set()
        all_sources = set()
        source_weights = []
        abuse_score: Optional[float] = None
        raw_collection = []

        for doc in raw_docs:
            src = doc.get("source", "unknown")
            all_sources.add(src)
            all_tags.update(doc.get("tags", []))
            source_weights.append(self.SOURCE_WEIGHTS.get(src, 0.40))
            raw_collection.append(doc.get("raw_data", {}))

            # Extract AbuseIPDB confidence if present
            if "abuse_confidence_score" in doc.get("raw_data", {}):
                abuse_score = doc["raw_data"]["abuse_confidence_score"]

        # ── Score Calculation ──────────────────────────────────────────────
        base_score = self.TYPE_BASE.get(itype, 3.0)

        # Source credibility factor (average weight of all sources)
        avg_weight = sum(source_weights) / len(source_weights)

        # Corroboration bonus — more sources = higher confidence
        corroboration_bonus = min(len(all_sources) * 0.3, 1.5)

        # Tag risk addition
        tag_addition = 0.0
        all_tags_lower = {t.lower() for t in all_tags}
        for tag, bonus in self.HIGH_RISK_TAGS.items():
            if tag in all_tags_lower:
                tag_addition += bonus

        # AbuseIPDB override — their score is authoritative
        if abuse_score is not None:
            # Map 0-100 confidence to 0-10 score scale
            abuse_risk = (abuse_score / 100) * 10
            base_score = max(base_score, abuse_risk * 0.9)

        # Final calculation
        raw_score = (base_score * avg_weight) + corroboration_bonus + tag_addition
        final_score = round(min(raw_score, 10.0), 2)

        # ── Severity Band ──────────────────────────────────────────────────
        if final_score >= 9.0:
            severity = "CRITICAL"
        elif final_score >= 7.0:
            severity = "HIGH"
        elif final_score >= 4.0:
            severity = "MEDIUM"
        elif final_score >= 1.0:
            severity = "LOW"
        else:
            severity = "INFO"

        return {
            "indicator": indicator,
            "type": itype,
            "risk_score": final_score,
            "severity": severity,
            "sources": list(all_sources),
            "source_count": len(all_sources),
            "tags": list(all_tags),
            "abuse_confidence_score": abuse_score,
            "status": "active",
            "enforced": False,
            "last_seen": datetime.now(timezone.utc),
            "raw_refs": raw_collection[:3],  # Store up to 3 raw refs
            "score_breakdown": {
                "base_score": base_score,
                "avg_source_weight": round(avg_weight, 3),
                "corroboration_bonus": round(corroboration_bonus, 3),
                "tag_addition": round(tag_addition, 3),
            },
        }


# ── Normalization Pipeline ────────────────────────────────────────────────────

class NormalizationPipeline:
    """
    Reads all raw indicators from MongoDB, groups them by indicator value,
    scores them, and writes normalized records back.
    """

    BATCH_SIZE = 500

    def __init__(self, config_path: str = "config/config.yaml"):
        self.cfg = load_config(config_path)
        self.db = TIPDatabase(config_path)
        self.scorer = RiskScorer()

    def run(self) -> dict:
        logger.info("Starting normalization pipeline...")
        start = datetime.now(timezone.utc)

        # Pull all raw indicators and group by indicator value
        raw_docs = self.db.get_raw_indicators(limit=50000)
        logger.info("Loaded %d raw indicators", len(raw_docs))

        # Group by indicator value
        grouped: dict[str, list[dict]] = {}
        for doc in raw_docs:
            key = doc["indicator"]
            grouped.setdefault(key, []).append(doc)

        logger.info("Unique indicators: %d", len(grouped))

        # Score and batch-write
        batch = []
        total_normalized = 0

        for indicator, docs in grouped.items():
            normalized = self.scorer.calculate(docs)
            if normalized:
                batch.append(normalized)

            if len(batch) >= self.BATCH_SIZE:
                result = self.db.upsert_normalized(batch)
                total_normalized += result["inserted"] + result["updated"]
                batch = []

        if batch:
            result = self.db.upsert_normalized(batch)
            total_normalized += result["inserted"] + result["updated"]

        duration = (datetime.now(timezone.utc) - start).total_seconds()

        # Print severity distribution
        severity_counts = self._get_severity_distribution()
        logger.info("Normalization complete in %.1fs — %d records", duration, total_normalized)
        logger.info("Severity distribution: %s", severity_counts)

        self.db.log_audit(
            action="normalization_run",
            target="all_indicators",
            details={
                "total_normalized": total_normalized,
                "duration_seconds": duration,
                "severity_distribution": severity_counts,
            },
        )

        return {
            "total_normalized": total_normalized,
            "duration_seconds": duration,
            "severity_distribution": severity_counts,
        }

    def _get_severity_distribution(self) -> dict:
        pipeline = [
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        return {
            doc["_id"]: doc["count"]
            for doc in self.db.normalized.aggregate(pipeline)
        }


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logger.info("=" * 60)
    logger.info("  TIP Platform — Normalizer & Risk Scorer (Week 2)")
    logger.info("=" * 60)
    pipeline = NormalizationPipeline()
    pipeline.run()
