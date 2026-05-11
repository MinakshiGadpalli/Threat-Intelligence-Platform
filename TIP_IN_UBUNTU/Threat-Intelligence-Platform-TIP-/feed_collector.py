"""
feed_collector.py - OSINT Threat Feed Aggregator
Week 1: Scrapes AlienVault OTX, AbuseIPDB, and URLhaus (all free tier)
        Deduplicates and stores results in MongoDB
"""

import logging
import logging.handlers
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator
import ipaddress

import requests
import yaml

# Adjust path so we can import db_handler from same package
sys.path.insert(0, str(Path(__file__).parent.parent))
from week1_osint.db_handler import TIPDatabase

# ── Logging Setup ─────────────────────────────────────────────────────────────
Path("logs").mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.handlers.RotatingFileHandler(
            "logs/tip_platform.log", maxBytes=10_485_760, backupCount=5
        ),
    ],
)
logger = logging.getLogger("feed_collector")


def load_config(path: str = "config/config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def is_valid_public_ip(ip_str: str) -> bool:
    """Validate IP is a real, routable public IP (not RFC1918/loopback)."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False


# ── Source 1: AlienVault OTX ──────────────────────────────────────────────────

class AlienVaultOTXCollector:
    """
    Pulls threat pulses from AlienVault OTX (Open Threat Exchange).
    Free registration at https://otx.alienvault.com
    """

    SOURCE = "alienvault_otx"

    def __init__(self, api_key: str, base_url: str):
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {"X-OTX-API-KEY": api_key}

    def collect(self, page_limit: int = 5) -> Generator[dict, None, None]:
        """
        Fetch subscribed pulses and extract IP/domain indicators.
        Yields normalized indicator dicts ready for MongoDB insertion.
        """
        logger.info("[OTX] Starting collection...")
        page = 1
        collected = 0

        while page <= page_limit:
            try:
                resp = requests.get(
                    f"{self.base_url}/pulses/subscribed",
                    headers=self.headers,
                    params={"page": page, "limit": 50},
                    timeout=30,
                )
                resp.raise_for_status()
                data = resp.json()
            except requests.RequestException as e:
                logger.error("[OTX] Request failed on page %d: %s", page, e)
                break

            pulses = data.get("results", [])
            if not pulses:
                break

            for pulse in pulses:
                pulse_name = pulse.get("name", "unknown")
                tags = pulse.get("tags", [])

                for indicator in pulse.get("indicators", []):
                    itype = indicator.get("type", "").lower()
                    value = indicator.get("indicator", "").strip()

                    if not value:
                        continue

                    # Only collect IP and domain indicators for now
                    if itype in ("ipv4", "ipv6"):
                        if not is_valid_public_ip(value):
                            continue
                        normalized_type = "ip"
                    elif itype in ("domain", "hostname", "url"):
                        normalized_type = "domain"
                    else:
                        continue

                    yield {
                        "indicator": value,
                        "type": normalized_type,
                        "source": self.SOURCE,
                        "tags": tags,
                        "raw_data": {
                            "pulse_name": pulse_name,
                            "otx_type": itype,
                            "description": indicator.get("description", ""),
                        },
                    }
                    collected += 1

            next_page = data.get("next")
            if not next_page:
                break
            page += 1
            time.sleep(0.5)  # Respect rate limits

        logger.info("[OTX] Collected %d indicators", collected)


# ── Source 2: AbuseIPDB ───────────────────────────────────────────────────────

class AbuseIPDBCollector:
    """
    Pulls recently reported malicious IPs from AbuseIPDB blacklist endpoint.
    Free tier: 1000 requests/day — https://www.abuseipdb.com/api
    """

    SOURCE = "abuseipdb"

    def __init__(self, api_key: str, base_url: str):
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {"Key": api_key, "Accept": "application/json"}

    def collect(self, confidence_minimum: int = 75, limit: int = 500) -> Generator[dict, None, None]:
        """
        Fetch blacklisted IPs with confidence score above threshold.
        confidence_minimum: 0-100, higher = more certain it's malicious
        """
        logger.info("[AbuseIPDB] Starting collection (confidence >= %d)...", confidence_minimum)

        try:
            resp = requests.get(
                f"{self.base_url}/blacklist",
                headers=self.headers,
                params={
                    "confidenceMinimum": confidence_minimum,
                    "limit": limit,
                },
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            logger.error("[AbuseIPDB] Request failed: %s", e)
            return

        entries = data.get("data", [])
        collected = 0

        for entry in entries:
            ip = entry.get("ipAddress", "").strip()
            if not ip or not is_valid_public_ip(ip):
                continue

            yield {
                "indicator": ip,
                "type": "ip",
                "source": self.SOURCE,
                "tags": ["abuse", "blacklisted"],
                "raw_data": {
                    "abuse_confidence_score": entry.get("abuseConfidenceScore", 0),
                    "country_code": entry.get("countryCode", ""),
                    "usage_type": entry.get("usageType", ""),
                    "isp": entry.get("isp", ""),
                    "total_reports": entry.get("totalReports", 0),
                    "last_reported_at": entry.get("lastReportedAt", ""),
                },
            }
            collected += 1

        logger.info("[AbuseIPDB] Collected %d indicators", collected)


# ── Source 3: URLhaus (no API key needed!) ────────────────────────────────────

class URLhausCollector:
    """
    Pulls recent malware URLs and hosting IPs from URLhaus.
    Completely free, no API key required — https://urlhaus-api.abuse.ch
    """

    SOURCE = "urlhaus"

    def __init__(self, base_url: str):
        self.base_url = base_url

    def collect(self, limit: int = 300) -> Generator[dict, None, None]:
        """
        Fetch recent malicious URLs (active malware distribution sites).
        Extracts both URL indicators and their hosting IPs.
        """
        logger.info("[URLhaus] Starting collection...")

        try:
            resp = requests.post(
                f"{self.base_url}/urls/recent/",
                data={"limit": limit},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            logger.error("[URLhaus] Request failed: %s", e)
            return

        urls = data.get("urls", [])
        collected = 0

        for entry in urls:
            url = entry.get("url", "").strip()
            host = entry.get("host", "").strip()
            tags = entry.get("tags") or []
            threat = entry.get("threat", "")
            url_status = entry.get("url_status", "")

            # Only include online/active threats
            if url_status not in ("online", "unknown"):
                continue

            # Yield URL indicator
            if url:
                yield {
                    "indicator": url,
                    "type": "url",
                    "source": self.SOURCE,
                    "tags": tags + [threat] if threat else tags,
                    "raw_data": {
                        "threat_type": threat,
                        "url_status": url_status,
                        "date_added": entry.get("date_added", ""),
                        "host": host,
                    },
                }
                collected += 1

            # Also yield the hosting IP/domain if it looks like an IP
            if host and is_valid_public_ip(host):
                yield {
                    "indicator": host,
                    "type": "ip",
                    "source": f"{self.SOURCE}_host",
                    "tags": ["malware-hosting"] + tags,
                    "raw_data": {
                        "threat_type": threat,
                        "malware_url": url,
                    },
                }
                collected += 1

        logger.info("[URLhaus] Collected %d indicators", collected)


# ── Orchestrator ──────────────────────────────────────────────────────────────

class FeedOrchestrator:
    """
    Runs all enabled collectors, batches results, and writes to MongoDB.
    """

    BATCH_SIZE = 200

    def __init__(self, config_path: str = "config/config.yaml"):
        self.cfg = load_config(config_path)
        self.db = TIPDatabase(config_path)
        self._build_collectors()

    def _build_collectors(self):
        self.collectors = []
        apis = self.cfg["apis"]

        if apis["alienvault_otx"]["enabled"]:
            key = apis["alienvault_otx"]["api_key"]
            if key and key != "YOUR_OTX_API_KEY_HERE":
                self.collectors.append(
                    AlienVaultOTXCollector(
                        key, apis["alienvault_otx"]["base_url"]
                    )
                )
                logger.info("Registered: AlienVault OTX")
            else:
                logger.warning("AlienVault OTX skipped — API key not configured")

        if apis["abuseipdb"]["enabled"]:
            key = apis["abuseipdb"]["api_key"]
            if key and key != "YOUR_ABUSEIPDB_KEY_HERE":
                self.collectors.append(
                    AbuseIPDBCollector(key, apis["abuseipdb"]["base_url"])
                )
                logger.info("Registered: AbuseIPDB")
            else:
                logger.warning("AbuseIPDB skipped — API key not configured")

        if apis["urlhaus"]["enabled"]:
            self.collectors.append(
                URLhausCollector(apis["urlhaus"]["base_url"])
            )
            logger.info("Registered: URLhaus (no key needed)")

        logger.info("%d collector(s) active", len(self.collectors))

    def run(self) -> dict:
        """
        Execute all collectors and persist results.
        Returns summary statistics.
        """
        total_stats = {"inserted": 0, "updated": 0, "errors": 0}
        run_start = datetime.now(timezone.utc)

        for collector in self.collectors:
            source = collector.SOURCE
            batch = []

            try:
                for indicator in collector.collect():
                    batch.append(indicator)
                    if len(batch) >= self.BATCH_SIZE:
                        result = self.db.upsert_raw_indicators(batch)
                        total_stats["inserted"] += result["inserted"]
                        total_stats["updated"] += result["updated"]
                        batch = []

                # Flush remaining
                if batch:
                    result = self.db.upsert_raw_indicators(batch)
                    total_stats["inserted"] += result["inserted"]
                    total_stats["updated"] += result["updated"]

            except Exception as e:
                logger.exception("[%s] Collector failed: %s", source, e)
                total_stats["errors"] += 1

        duration = (datetime.now(timezone.utc) - run_start).total_seconds()
        logger.info(
            "Collection complete in %.1fs — inserted: %d, updated: %d, errors: %d",
            duration,
            total_stats["inserted"],
            total_stats["updated"],
            total_stats["errors"],
        )

        # Log to audit trail
        self.db.log_audit(
            action="osint_collection_run",
            target="all_feeds",
            details={**total_stats, "duration_seconds": duration},
        )

        # Print database stats
        stats = self.db.get_stats()
        logger.info("DB Stats: %s", stats)

        return total_stats


if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("  TIP Platform — OSINT Feed Collector (Week 1)")
    logger.info("=" * 60)
    orchestrator = FeedOrchestrator()
    orchestrator.run()
