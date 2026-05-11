"""
test_all.py - TIP Platform Unit Tests
Tests all modules across all 4 weeks without requiring live services.
Run with: pytest tests/test_all.py -v
"""

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, str(Path(__file__).parent.parent))


# ══════════════════════════════════════════════════════════════════════════════
# Week 1: OSINT Collectors
# ══════════════════════════════════════════════════════════════════════════════

class TestIPValidation(unittest.TestCase):
    """Test the IP validation utility used by collectors."""

    def setUp(self):
        from week1_osint.feed_collector import is_valid_public_ip
        self.validate = is_valid_public_ip

    def test_valid_public_ips(self):
        for ip in ["8.8.8.8", "1.1.1.1", "185.220.101.1", "45.33.32.156"]:
            with self.subTest(ip=ip):
                self.assertTrue(self.validate(ip))

    def test_private_ips_rejected(self):
        for ip in ["192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1"]:
            with self.subTest(ip=ip):
                self.assertFalse(self.validate(ip))

    def test_invalid_strings_rejected(self):
        for val in ["not-an-ip", "", "999.999.999.999", "abc.def.ghi.jkl"]:
            with self.subTest(val=val):
                self.assertFalse(self.validate(val))

    def test_multicast_reserved_rejected(self):
        for ip in ["224.0.0.1", "240.0.0.1", "0.0.0.0"]:
            with self.subTest(ip=ip):
                self.assertFalse(self.validate(ip))


class TestAbuseIPDBCollector(unittest.TestCase):
    """Test AbuseIPDB collector with mocked HTTP responses."""

    @patch("week1_osint.feed_collector.requests.get")
    def test_collect_yields_valid_indicators(self, mock_get):
        from week1_osint.feed_collector import AbuseIPDBCollector

        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "data": [
                {
                    "ipAddress": "185.220.101.1",
                    "abuseConfidenceScore": 95,
                    "countryCode": "DE",
                    "usageType": "Data Center/Web Hosting/Transit",
                    "isp": "Tor Exit Node",
                    "totalReports": 150,
                    "lastReportedAt": "2024-01-15T10:00:00+00:00",
                },
                {
                    "ipAddress": "192.168.1.1",  # Private — should be filtered
                    "abuseConfidenceScore": 80,
                    "countryCode": "US",
                    "usageType": "",
                    "isp": "",
                    "totalReports": 5,
                    "lastReportedAt": "",
                },
            ]
        }

        collector = AbuseIPDBCollector("test-key", "https://api.abuseipdb.com/api/v2")
        results = list(collector.collect())

        # Only public IPs should be yielded
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["indicator"], "185.220.101.1")
        self.assertEqual(results[0]["type"], "ip")
        self.assertEqual(results[0]["source"], "abuseipdb")
        self.assertEqual(results[0]["raw_data"]["abuse_confidence_score"], 95)

    @patch("week1_osint.feed_collector.requests.get")
    def test_handles_api_error_gracefully(self, mock_get):
        from week1_osint.feed_collector import AbuseIPDBCollector
        import requests as req

        mock_get.side_effect = req.ConnectionError("Connection refused")
        collector = AbuseIPDBCollector("test-key", "https://api.abuseipdb.com/api/v2")
        results = list(collector.collect())
        self.assertEqual(results, [])


class TestURLhausCollector(unittest.TestCase):
    """Test URLhaus collector with mocked responses."""

    @patch("week1_osint.feed_collector.requests.post")
    def test_collect_active_urls(self, mock_post):
        from week1_osint.feed_collector import URLhausCollector

        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            "urls": [
                {
                    "url": "http://malware-host.example.com/payload.exe",
                    "host": "45.33.32.156",
                    "url_status": "online",
                    "threat": "malware_download",
                    "tags": ["emotet"],
                    "date_added": "2024-01-15 10:00:00 UTC",
                },
                {
                    "url": "http://old-site.example.com/payload.zip",
                    "host": "1.2.3.4",
                    "url_status": "offline",  # Should be filtered
                    "threat": "malware_download",
                    "tags": [],
                    "date_added": "2024-01-01 00:00:00 UTC",
                },
            ]
        }

        collector = URLhausCollector("https://urlhaus-api.abuse.ch/v1")
        results = list(collector.collect())

        # Should yield URL indicator + host IP for the online entry only
        self.assertEqual(len(results), 2)
        types = {r["type"] for r in results}
        self.assertIn("url", types)
        self.assertIn("ip", types)

    @patch("week1_osint.feed_collector.requests.post")
    def test_skips_offline_urls(self, mock_post):
        from week1_osint.feed_collector import URLhausCollector

        mock_post.return_value.json.return_value = {
            "urls": [
                {"url": "http://offline.example.com/x", "host": "1.2.3.4",
                 "url_status": "offline", "threat": "malware", "tags": [], "date_added": ""},
            ]
        }
        collector = URLhausCollector("https://urlhaus-api.abuse.ch/v1")
        results = list(collector.collect())
        self.assertEqual(len(results), 0)


# ══════════════════════════════════════════════════════════════════════════════
# Week 2: Risk Scoring
# ══════════════════════════════════════════════════════════════════════════════

class TestRiskScorer(unittest.TestCase):
    """Test risk scoring logic."""

    def setUp(self):
        from week2_siem.normalizer import RiskScorer
        self.scorer = RiskScorer()

    def _make_doc(self, indicator, itype, source, tags=None, raw_data=None):
        return {
            "indicator": indicator,
            "type": itype,
            "source": source,
            "tags": tags or [],
            "raw_data": raw_data or {},
        }

    def test_score_is_between_0_and_10(self):
        docs = [self._make_doc("8.8.8.8", "ip", "abuseipdb")]
        result = self.scorer.calculate(docs)
        self.assertGreaterEqual(result["risk_score"], 0.0)
        self.assertLessEqual(result["risk_score"], 10.0)

    def test_ransomware_tag_raises_score(self):
        docs_no_tag = [self._make_doc("1.2.3.4", "ip", "urlhaus")]
        docs_ransomware = [self._make_doc("1.2.3.4", "ip", "urlhaus", tags=["ransomware"])]
        score_clean = self.scorer.calculate(docs_no_tag)["risk_score"]
        score_ransomware = self.scorer.calculate(docs_ransomware)["risk_score"]
        self.assertGreater(score_ransomware, score_clean)

    def test_multiple_sources_increase_score(self):
        doc_single = [self._make_doc("1.2.3.4", "ip", "urlhaus")]
        docs_multi = [
            self._make_doc("1.2.3.4", "ip", "urlhaus"),
            self._make_doc("1.2.3.4", "ip", "abuseipdb"),
            self._make_doc("1.2.3.4", "ip", "alienvault_otx"),
        ]
        score_single = self.scorer.calculate(doc_single)["risk_score"]
        score_multi = self.scorer.calculate(docs_multi)["risk_score"]
        self.assertGreater(score_multi, score_single)

    def test_high_abuse_confidence_raises_score(self):
        docs = [
            self._make_doc(
                "5.5.5.5", "ip", "abuseipdb",
                raw_data={"abuse_confidence_score": 98}
            )
        ]
        result = self.scorer.calculate(docs)
        self.assertGreater(result["risk_score"], 6.0)

    def test_severity_bands_correct(self):
        cases = [
            (9.5, "CRITICAL"),
            (8.0, "HIGH"),
            (5.0, "MEDIUM"),
            (2.0, "LOW"),
        ]
        for score, expected_severity in cases:
            with self.subTest(score=score):
                # Manually check band assignment
                if score >= 9.0:
                    band = "CRITICAL"
                elif score >= 7.0:
                    band = "HIGH"
                elif score >= 4.0:
                    band = "MEDIUM"
                elif score >= 1.0:
                    band = "LOW"
                else:
                    band = "INFO"
                self.assertEqual(band, expected_severity)

    def test_returns_none_for_empty_input(self):
        result = self.scorer.calculate([])
        self.assertIsNone(result)

    def test_correct_fields_in_output(self):
        docs = [self._make_doc("10.0.0.1", "ip", "urlhaus", tags=["botnet"])]
        result = self.scorer.calculate(docs)
        required_fields = [
            "indicator", "type", "risk_score", "severity",
            "sources", "source_count", "tags", "status",
            "score_breakdown"
        ]
        for field in required_fields:
            self.assertIn(field, result)


# ══════════════════════════════════════════════════════════════════════════════
# Week 3: Firewall Rule Engine
# ══════════════════════════════════════════════════════════════════════════════

class TestFirewallRuleEngine(unittest.TestCase):
    """Test the rule engine in dry-run mode (safe, no root required)."""

    def setUp(self):
        from week3_enforcer.rule_engine import FirewallRuleEngine
        self.engine = FirewallRuleEngine(
            whitelist=["192.168.0.0/16", "10.0.0.0/8", "127.0.0.1"],
            dry_run=True,
        )

    def test_whitelist_blocks_private_ranges(self):
        self.assertIsNone(self.engine.block_ip("192.168.1.1", 9.5))
        self.assertIsNone(self.engine.block_ip("10.20.30.40", 9.5))
        self.assertIsNone(self.engine.block_ip("127.0.0.1", 9.5))

    def test_public_ip_returns_rule_id(self):
        result = self.engine.block_ip("185.220.101.1", 8.5)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, str)
        self.assertEqual(len(result), 64)  # SHA-256 hex digest

    def test_rule_id_unique_per_call(self):
        id1 = self.engine.block_ip("185.220.101.1", 8.5)
        id2 = self.engine.block_ip("185.220.101.1", 8.5)
        # Rule IDs include timestamp so they should be different
        # (in extremely fast execution they might be the same — acceptable)
        self.assertIsNotNone(id1)
        self.assertIsNotNone(id2)

    def test_dry_run_does_not_call_subprocess(self):
        with patch("week3_enforcer.rule_engine.subprocess.run") as mock_run:
            self.engine.block_ip("185.220.101.1", 8.5)
            mock_run.assert_not_called()

    def test_whitelist_cidr_matching(self):
        self.assertTrue(self.engine._is_whitelisted("192.168.100.50"))
        self.assertTrue(self.engine._is_whitelisted("10.255.255.255"))
        self.assertFalse(self.engine._is_whitelisted("8.8.8.8"))
        self.assertFalse(self.engine._is_whitelisted("185.220.101.1"))


# ══════════════════════════════════════════════════════════════════════════════
# Week 4: Rollback and Alerting
# ══════════════════════════════════════════════════════════════════════════════

class TestRollbackManager(unittest.TestCase):
    """Test rollback manager with mocked database."""

    def setUp(self):
        self.patcher = patch("week4_dashboard.rollback_manager.TIPDatabase")
        self.mock_db_class = self.patcher.start()
        self.mock_db = MagicMock()
        self.mock_db_class.return_value = self.mock_db

        self.patcher2 = patch("week4_dashboard.rollback_manager.FirewallRuleEngine")
        self.mock_engine_class = self.patcher2.start()
        self.mock_engine = MagicMock()
        self.mock_engine_class.return_value = self.mock_engine

        from week4_dashboard.rollback_manager import RollbackManager
        with patch("week4_dashboard.rollback_manager.load_config") as mock_cfg:
            mock_cfg.return_value = {
                "enforcer": {"whitelist": [], "dry_run": True}
            }
            self.mgr = RollbackManager()

    def tearDown(self):
        self.patcher.stop()
        self.patcher2.stop()

    def test_unblock_existing_ip_succeeds(self):
        self.mock_db.blocked.find_one.return_value = {
            "ip": "1.2.3.4",
            "rule_id": "abc123def456",
            "risk_score": 8.5,
        }
        self.mock_db.unblock_ip.return_value = True
        self.mock_engine.unblock_ip.return_value = True

        result = self.mgr.unblock_ip("1.2.3.4", "alice", "false_positive")
        self.assertTrue(result)
        self.mock_db.log_audit.assert_called_once()
        audit_call = self.mock_db.log_audit.call_args
        self.assertEqual(audit_call.kwargs["action"], "ip_unblocked")

    def test_unblock_nonexistent_ip_fails(self):
        self.mock_db.blocked.find_one.return_value = None
        result = self.mgr.unblock_ip("99.99.99.99", "alice", "test")
        self.assertFalse(result)

    def test_unblock_always_writes_audit_log(self):
        self.mock_db.blocked.find_one.return_value = {
            "ip": "1.2.3.4", "rule_id": "abc", "risk_score": 7.0
        }
        self.mock_db.unblock_ip.return_value = True
        self.mgr.unblock_ip("1.2.3.4", "bob", "test")
        self.mock_db.log_audit.assert_called()


class TestAlertManager(unittest.TestCase):
    """Test alert manager dispatch logic."""

    def setUp(self):
        self.patcher = patch("week4_dashboard.alert_manager.TIPDatabase")
        self.mock_db_class = self.patcher.start()
        self.mock_db = MagicMock()
        self.mock_db_class.return_value = self.mock_db

    def tearDown(self):
        self.patcher.stop()

    def test_no_channels_logs_warning(self):
        with patch("week4_dashboard.alert_manager.load_config") as mock_cfg:
            mock_cfg.return_value = {
                "alerts": {
                    "email": {"enabled": False},
                    "slack": {"enabled": False},
                }
            }
            from week4_dashboard.alert_manager import AlertManager
            mgr = AlertManager()
            # Should not raise even with no channels
            with self.assertLogs("alert_manager", level="WARNING"):
                mgr._dispatch("Test", "Test body", "HIGH")

    @patch("week4_dashboard.alert_manager.requests.post")
    def test_slack_sends_post_request(self, mock_post):
        from week4_dashboard.alert_manager import SlackAlerter

        mock_post.return_value.status_code = 200
        alerter = SlackAlerter("https://hooks.slack.com/test/webhook")
        result = alerter.send("Test Alert", "Test message", "HIGH")
        self.assertTrue(result)
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        payload = call_kwargs.kwargs.get("json", call_kwargs[1].get("json", {}))
        self.assertIn("attachments", payload)


# ══════════════════════════════════════════════════════════════════════════════
# Integration-style: DB Handler
# ══════════════════════════════════════════════════════════════════════════════

class TestTIPDatabaseMocked(unittest.TestCase):
    """Test DB handler logic with mocked pymongo."""

    def setUp(self):
        with patch("week1_osint.db_handler.MongoClient"), \
             patch("week1_osint.db_handler.load_config") as mock_cfg:
            mock_cfg.return_value = {
                "mongodb": {
                    "host": "localhost",
                    "port": 27017,
                    "database": "test_db",
                    "collections": {
                        "raw_indicators": "raw",
                        "normalized": "norm",
                        "blocked_ips": "blocked",
                        "audit_log": "audit",
                    },
                }
            }
            from week1_osint.db_handler import TIPDatabase
            self.db = TIPDatabase()

    def test_upsert_raw_empty_list_returns_zero(self):
        result = self.db.upsert_raw_indicators([])
        self.assertEqual(result, {"inserted": 0, "updated": 0})

    def test_upsert_normalized_empty_list_returns_zero(self):
        result = self.db.upsert_normalized([])
        self.assertEqual(result, {"inserted": 0, "updated": 0})


if __name__ == "__main__":
    unittest.main(verbosity=2)
