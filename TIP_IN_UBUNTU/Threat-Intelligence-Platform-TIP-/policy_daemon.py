"""
policy_daemon.py - Dynamic Security Policy Enforcement Daemon
Week 3: Continuously monitors high-risk indicators in MongoDB
        and automatically enforces iptables firewall rules.
        Must be run as root: sudo python3 week3_enforcer/policy_daemon.py
"""

import logging
import logging.handlers
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))
from week1_osint.db_handler import TIPDatabase
from week3_enforcer.rule_engine import FirewallRuleEngine

# ── Logging ───────────────────────────────────────────────────────────────────
Path("logs").mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.handlers.RotatingFileHandler(
            "logs/policy_daemon.log", maxBytes=10_485_760, backupCount=5
        ),
    ],
)
logger = logging.getLogger("policy_daemon")


def load_config(path: str = "config/config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


# ── Daemon ────────────────────────────────────────────────────────────────────

class PolicyEnforcementDaemon:
    """
    Continuously running daemon that:
    1. Polls MongoDB for high-risk indicators not yet enforced
    2. Validates each IP against the whitelist
    3. Applies iptables DROP rules via FirewallRuleEngine
    4. Records every action in the audit log
    5. Pushes enforcement events to Elasticsearch

    Requires root privileges for iptables operations.
    """

    def __init__(self, config_path: str = "config/config.yaml"):
        self.cfg = load_config(config_path)
        self.enforcer_cfg = self.cfg["enforcer"]
        self.db = TIPDatabase(config_path)
        self.engine = FirewallRuleEngine(
            whitelist=self.enforcer_cfg.get("whitelist", []),
            dry_run=self.enforcer_cfg.get("dry_run", False),
            backend=self.enforcer_cfg.get("firewall_backend", "iptables"),
        )
        self.check_interval = self.enforcer_cfg.get("check_interval_seconds", 60)
        self.risk_threshold = self.enforcer_cfg.get("risk_threshold", 7.0)
        self._running = False
        self._cycle_count = 0

        # Register graceful shutdown handlers
        signal.signal(signal.SIGINT, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

    def _check_root(self) -> bool:
        """Warn if not running as root (required for iptables)."""
        if os.geteuid() != 0 and not self.engine.dry_run:
            logger.error(
                "❌ Must run as root for iptables. Use: sudo python3 week3_enforcer/policy_daemon.py"
            )
            logger.error("   Or set dry_run: true in config.yaml for testing.")
            return False
        return True

    def start(self):
        """Start the daemon loop."""
        if not self._check_root():
            sys.exit(1)

        logger.info("=" * 60)
        logger.info("  TIP Policy Enforcement Daemon — STARTING")
        logger.info("  Risk threshold:   >= %.1f", self.risk_threshold)
        logger.info("  Check interval:   %ds", self.check_interval)
        logger.info("  Dry-run mode:     %s", self.engine.dry_run)
        logger.info("=" * 60)

        # Ensure iptables chain exists
        if not self.engine.dry_run:
            self.engine.ensure_chain_exists()

        self._running = True
        self.db.log_audit(
            action="daemon_start",
            target="policy_daemon",
            details={
                "risk_threshold": self.risk_threshold,
                "check_interval": self.check_interval,
                "dry_run": self.engine.dry_run,
            },
        )

        while self._running:
            try:
                self._enforcement_cycle()
            except Exception as e:
                logger.exception("Cycle failed: %s", e)

            logger.debug("Sleeping for %ds...", self.check_interval)
            time.sleep(self.check_interval)

    def _enforcement_cycle(self):
        """
        Single enforcement cycle:
        - Query MongoDB for high-risk unblocked IPs
        - Apply firewall rules
        - Record results
        """
        self._cycle_count += 1
        cycle_start = datetime.now(timezone.utc)

        # Fetch high-risk indicators not yet enforced
        indicators = self.db.get_high_risk_indicators(
            min_score=self.risk_threshold
        )

        if not indicators:
            logger.debug("[Cycle %d] No new high-risk indicators", self._cycle_count)
            return

        logger.info(
            "[Cycle %d] Found %d high-risk indicator(s) to enforce",
            self._cycle_count,
            len(indicators),
        )

        blocked_count = 0
        failed_count = 0

        for indicator in indicators:
            ip = indicator["indicator"]
            risk_score = indicator["risk_score"]
            severity = indicator["severity"]
            tags = indicator.get("tags", [])

            logger.info(
                "Processing %s — score: %.1f (%s), tags: %s",
                ip, risk_score, severity, tags,
            )

            # Apply firewall rule
            rule_id = self.engine.block_ip(ip, risk_score)

            if rule_id:
                # Record in MongoDB
                self.db.record_blocked_ip(ip, risk_score, rule_id)

                # Write to audit log
                self.db.log_audit(
                    action="ip_blocked",
                    target=ip,
                    actor="policy_daemon",
                    details={
                        "rule_id": rule_id,
                        "risk_score": risk_score,
                        "severity": severity,
                        "tags": tags,
                        "sources": indicator.get("sources", []),
                        "cycle": self._cycle_count,
                    },
                    success=True,
                )
                blocked_count += 1

            else:
                # Whitelisted or rule application failed
                self.db.log_audit(
                    action="ip_block_failed",
                    target=ip,
                    actor="policy_daemon",
                    details={
                        "risk_score": risk_score,
                        "reason": "whitelisted_or_error",
                    },
                    success=False,
                )
                # Mark as enforced anyway to avoid retry loops
                self.db.normalized.update_one(
                    {"indicator": ip},
                    {"$set": {"enforced": True, "block_skipped": True}},
                )
                failed_count += 1

        duration = (datetime.now(timezone.utc) - cycle_start).total_seconds()
        active_rules = self.engine.get_rule_count()

        logger.info(
            "[Cycle %d] Complete in %.2fs — blocked: %d, failed/skipped: %d, active rules: %d",
            self._cycle_count, duration, blocked_count, failed_count, active_rules,
        )

    def _shutdown(self, signum, frame):
        """Graceful shutdown on SIGINT/SIGTERM."""
        logger.info("Shutdown signal received. Stopping daemon...")
        self._running = False
        active_rules = self.engine.get_rule_count()
        self.db.log_audit(
            action="daemon_stop",
            target="policy_daemon",
            details={
                "cycles_completed": self._cycle_count,
                "active_rules_at_stop": active_rules,
            },
        )
        logger.info(
            "Daemon stopped. Completed %d cycles. Active rules: %d",
            self._cycle_count, active_rules,
        )
        sys.exit(0)

    def get_status(self) -> dict:
        """Return current daemon status."""
        return {
            "running": self._running,
            "cycle_count": self._cycle_count,
            "active_rules": self.engine.get_rule_count(),
            "db_stats": self.db.get_stats(),
        }


if __name__ == "__main__":
    daemon = PolicyEnforcementDaemon()
    daemon.start()
