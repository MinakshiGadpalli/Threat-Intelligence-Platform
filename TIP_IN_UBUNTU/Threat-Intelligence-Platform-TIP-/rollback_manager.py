"""
rollback_manager.py - Firewall Rule Rollback System
Week 4: Allows SOC analysts to reverse automated firewall blocks.
        All rollbacks are audited for PCI-DSS compliance.
        Provides both CLI and programmatic interfaces.
"""

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))
from week1_osint.db_handler import TIPDatabase
from week3_enforcer.rule_engine import FirewallRuleEngine

logger = logging.getLogger("rollback_manager")


def load_config(path: str = "config/config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


class RollbackManager:
    """
    SOC analyst tool to:
    - List all currently blocked IPs
    - Unblock a specific IP (false positive response)
    - Unblock all IPs (emergency flush)
    - View rollback history
    - Re-block a previously unblocked IP
    """

    def __init__(self, config_path: str = "config/config.yaml"):
        self.cfg = load_config(config_path)
        self.db = TIPDatabase(config_path)
        enforcer_cfg = self.cfg["enforcer"]
        self.engine = FirewallRuleEngine(
            whitelist=enforcer_cfg.get("whitelist", []),
            dry_run=enforcer_cfg.get("dry_run", False),
        )

    def list_active_blocks(self) -> list[dict]:
        """Return all IPs currently blocked by TIP."""
        blocks = self.db.get_active_blocks()
        if not blocks:
            print("\n✅ No active TIP blocks found.\n")
            return []

        print(f"\n{'─'*70}")
        print(f"{'IP ADDRESS':<20} {'RISK':>6}  {'BLOCKED AT':<30} {'RULE ID':<12}")
        print(f"{'─'*70}")
        for b in blocks:
            blocked_at = b.get("blocked_at", "N/A")
            if hasattr(blocked_at, "strftime"):
                blocked_at = blocked_at.strftime("%Y-%m-%d %H:%M:%S UTC")
            print(
                f"{b['ip']:<20} {b.get('risk_score', 0):>6.1f}  "
                f"{str(blocked_at):<30} {b.get('rule_id', '')[:8]:<12}"
            )
        print(f"{'─'*70}")
        print(f"Total active blocks: {len(blocks)}\n")
        return blocks

    def unblock_ip(self, ip: str, actor: str, reason: str = "") -> bool:
        """
        Unblock a specific IP. Removes iptables rule and updates DB.
        SOC analyst must provide their name as actor for the audit trail.
        """
        # Verify IP is actually blocked
        block_record = self.db.blocked.find_one({"ip": ip, "status": "active"})
        if not block_record:
            logger.warning("IP %s is not in the active block list", ip)
            print(f"⚠️  {ip} is not currently blocked by TIP.")
            return False

        rule_id = block_record.get("rule_id", "")
        risk_score = block_record.get("risk_score", 0)

        logger.info("Unblocking %s (rule_id=%s) by %s. Reason: %s",
                    ip, rule_id[:8], actor, reason)

        # Remove iptables rule
        rule_removed = self.engine.unblock_ip(ip, rule_id)

        # Update MongoDB regardless (the iptables rule might already be gone)
        db_updated = self.db.unblock_ip(ip, actor)

        # Write to audit log — immutable record required for PCI-DSS
        self.db.log_audit(
            action="ip_unblocked",
            target=ip,
            actor=actor,
            details={
                "rule_id": rule_id,
                "original_risk_score": risk_score,
                "reason": reason or "false_positive",
                "rule_removed_from_firewall": rule_removed,
            },
            success=db_updated,
        )

        if db_updated:
            print(f"✅ {ip} has been unblocked by {actor}")
            print(f"   Rule ID: {rule_id[:8]}...")
            print(f"   Reason recorded: {reason or 'false_positive'}")
            logger.info("✅ Unblocked %s by %s", ip, actor)
        else:
            print(f"❌ Failed to unblock {ip}")
            logger.error("Failed to unblock %s", ip)

        return db_updated

    def unblock_all(self, actor: str, confirm: bool = False) -> int:
        """
        Emergency flush — unblock ALL active IPs.
        Requires explicit confirmation to prevent accidental use.
        """
        if not confirm:
            print("⚠️  This will unblock ALL active IPs. Pass confirm=True to proceed.")
            return 0

        blocks = self.db.get_active_blocks()
        count = 0
        for block in blocks:
            if self.unblock_ip(block["ip"], actor, reason="emergency_flush"):
                count += 1

        # Flush the entire chain as a safety net
        self.engine.flush_chain()

        self.db.log_audit(
            action="emergency_flush",
            target="all_ips",
            actor=actor,
            details={"ips_unblocked": count},
        )
        print(f"\n🔓 Emergency flush complete. Unblocked {count} IPs.")
        return count

    def reblock_ip(self, ip: str, actor: str) -> bool:
        """
        Re-block an IP that was previously manually unblocked.
        Useful when a false positive determination was incorrect.
        """
        # Get the normalized record
        record = self.db.normalized.find_one({"indicator": ip})
        if not record:
            print(f"⚠️  No threat record found for {ip}")
            return False

        risk_score = record.get("risk_score", 5.0)

        # Re-apply firewall rule
        rule_id = self.engine.block_ip(ip, risk_score)
        if rule_id:
            self.db.record_blocked_ip(ip, risk_score, rule_id)
            self.db.log_audit(
                action="ip_reblocked",
                target=ip,
                actor=actor,
                details={"rule_id": rule_id, "risk_score": risk_score},
            )
            print(f"🚫 {ip} has been re-blocked (score: {risk_score:.1f})")
            return True
        return False

    def get_rollback_history(self, limit: int = 50) -> list[dict]:
        """Retrieve history of all unblock/reblock actions."""
        entries = list(
            self.db.audit.find(
                {"action": {"$in": ["ip_unblocked", "ip_reblocked", "emergency_flush"]}},
                {"_id": 0},
            )
            .sort("timestamp", -1)
            .limit(limit)
        )
        if entries:
            print(f"\n{'─'*80}")
            print(f"{'ACTION':<16} {'TARGET':<20} {'ACTOR':<20} {'TIMESTAMP':<25}")
            print(f"{'─'*80}")
            for e in entries:
                ts = e.get("timestamp", "")
                if hasattr(ts, "strftime"):
                    ts = ts.strftime("%Y-%m-%d %H:%M UTC")
                print(
                    f"{e.get('action',''):<16} {e.get('target',''):<20} "
                    f"{e.get('actor',''):<20} {str(ts):<25}"
                )
            print(f"{'─'*80}\n")
        return entries


# ── CLI Interface ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="TIP Rollback Manager — Manage TIP firewall blocks"
    )
    subparsers = parser.add_subparsers(dest="command")

    # list command
    subparsers.add_parser("list", help="List all active blocks")

    # unblock command
    unblock = subparsers.add_parser("unblock", help="Unblock a specific IP")
    unblock.add_argument("ip", help="IP address to unblock")
    unblock.add_argument("--actor", required=True, help="SOC analyst name (required)")
    unblock.add_argument("--reason", default="false_positive", help="Reason for unblocking")

    # reblock command
    reblock = subparsers.add_parser("reblock", help="Re-block a previously unblocked IP")
    reblock.add_argument("ip", help="IP address to re-block")
    reblock.add_argument("--actor", required=True, help="SOC analyst name")

    # flush command
    flush = subparsers.add_parser("flush", help="Emergency flush — unblock ALL IPs")
    flush.add_argument("--actor", required=True, help="SOC analyst name")
    flush.add_argument("--confirm", action="store_true", help="Required to execute flush")

    # history command
    history = subparsers.add_parser("history", help="Show rollback history")
    history.add_argument("--limit", type=int, default=50)

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    mgr = RollbackManager()

    if args.command == "list":
        mgr.list_active_blocks()
    elif args.command == "unblock":
        mgr.unblock_ip(args.ip, args.actor, args.reason)
    elif args.command == "reblock":
        mgr.reblock_ip(args.ip, args.actor)
    elif args.command == "flush":
        mgr.unblock_all(args.actor, confirm=args.confirm)
    elif args.command == "history":
        mgr.get_rollback_history(args.limit)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
