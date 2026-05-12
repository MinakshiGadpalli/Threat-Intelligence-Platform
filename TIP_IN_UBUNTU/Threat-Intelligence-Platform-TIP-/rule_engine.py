"""
rule_engine.py - iptables / nftables Firewall Rule Engine
Week 3: Executes and manages system-level firewall rules.
        All commands are logged to the audit trail for PCI-DSS compliance.
"""

import hashlib
import logging
import subprocess
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("rule_engine")


class FirewallRuleEngine:
    """
    Translates threat intelligence into active iptables firewall rules.

    Safety features:
    - IP whitelist validation before every block
    - Dry-run mode for safe testing
    - Atomic rule IDs for rollback tracking
    - All operations logged to audit trail
    """

    CHAIN = "TIP_BLOCKLIST"  # Dedicated chain — never touches INPUT directly

    def __init__(
        self,
        whitelist: list[str] = None,
        dry_run: bool = False,
        backend: str = "iptables",
    ):
        self.whitelist = set(whitelist or [])
        self.dry_run = dry_run
        self.backend = backend
        if dry_run:
            logger.warning("⚠️  DRY-RUN MODE ACTIVE — no rules will be applied")

    # ── Chain Management ──────────────────────────────────────────────────────

    def ensure_chain_exists(self) -> bool:
        """
        Create the TIP_BLOCKLIST chain and hook it into INPUT if not present.
        This approach keeps TIP rules isolated from system rules.
        """
        try:
            # Check if chain already exists
            result = self._run(
                ["iptables", "-L", self.CHAIN, "-n"], check=False
            )
            if result.returncode != 0:
                # Create the chain
                self._run(["iptables", "-N", self.CHAIN])
                logger.info("Created iptables chain: %s", self.CHAIN)

                # Hook it into INPUT (only once)
                self._run(
                    ["iptables", "-I", "INPUT", "1", "-j", self.CHAIN]
                )
                logger.info("Hooked %s into INPUT chain", self.CHAIN)
            return True
        except Exception as e:
            logger.error("Failed to ensure chain: %s", e)
            return False

    # ── Block / Unblock ───────────────────────────────────────────────────────

    def block_ip(self, ip: str, risk_score: float) -> Optional[str]:
        """
        Block inbound and outbound traffic to/from a malicious IP.
        Returns a rule_id that can be used for rollback, or None on failure.
        """
        # Safety check — never block whitelisted IPs
        if self._is_whitelisted(ip):
            logger.warning("Skipping whitelisted IP: %s", ip)
            return None

        rule_id = self._generate_rule_id(ip)
        comment = f"TIP:{rule_id[:8]}:score={risk_score}"

        commands = [
            # Block inbound from malicious IP
            [
                "iptables", "-A", self.CHAIN,
                "-s", ip,
                "-m", "comment", "--comment", comment,
                "-j", "DROP",
            ],
            # Block outbound to malicious IP (C2 prevention)
            [
                "iptables", "-A", "OUTPUT",
                "-d", ip,
                "-m", "comment", "--comment", comment,
                "-j", "DROP",
            ],
        ]

        success = True
        for cmd in commands:
            result = self._run(cmd)
            if result.returncode != 0:
                logger.error("Rule failed for %s: %s", ip, result.stderr)
                success = False

        if success:
            logger.info(
                "🚫 BLOCKED %s (score=%.1f, rule_id=%s)", ip, risk_score, rule_id[:8]
            )
            return rule_id
        return None

    def unblock_ip(self, ip: str, rule_id: str) -> bool:
        """
        Remove both INPUT and OUTPUT DROP rules for an IP.
        Used by the rollback manager when a false positive is detected.
        """
        comment_prefix = f"TIP:{rule_id[:8]}"
        success = True

        for table, flag in [("INPUT", "-s"), ("OUTPUT", "-d")]:
            # Find and delete matching rules
            try:
                # List rules with line numbers to find our rule
                list_result = subprocess.run(
                    ["iptables", "-L", table if table == "INPUT" else "OUTPUT",
                     "-n", "--line-numbers"],
                    capture_output=True, text=True
                )
                # Delete rules matching our rule comment (reverse order to preserve numbering)
                lines = list_result.stdout.strip().split("\n")
                to_delete = []
                for line in lines:
                    if comment_prefix in line:
                        line_num = line.split()[0]
                        to_delete.append(int(line_num))

                for line_num in sorted(to_delete, reverse=True):
                    chain = self.CHAIN if table == "INPUT" else "OUTPUT"
                    cmd = ["iptables", "-D", chain, str(line_num)]
                    result = self._run(cmd)
                    if result.returncode != 0:
                        success = False

            except Exception as e:
                logger.error("Unblock failed for %s: %s", ip, e)
                success = False

        # Alternative: direct delete approach
        comment = f"TIP:{rule_id[:8]}"
        for chain, flag in [(self.CHAIN, "-s"), ("OUTPUT", "-d")]:
            cmd = [
                "iptables", "-D", chain,
                flag, ip,
                "-m", "comment", "--comment", comment,
                "-j", "DROP",
            ]
            self._run(cmd, check=False)  # Best-effort

        if success:
            logger.info("✅ UNBLOCKED %s (rule_id=%s)", ip, rule_id[:8])
        return success

    # ── Bulk Operations ───────────────────────────────────────────────────────

    def flush_chain(self) -> bool:
        """
        Remove ALL rules from TIP_BLOCKLIST chain.
        Use with caution — only for maintenance or emergency flush.
        """
        logger.warning("⚠️  Flushing entire TIP_BLOCKLIST chain!")
        result = self._run(["iptables", "-F", self.CHAIN], check=False)
        return result.returncode == 0

    def list_active_rules(self) -> list[str]:
        """Return all active TIP rules for display/audit."""
        try:
            result = subprocess.run(
                ["iptables", "-L", self.CHAIN, "-n", "--line-numbers", "-v"],
                capture_output=True, text=True
            )
            lines = [l for l in result.stdout.split("\n") if "TIP:" in l]
            return lines
        except Exception:
            return []

    def get_rule_count(self) -> int:
        """Return number of active TIP firewall rules."""
        return len(self.list_active_rules())

    def is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked by a TIP rule."""
        try:
            result = subprocess.run(
                ["iptables", "-C", self.CHAIN, "-s", ip, "-j", "DROP"],
                capture_output=True, text=True
            )
            return result.returncode == 0
        except Exception:
            return False

    # ── Internal Helpers ──────────────────────────────────────────────────────

    def _run(
        self, cmd: list[str], check: bool = True
    ) -> subprocess.CompletedProcess:
        """Execute a command, respecting dry-run mode."""
        if self.dry_run:
            logger.info("[DRY-RUN] Would execute: %s", " ".join(cmd))
            return subprocess.CompletedProcess(cmd, 0, "", "")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if check and result.returncode != 0:
                logger.error(
                    "Command failed: %s\nSTDERR: %s",
                    " ".join(cmd),
                    result.stderr.strip(),
                )
            return result
        except subprocess.TimeoutExpired:
            logger.error("Command timed out: %s", " ".join(cmd))
            return subprocess.CompletedProcess(cmd, 1, "", "timeout")
        except FileNotFoundError:
            logger.error(
                "iptables not found. Install with: sudo apt install iptables"
            )
            return subprocess.CompletedProcess(cmd, 1, "", "not found")

    def _is_whitelisted(self, ip: str) -> bool:
        """Check if IP matches any whitelist entry (exact or CIDR)."""
        import ipaddress
        try:
            target = ipaddress.ip_address(ip)
            for entry in self.whitelist:
                try:
                    if "/" in entry:
                        if target in ipaddress.ip_network(entry, strict=False):
                            return True
                    else:
                        if target == ipaddress.ip_address(entry):
                            return True
                except ValueError:
                    continue
        except ValueError:
            pass
        return False

    @staticmethod
    def _generate_rule_id(ip: str) -> str:
        """Generate a deterministic rule ID from IP + timestamp."""
        seed = f"{ip}:{datetime.now(timezone.utc).isoformat()}"
        return hashlib.sha256(seed.encode()).hexdigest()
