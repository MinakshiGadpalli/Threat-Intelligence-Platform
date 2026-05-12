"""
alert_manager.py - Multi-Channel Alert Manager
Week 4: Sends real-time alerts to SOC analysts via email and/or Slack
        when high-risk threats are detected or firewall rules are applied
"""

import json
import logging
import smtplib
import sys
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

import requests
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))
from week1_osint.db_handler import TIPDatabase

logger = logging.getLogger("alert_manager")


def load_config(path: str = "config/config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


# ── Email Alerter ─────────────────────────────────────────────────────────────

class EmailAlerter:
    def __init__(self, cfg: dict):
        self.smtp_host = cfg["smtp_host"]
        self.smtp_port = cfg["smtp_port"]
        self.sender = cfg["sender"]
        self.password = cfg["password"]
        self.recipients = cfg["recipients"]

    def send(self, subject: str, body_html: str) -> bool:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.sender
            msg["To"] = ", ".join(self.recipients)
            msg.attach(MIMEText(body_html, "html"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender, self.password)
                server.sendmail(self.sender, self.recipients, msg.as_string())

            logger.info("Email alert sent to %s", self.recipients)
            return True
        except Exception as e:
            logger.error("Email send failed: %s", e)
            return False


# ── Slack Alerter ─────────────────────────────────────────────────────────────

class SlackAlerter:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(self, title: str, message: str, severity: str = "HIGH") -> bool:
        color_map = {
            "CRITICAL": "#FF0000",
            "HIGH": "#FF6600",
            "MEDIUM": "#FFA500",
            "LOW": "#FFFF00",
            "INFO": "#36a64f",
        }
        color = color_map.get(severity, "#36a64f")

        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": f"🛡️ TIP Alert — {title}",
                    "text": message,
                    "footer": "Threat Intelligence Platform",
                    "ts": int(datetime.now(timezone.utc).timestamp()),
                    "fields": [
                        {"title": "Severity", "value": severity, "short": True},
                        {
                            "title": "Time",
                            "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                            "short": True,
                        },
                    ],
                }
            ]
        }

        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=10)
            resp.raise_for_status()
            logger.info("Slack alert sent")
            return True
        except Exception as e:
            logger.error("Slack send failed: %s", e)
            return False


# ── Alert Manager ─────────────────────────────────────────────────────────────

class AlertManager:
    """
    Monitors MongoDB for new high-severity threats and blocked IPs,
    sends multi-channel alerts to the SOC team.
    """

    def __init__(self, config_path: str = "config/config.yaml"):
        self.cfg = load_config(config_path)
        self.db = TIPDatabase(config_path)
        self._email: Optional[EmailAlerter] = None
        self._slack: Optional[SlackAlerter] = None
        self._setup_channels()

    def _setup_channels(self):
        alert_cfg = self.cfg.get("alerts", {})

        if alert_cfg.get("email", {}).get("enabled"):
            self._email = EmailAlerter(alert_cfg["email"])
            logger.info("Email alerts enabled")

        if alert_cfg.get("slack", {}).get("enabled"):
            self._slack = SlackAlerter(alert_cfg["slack"]["webhook_url"])
            logger.info("Slack alerts enabled")

        if not self._email and not self._slack:
            logger.warning(
                "No alert channels configured. Set alerts.email.enabled or "
                "alerts.slack.enabled in config.yaml"
            )

    def alert_new_block(self, ip: str, risk_score: float, severity: str, tags: list):
        """Send alert when a new IP is blocked by the policy daemon."""
        title = f"IP Blocked: {ip}"
        body = (
            f"The TIP Policy Daemon has automatically blocked:\n\n"
            f"IP:        {ip}\n"
            f"Score:     {risk_score:.1f}/10.0\n"
            f"Severity:  {severity}\n"
            f"Tags:      {', '.join(tags)}\n\n"
            f"To review and roll back if false positive:\n"
            f"  python3 week4_dashboard/rollback_manager.py list\n"
            f"  python3 week4_dashboard/rollback_manager.py unblock {ip} --actor YOUR_NAME"
        )
        self._dispatch(title, body, severity)

    def alert_high_risk_detected(
        self, indicator: str, itype: str, risk_score: float, sources: list
    ):
        """Alert when a high-risk indicator is detected but not yet blocked."""
        title = f"High-Risk {itype.upper()} Detected: {indicator}"
        body = (
            f"A high-risk indicator has been identified:\n\n"
            f"Indicator: {indicator}\n"
            f"Type:      {itype}\n"
            f"Score:     {risk_score:.1f}/10.0\n"
            f"Sources:   {', '.join(sources)}\n\n"
            f"The policy daemon will automatically block this if score >= threshold."
        )
        severity = "CRITICAL" if risk_score >= 9 else "HIGH"
        self._dispatch(title, body, severity)

    def alert_false_positive_rollback(self, ip: str, actor: str, reason: str):
        """Alert when a SOC analyst manually unblocks an IP."""
        title = f"Manual Rollback: {ip}"
        body = (
            f"A TIP firewall block has been manually reversed:\n\n"
            f"IP:      {ip}\n"
            f"Actor:   {actor}\n"
            f"Reason:  {reason}\n"
            f"Time:    {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n\n"
            f"This action has been recorded in the PCI-DSS audit log."
        )
        self._dispatch(title, body, severity="INFO")

    def send_daily_summary(self) -> dict:
        """
        Generate and send a daily threat summary to SOC analysts.
        """
        stats = self.db.get_stats()
        severity_dist = self._get_severity_dist()

        title = f"TIP Daily Summary — {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
        body = (
            f"Daily Threat Intelligence Summary\n"
            f"{'='*40}\n\n"
            f"Total Indicators:   {stats['raw_indicators']:,}\n"
            f"Normalized:         {stats['normalized_indicators']:,}\n"
            f"Active Blocks:      {stats['active_blocks']:,}\n"
            f"Pending (High Risk): {stats['high_risk_pending']:,}\n\n"
            f"Severity Distribution:\n"
        )
        for sev, count in severity_dist.items():
            body += f"  {sev:<10}: {count:,}\n"

        self._dispatch(title, body, severity="INFO")
        logger.info("Daily summary sent")
        return stats

    def _dispatch(self, title: str, body: str, severity: str = "HIGH"):
        """Send to all configured channels."""
        if self._email:
            html_body = f"<pre>{body}</pre>"
            self._email.send(f"[TIP] {title}", html_body)

        if self._slack:
            self._slack.send(title, body, severity)

        if not self._email and not self._slack:
            # Fallback: print to console and log
            logger.warning("[ALERT] %s\n%s", title, body)

    def _get_severity_dist(self) -> dict:
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
    logger.info("  TIP Platform — Alert Manager (Week 4)")
    logger.info("=" * 60)
    mgr = AlertManager()
    mgr.send_daily_summary()
