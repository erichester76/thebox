"""
Alert notification backend.

Reads configuration from environment variables:

  ALERT_EMAIL        — recipient address (enables email delivery)
  SMTP_HOST          — SMTP server hostname
  SMTP_PORT          — SMTP port (default: 587)
  SMTP_FROM          — sender address (default: alerts@thebox.local)
  SMTP_USER          — SMTP username (optional)
  SMTP_PASSWORD      — SMTP password (optional)
  SMTP_TLS           — use STARTTLS when "true" (default: true)
  ALERT_WEBHOOK_URL  — HTTP endpoint to POST alerts to (enables webhook)

Both channels are optional and independent.  If neither is configured the
function returns immediately without raising any exception.
"""

import json
import logging
import os
import smtplib
import urllib.error
import urllib.request
from email.mime.text import MIMEText

log = logging.getLogger(__name__)

_ALERT_EMAIL = os.environ.get("ALERT_EMAIL", "")
_SMTP_HOST = os.environ.get("SMTP_HOST", "")
try:
    _SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
except ValueError:
    _SMTP_PORT = 587
_SMTP_FROM = os.environ.get("SMTP_FROM", "alerts@thebox.local")
_SMTP_USER = os.environ.get("SMTP_USER", "")
_SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
_SMTP_TLS = os.environ.get("SMTP_TLS", "true").lower() == "true"
_ALERT_WEBHOOK_URL = os.environ.get("ALERT_WEBHOOK_URL", "")


def send_alert_notification(source: str, level: str, title: str, detail: str) -> None:
    """Deliver a notification via every configured channel; swallows all errors."""
    _send_email(source, level, title, detail)
    _send_webhook(source, level, title, detail)


def _send_email(source: str, level: str, title: str, detail: str) -> None:
    if not _ALERT_EMAIL or not _SMTP_HOST:
        return
    try:
        subject = f"[TheBox Alert] [{level.upper()}] {title}"
        body = (
            f"Source:  {source}\n"
            f"Level:   {level}\n"
            f"Title:   {title}\n\n"
            f"{detail}"
        )
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = _SMTP_FROM
        msg["To"] = _ALERT_EMAIL
        smtp = smtplib.SMTP(_SMTP_HOST, _SMTP_PORT, timeout=10)
        try:
            if _SMTP_TLS:
                smtp.starttls()
            if _SMTP_USER:
                smtp.login(_SMTP_USER, _SMTP_PASSWORD)
            smtp.sendmail(_SMTP_FROM, [_ALERT_EMAIL], msg.as_string())
        finally:
            smtp.quit()
        log.info("alert email sent to %s", _ALERT_EMAIL)
    except Exception:
        log.exception("failed to send alert email")


def _send_webhook(source: str, level: str, title: str, detail: str) -> None:
    if not _ALERT_WEBHOOK_URL:
        return
    try:
        payload = json.dumps(
            {"source": source, "level": level, "title": title, "detail": detail}
        ).encode()
        req = urllib.request.Request(
            _ALERT_WEBHOOK_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            log.info("alert webhook delivered status=%s", resp.status)
    except Exception:
        log.exception("failed to deliver alert webhook")
