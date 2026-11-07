"""Notificações por e-mail (SMTP) e webhook (Teams / Slack / SOAR) da organização."""
from __future__ import annotations

import logging
import smtplib
import ssl
import threading
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

import requests
from flask import current_app

from .extensions import db
from .models import NotificationLog, Tenant
from .security import OutboundURLError, check_outbound_url

log = logging.getLogger("omxpatch.notify")


def send_email(recipients: list[str], subject: str, body: str, cfg=None) -> None:
    cfg = cfg if cfg is not None else current_app.config
    host = cfg.get("SMTP_HOST")
    if not host:
        raise RuntimeError("SMTP não configurado ([smtp] host)")
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, cfg.get("MAIL_FROM") or "omxpatch@localhost", ", ".join(recipients)
    msg["Date"], msg["Message-ID"] = formatdate(localtime=True), make_msgid()
    msg.set_content(body)
    port, timeout = int(cfg.get("SMTP_PORT") or 587), int(cfg.get("SMTP_TIMEOUT") or 30)
    if cfg.get("SMTP_SSL"):
        smtp = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ssl.create_default_context())
    else:
        smtp = smtplib.SMTP(host, port, timeout=timeout)
        if cfg.get("SMTP_STARTTLS"):
            smtp.starttls(context=ssl.create_default_context())
    with smtp:
        if cfg.get("SMTP_USERNAME"):
            smtp.login(cfg["SMTP_USERNAME"], cfg.get("SMTP_PASSWORD", ""))
        smtp.send_message(msg)


def _deliver(app, tenant_id: int, subject: str, body: str) -> None:
    with app.app_context():
        tenant = db.session.get(Tenant, tenant_id)
        if tenant is None:
            return
        emails = [e.strip() for e in (tenant.notify_emails or "").replace(";", ",").split(",") if e.strip()]
        if emails and app.config.get("SMTP_HOST"):
            try:
                send_email(emails, subject, body)
                db.session.add(NotificationLog(tenant_id=tenant_id, channel="email", subject=subject[:300], ok=True))
            except Exception as exc:  # noqa: BLE001
                db.session.add(NotificationLog(tenant_id=tenant_id, channel="email", subject=subject[:300], ok=False, detail=str(exc)[:500]))
        if tenant.webhook_url:
            try:
                check_outbound_url(tenant.webhook_url)
                r = requests.post(tenant.webhook_url, json={"text": f"{subject}\n{body}"[:3500], "subject": subject, "body": body}, timeout=15)
                db.session.add(NotificationLog(tenant_id=tenant_id, channel="webhook", subject=subject[:300], ok=r.status_code < 300,
                                               detail=f"HTTP {r.status_code}"))
            except (requests.RequestException, OutboundURLError) as exc:
                db.session.add(NotificationLog(tenant_id=tenant_id, channel="webhook", subject=subject[:300], ok=False, detail=str(exc)[:500]))
        db.session.commit()


def notify(tenant: Tenant, subject: str, body: str) -> None:
    app = current_app._get_current_object()
    if app.config.get("NOTIFY_ASYNC") and not app.config.get("TESTING"):
        threading.Thread(target=_deliver, args=(app, tenant.id, subject, body), daemon=True).start()
    else:
        _deliver(app, tenant.id, subject, body)
