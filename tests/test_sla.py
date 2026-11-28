"""I5 — SLA, aging, cobertura, CSV e relatório agendado."""
from __future__ import annotations

from datetime import timedelta

from omxpatch import notifications
from omxpatch.engine import sla
from omxpatch.extensions import db
from omxpatch.models import Agent, Exposure, Tenant, utcnow
from tests.conftest import make_asset


def exp(tenant, asset, cve, cat, age, status="open", closed_after=None, due_in=None):
    now = utcnow()
    e = Exposure(tenant_id=tenant.id, asset_id=asset.id, cve_id=cve, status=status, risk_category=cat, risk_score=80, detected_at=now - timedelta(days=age),
                 due_date=(now - timedelta(days=age) + timedelta(days=due_in)) if due_in is not None else None)
    if closed_after is not None:
        e.closed_at = e.detected_at + timedelta(days=closed_after)
    db.session.add(e)
    db.session.flush()
    return e


def test_report_mttr_sla_aging_and_coverage(app, tenant):
    with app.app_context():
        a, b = make_asset(tenant, "s1"), make_asset(tenant, "s2")
        b.managed = False
        exp(tenant, a, "CVE-2026-0001", "critical", 40, "closed", closed_after=5, due_in=7)          # cumpriu (5 ≤ 7)
        exp(tenant, a, "CVE-2026-0002", "critical", 40, "closed", closed_after=10, due_in=7)         # falhou
        exp(tenant, a, "CVE-2026-0003", "critical", 20, "open", due_in=7)                            # aberta, atrasada 13 d
        exp(tenant, b, "CVE-2026-0004", "low", 3, "open", due_in=180)
        exp(tenant, b, "CVE-2026-0005", "high", 100, "open", due_in=30)
        db.session.add(Agent(tenant_id=tenant.id, asset_id=a.id, key_hash="z" * 64, key_prefix="z", last_seen=utcnow()))
        db.session.flush()
        r = sla.report(tenant)
        c = r["categories"]["critical"]
        assert c["open"] == 1 and c["overdue"] == 1 and c["closed"] == 2 and c["mttr_days"] == 7.5 and c["sla_compliance"] == 50.0 and c["sla_days"] == tenant.sla_critical
        assert r["overall_sla"] == 50.0 and r["open"] == 3 and r["overdue_total"] == 2
        ages = {x["label"]: x["n"] for x in r["aging"]}
        assert ages["0–7 d"] == 1 and ages["8–30 d"] == 1 and ages["> 90 d"] == 1 and ages["31–60 d"] == 0
        assert r["coverage"]["assets"] == 2 and r["coverage"]["agent_active"] == 1 and r["coverage"]["managed"] == 1 and r["coverage"]["pct"] == 50.0
        assert r["oldest"][0]["cve"] == "CVE-2026-0005" and r["oldest"][0]["overdue_days"] == 70


def test_csv_neutralises_formulas_and_flags_sla(app, tenant):
    with app.app_context():
        a = make_asset(tenant, "=cmd|calc")
        exp(tenant, a, "CVE-2026-0009", "critical", 30, "open", due_in=7)
        exp(tenant, a, "CVE-2026-0010", "high", 2, "open", due_in=30)
        text = sla.csv_text(tenant)
        lines = text.strip().splitlines()
        assert lines[0].startswith("CVE;Ativo;") and "'=cmd|calc" in text
        assert any("fora do prazo" in x and "CVE-2026-0009" in x for x in lines) and any("dentro do prazo" in x and "CVE-2026-0010" in x for x in lines)


def test_scheduling_rules_and_email_with_csv(app, tenant, monkeypatch):
    with app.app_context():
        t = db.session.get(Tenant, tenant.id)
        a = make_asset(t, "m1")
        exp(t, a, "CVE-2026-0011", "high", 5, "open", due_in=30)
        sent = []
        monkeypatch.setattr(notifications, "send_email", lambda rec, subj, body, cfg=None, attachments=None: sent.append((rec, subj, body, attachments)))
        from datetime import datetime
        monday, tuesday, first = datetime(2026, 11, 30, 8), datetime(2026, 12, 1, 8), datetime(2026, 12, 1, 8)
        assert not sla.due_now(t, monday)                                         # desligado
        t.report_schedule, t.notify_emails = "weekly", "ciso@example.com; sec@example.com"
        assert sla.due_now(t, monday) and not sla.due_now(t, tuesday)
        assert sla.send_report(t, monday) == 2
        rec, subj, body, att = sent[0]
        assert rec == ["ciso@example.com", "sec@example.com"] and "SLA" in subj and "Envelhecimento" in body and att[0][0] == "omxpatch-sla-20261130.csv" and att[0][1].startswith(b"\xef\xbb\xbfCVE")
        assert not sla.due_now(t, monday + timedelta(days=1))                      # já enviado há < 5 dias
        t.report_schedule, t.report_last_sent = "monthly", None
        assert sla.due_now(t, first) and not sla.due_now(t, monday)
        t.notify_emails = ""
        assert not sla.due_now(t, first)


def test_send_email_builds_attachment(monkeypatch):
    import smtplib
    msgs = []

    class S:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def starttls(self, **k): pass
        def login(self, *a): pass
        def send_message(self, m): msgs.append(m)
    monkeypatch.setattr(smtplib, "SMTP", S)
    notifications.send_email(["a@b.pt"], "x", "corpo", cfg={"SMTP_HOST": "h", "SMTP_STARTTLS": False}, attachments=[("r.csv", b"a;b\n", "text/csv")])
    parts = list(msgs[0].iter_attachments())
    assert parts[0].get_filename() == "r.csv" and parts[0].get_content_type() == "text/csv"


def test_pages_csv_and_schedule_form(app, tenant, alpha_admin):
    with app.app_context():
        exp(tenant, make_asset(tenant, "w1"), "CVE-2026-0012", "critical", 9, "open", due_in=7)
        db.session.commit()
    page = alpha_admin.get("/sla").data.decode()
    assert "Cumprimento de SLA" in page and "Envelhecimento" in page and "CVE-2026-0012" in page
    r = alpha_admin.get("/sla.csv")
    assert r.status_code == 200 and r.headers["Content-Type"].startswith("text/csv") and b"CVE-2026-0012" in r.data
    alpha_admin.post("/sla/schedule", data={"schedule": "monthly"})
    with app.app_context():
        assert db.session.get(Tenant, tenant.id).report_schedule == "monthly"
