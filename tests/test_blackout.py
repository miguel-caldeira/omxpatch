"""I3 — congelações, prazo limite e reinício com aviso."""
from __future__ import annotations

from datetime import date, datetime, timedelta

from omxpatch.engine import agentops, deploy
from omxpatch.extensions import db
from omxpatch.models import Agent, BlackoutPeriod, MaintenanceWindow, Tenant
from omxpatch_agent import executor, reboot
from tests.conftest import make_asset


def _noon(d: date) -> datetime:
    return datetime(d.year, d.month, d.day, 12, 0)


def test_blackout_blocks_all_windows_and_only_allowed_emergency_passes(app, tenant):
    with app.app_context():
        a = make_asset(tenant, "b1", ring=2)
        other = make_asset(tenant, "b2", ring=4)
        today = date.today()
        now = datetime.utcnow().replace(hour=12, minute=0, second=0, microsecond=0)
        assert deploy.window_allows(tenant.id, a, now) == (True, "")                      # sem janelas nem congelações
        db.session.add(BlackoutPeriod(tenant_id=tenant.id, name="Fecho de contas", start_date=today - timedelta(days=1), end_date=today + timedelta(days=1), rings="2"))
        db.session.flush()
        ok, why = deploy.window_allows(tenant.id, a, now)
        assert not ok and "Fecho de contas" in why
        assert deploy.window_allows(tenant.id, other, now)[0]                              # anel 4 fora do âmbito
        assert not deploy.window_allows(tenant.id, a, now, emergency=True)[0]              # emergência só se o período o permitir
        BlackoutPeriod.query.one().allow_emergency = True
        assert deploy.window_allows(tenant.id, a, now, emergency=True)[0]
        BlackoutPeriod.query.one().enabled = False
        assert deploy.window_allows(tenant.id, a, now)[0]
        BlackoutPeriod.query.one().enabled, BlackoutPeriod.query.one().end_date = True, today - timedelta(days=1)
        assert deploy.window_allows(tenant.id, a, now)[0]                                  # já terminou


def test_deadline_overrides_windows_but_never_a_blackout(app, tenant):
    with app.app_context():
        a = make_asset(tenant, "d1")
        now = datetime.utcnow().replace(hour=12, minute=0, second=0, microsecond=0)
        db.session.add(MaintenanceWindow(tenant_id=tenant.id, name="Noite", weekdays="0,1,2,3,4,5,6", start_time="03:00", duration_minutes=30, timezone="UTC"))
        db.session.flush()
        assert not deploy.window_allows(tenant.id, a, now)[0]
        assert not deploy.window_allows(tenant.id, a, now, deadline=now + timedelta(hours=1))[0]          # prazo ainda não chegou
        ok, why = deploy.window_allows(tenant.id, a, now, deadline=now - timedelta(minutes=1))
        assert ok and "prazo limite" in why
        db.session.add(BlackoutPeriod(tenant_id=tenant.id, name="Freeze", start_date=now.date(), end_date=now.date()))
        db.session.flush()
        assert not deploy.window_allows(tenant.id, a, now, deadline=now - timedelta(days=1))[0]            # congelação prevalece sobre o prazo


def test_reboot_helper_gives_notice_and_can_cancel(monkeypatch):
    calls = []

    class R:
        ok, out, err = True, "", ""
    monkeypatch.setattr(reboot, "run", lambda cmd, timeout=3600, **k: calls.append(cmd) or R())
    monkeypatch.setattr(reboot.sys, "platform", "linux")
    assert "30 minuto" in reboot.schedule(30)
    assert calls[-1][:3] == ["shutdown", "-r", "+30"] and "Guarde" in calls[-1][3]
    monkeypatch.setattr(reboot.sys, "platform", "win32")
    reboot.schedule(5)
    assert calls[-1][:4] == ["shutdown", "/r", "/t", "300"]
    reboot.cancel()
    assert calls[-1] == ["shutdown", "/a"]
    assert reboot.clamp(0) == 1 and reboot.clamp(10 ** 9) == 10080 and reboot.clamp("x") == 2


def test_agent_ctl_reboot_actions(monkeypatch):
    seen = []
    monkeypatch.setattr(reboot, "schedule", lambda m, *a: seen.append(("s", m)) or f"agendado {m}")
    monkeypatch.setattr(reboot, "cancel", lambda: seen.append(("c",)) or "cancelado")
    r = executor._agent_ctl(None, {"id": 1, "payload": {"action": "reboot", "minutes": 45, "requested_by": "x"}})
    assert r["status"] == "succeeded" and seen[-1] == ("s", 45)
    assert executor._agent_ctl(None, {"id": 2, "payload": {"action": "reboot_cancel"}})["output"] == "cancelado"


def test_console_schedules_reboot_and_settings(app, tenant, alpha_admin):
    with app.app_context():
        a = make_asset(tenant, "r1")
        ag = Agent(tenant_id=tenant.id, asset_id=a.id, key_hash="k" * 64, key_prefix="k", hostname="r1", os_family="linux")
        db.session.add(ag)
        db.session.commit()
        aid = ag.id
    alpha_admin.post(f"/agents/{aid}/command", data={"action": "reboot", "minutes": "45"})
    with app.app_context():
        t = agentops.Task.query.filter_by(type="agent_ctl").one()
        assert t.payload_data["action"] == "reboot" and t.payload_data["minutes"] == 45
    alpha_admin.post("/windows/blackout", data={"name": "Natal", "start_date": "2026-12-20", "end_date": "2027-01-03"})
    alpha_admin.post("/windows/blackout", data={"act": "notice", "reboot_notice_min": "15"})
    alpha_admin.post("/windows/blackout", data={"name": "Mau", "start_date": "2026-12-20", "end_date": "2026-12-01"})          # datas invertidas: recusado
    page = alpha_admin.get("/windows").data.decode()
    assert "Natal" in page and "Mau" not in page
    with app.app_context():
        assert db.session.get(Tenant, tenant.id).reboot_notice_min == 15 and deploy.reboot_notice(tenant.id) == 15
