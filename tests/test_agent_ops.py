"""Registos, depuração, reinício/atualização a partir da consola, heartbeat e desistência do agente."""
import json
import time

import pytest

from omxpatch.engine import agentops
from omxpatch.extensions import db
from omxpatch.models import Agent, AgentLog, Asset, Task, Tenant, utcnow


@pytest.fixture()
def ag(app):
    with app.app_context():
        t = Tenant.query.filter_by(slug="alpha").first()
        a = Asset(tenant_id=t.id, name="h-ops", uid="ops-1")
        db.session.add(a)
        db.session.flush()
        agent = Agent(tenant_id=t.id, asset_id=a.id, key_hash="kops", key_prefix="omxa_ops", hostname="h-ops", version="1.20.20261109", last_seen=utcnow())
        db.session.add(agent)
        db.session.commit()
        yield agent


def test_commands_and_agent_config(app, ag):
    with app.app_context():
        agent = db.session.get(Agent, ag.id)
        t = agentops.command(agent, "restart")
        assert t.type == "agent_ctl" and json.loads(t.payload)["action"] == "restart"
        assert agentops.command(agent, "restart") is None                       # não duplica
        agentops.command(agent, "debug_on", minutes=30)
        db.session.commit()
        ac = agentops.agent_config(agent)
        assert 1700 < ac["debug_seconds"] <= 1800 and ac["giveup_minutes"] == 120
        agentops.command(agent, "debug_off")
        assert agentops.agent_config(agent)["debug_seconds"] == 0
        assert AgentLog.query.filter_by(agent_id=ag.id, source="console", kind="audit").count() >= 3


def test_ingest_validates_and_redacts(app, ag):
    with app.app_context():
        agent = db.session.get(Agent, ag.id)
        n = agentops.ingest(agent, [{"ts": time.time(), "kind": "audit", "level": "info", "msg": "x Bearer abcdefgh12345 omxa_secretsecret1"},
                                    {"ts": "lixo", "kind": "estranho", "level": "xx", "msg": "y" * 5000}, "não é dict"])
        db.session.commit()
        assert n == 2
        rows = AgentLog.query.filter_by(agent_id=ag.id).order_by(AgentLog.id).all()
        assert "abcdefgh12345" not in rows[0].message and "secretsecret1" not in rows[0].message
        assert rows[1].kind == "operation" and rows[1].level == "info" and len(rows[1].message) == 2000


def test_poll_and_logs_api(app, client, ag):
    with app.app_context():
        from omxpatch.web.agent_api import _hash
        agent = db.session.get(Agent, ag.id)
        agent.key_hash = _hash("omxa_testkeytestkey")
        agentops.command(agent, "debug_on", minutes=10)
        db.session.commit()
    h = {"Authorization": "Bearer omxa_testkeytestkey"}
    r = client.c.post("/agent/v1/poll", json={"version": "1.20.20261109", "state": {"uptime_s": 5, "debug": False, "python": "3.12"}}, headers=h)
    assert r.status_code == 200
    j = r.get_json()
    assert j["agent_config"]["debug_seconds"] > 0 and j["poll_seconds"] == 300
    r = client.c.post("/agent/v1/logs", json={"events": [{"ts": time.time(), "kind": "operation", "level": "warning", "msg": "algo"}]}, headers=h)
    assert r.get_json() == {"ok": True, "stored": 1}
    assert client.c.post("/agent/v1/logs", json={}, headers=h).status_code == 400
    with app.app_context():
        assert db.session.get(Agent, ag.id).status["uptime_s"] == 5


def test_agent_telemetry_giveup_and_debug(tmp_path, monkeypatch):
    monkeypatch.setenv("OMXPATCH_AGENT_DIR", str(tmp_path))
    from omxpatch_agent import config, telemetry
    monkeypatch.setattr(config, "config_dir", lambda: tmp_path)
    telemetry.update_runtime(giveup_minutes=120)
    t0 = 1_000_000.0
    assert telemetry.contact_failed(t0) == 0
    assert not telemetry.should_give_up(telemetry.contact_failed(t0 + 119 * 60))
    assert telemetry.should_give_up(telemetry.contact_failed(t0 + 121 * 60))
    telemetry.contact_ok()
    assert "first_fail" not in telemetry.runtime()
    telemetry.update_runtime(giveup_minutes=0)
    assert not telemetry.should_give_up(10 ** 6)                                  # 0 = nunca desligar
    telemetry.set_debug(600)
    assert telemetry.debug_active()
    telemetry.set_debug(0)
    assert not telemetry.debug_active()
    telemetry.event("operation", "info", "token=abc123 omxa_zzzzzzzz")
    evs, n = telemetry.pending(10)
    assert n >= 1 and "abc123" not in json.dumps(evs)


def test_agent_ctl_handler(tmp_path, monkeypatch):
    from omxpatch_agent import config, executor, telemetry
    monkeypatch.setattr(config, "config_dir", lambda: tmp_path)
    executor.PENDING_ACTION.clear()
    r = executor.HANDLERS["agent_ctl"](None, {"id": 1, "payload": {"action": "restart"}})
    assert r["status"] == "succeeded" and executor.PENDING_ACTION.get("restart")
    executor.PENDING_ACTION.clear()
    r = executor.HANDLERS["agent_ctl"](None, {"id": 2, "payload": {"action": "debug_on", "minutes": 5}})
    assert telemetry.debug_active() and r["status"] == "succeeded"
    assert executor.HANDLERS["agent_ctl"](None, {"id": 3, "payload": {"action": "nope"}})["status"] == "failed"


def test_console_pages(app, alpha_admin, alpha_user, ag):
    r = alpha_admin.get(f"/agents/{ag.id}")
    assert r.status_code == 200 and b"Ativar depura" in r.data
    r = alpha_admin.post(f"/agents/{ag.id}/command", {"action": "restart"})
    assert r.status_code == 302
    assert alpha_admin.post(f"/agents/{ag.id}/command", {"action": "rm -rf"}).status_code == 400
    assert alpha_user.post(f"/agents/{ag.id}/command", {"action": "restart"}).status_code == 403
    with app.app_context():
        assert Task.query.filter_by(type="agent_ctl", status="queued").count() == 1
    assert b"Reiniciar o agente" in alpha_admin.get(f"/agents/{ag.id}").data
    assert alpha_admin.get(f"/agents/{ag.id}/logs.csv").status_code == 200
    assert alpha_admin.get("/agents").status_code == 200


def test_run_loop_gives_up_after_two_hours(tmp_path, monkeypatch):
    from omxpatch_agent import cli, config, service, telemetry
    from omxpatch_agent.client import ServerError
    monkeypatch.setattr(config, "config_dir", lambda: tmp_path)
    clock = {"t": 2_000_000.0}
    monkeypatch.setattr(time, "time", lambda: clock["t"])
    monkeypatch.setattr(time, "sleep", lambda s: clock.__setitem__("t", clock["t"] + s))
    monkeypatch.setattr(cli, "_client", lambda: object())
    monkeypatch.setattr(cli, "cycle", lambda c, s: (_ for _ in ()).throw(ServerError("sem rede")))
    stopped = []
    monkeypatch.setattr(service, "stop_self", lambda: stopped.append(1) or True)
    monkeypatch.setattr(telemetry, "setup", lambda console=True: None)
    start = clock["t"]
    assert cli.cmd_run(None) == 0
    assert stopped == [1]
    waited = (clock["t"] - start) / 60
    assert 120 <= waited <= 140                      # ~2 h de tentativas (com recuo progressivo), não indefinidamente
    assert telemetry.runtime().get("disconnected")
    evs, _ = telemetry.pending(50)
    assert any("agent_giveup" in e["msg"] for e in evs)


def test_reenroll_reuses_entry_and_delete_with_history(app, alpha_admin, ag):
    import json as _j
    from omxpatch.models import EnrollmentToken, UpdateScan
    from omxpatch.web.agent_api import _hash
    with app.app_context():
        agent = db.session.get(Agent, ag.id)
        db.session.add(UpdateScan(tenant_id=agent.tenant_id, asset_id=agent.asset_id, agent_id=agent.id, scan_id="s1", total=1, sources="{}"))
        agentops.record(agent, "audit", "x")
        raw = "omxe_testtokentesttoken"
        db.session.add(EnrollmentToken(tenant_id=agent.tenant_id, name="t", token_hash=_hash(raw), prefix=raw[:9], ring=4))
        db.session.commit()
        before = Agent.query.filter_by(tenant_id=agent.tenant_id).count()
    c = alpha_admin.c
    for _ in range(2):
        r = c.post("/agent/v1/enroll", json={"token": raw, "hostname": "h-ops", "os_family": "linux"})
        assert r.status_code == 201, r.data
    with app.app_context():
        assert Agent.query.filter_by(tenant_id=agent.tenant_id).count() <= before + 1       # sem duplicados por reinstalação
    with app.app_context():
        a = Agent.query.filter_by(hostname="h-ops").first()
        a.revoked = True
        db.session.commit()
        aid = a.id
    assert alpha_admin.post(f"/agents/{aid}/delete").status_code == 302                      # antes: erro interno (FK do histórico)
    with app.app_context():
        assert db.session.get(Agent, aid) is None
        assert UpdateScan.query.filter_by(scan_id="s1").first() is not None
