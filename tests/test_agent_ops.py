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


def test_restart_command_and_main_as_script(monkeypatch):
    import os
    import subprocess
    import sys
    from pathlib import Path
    import omxpatch_agent
    from omxpatch_agent import update
    monkeypatch.setattr(sys, "argv", [str(Path(omxpatch_agent.__file__).parent / "__main__.py"), "run"])
    assert update.restart_argv() == [sys.executable, "-m", "omxpatch_agent", "run"]
    # o relançamento antigo (python …/__main__.py run) também tem de funcionar com o __main__ novo
    main = Path(omxpatch_agent.__file__).parent / "__main__.py"
    r = subprocess.run([sys.executable, str(main), "status"], capture_output=True, text=True, cwd="/tmp", env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"})
    assert r.returncode == 0 and "Agente" in r.stdout, r.stderr


def test_console_update_reports_real_outcome(tmp_path, monkeypatch):
    from omxpatch_agent import config, executor, update
    monkeypatch.setattr(config, "config_dir", lambda: tmp_path)
    task = {"id": 9, "payload": {"action": "update"}}
    executor.LAST_TRUST.clear()
    executor.PENDING_ACTION.clear()
    assert executor.HANDLERS["agent_ctl"](None, task)["status"] == "failed"                     # consola sem pacote assinado
    executor.LAST_TRUST.update(bundle_sig="x")
    monkeypatch.setattr(update, "check", lambda cfg, tr, manual=False: {"version": "9.9.9", "sha256": "a"})
    monkeypatch.setattr(update, "apply", lambda c, o: (_ for _ in ()).throw(RuntimeError("autoteste falhou")))
    r = executor.HANDLERS["agent_ctl"](None, task)
    assert r["status"] == "failed" and "autoteste" in r["output"] and not executor.PENDING_ACTION
    monkeypatch.setattr(update, "apply", lambda c, o: o["version"])
    r = executor.HANDLERS["agent_ctl"](None, task)
    assert r["status"] == "succeeded" and "9.9.9" in r["output"] and executor.PENDING_ACTION.get("restart")
    executor.PENDING_ACTION.clear()


def test_auto_update_flag_comes_from_console(tmp_path, monkeypatch):
    from omxpatch_agent import config, telemetry, update
    monkeypatch.setattr(config, "config_dir", lambda: tmp_path)
    telemetry.adopt_server_config({"auto_update": False})
    cfg = {"auto_update": True, "task_keys": []}
    assert update.check(cfg, {"agent_version": "99.0.0", "bundle_sha256": "a" * 64, "bundle_sig": "00" * 64}) is None
    assert telemetry.runtime()["auto_update"] is False


def test_first_cycle_after_upgrade_forces_discovery(tmp_path, monkeypatch):
    from omxpatch_agent import cli, config, telemetry
    from omxpatch_agent.updates import sync
    monkeypatch.setattr(config, "config_dir", lambda: tmp_path)
    monkeypatch.setattr(config, "load", lambda: {"agent_key": "k"})
    calls = []
    monkeypatch.setattr(sync, "run_and_upload", lambda client, force=False, hours=6: calls.append(force) or {"scanned": True, "sent": True})

    class C:
        s = object()
        def poll(self, state=None):
            return {"tasks": [], "trust": {}, "poll_seconds": 300}
        def logs(self, ev):
            return {"ok": True}
    monkeypatch.setattr(cli, "_adopt_servers", lambda *a: None)
    monkeypatch.setattr(cli, "_adopt_trust", lambda c, r: {})
    monkeypatch.setattr(cli.time, "time", cli.time.time)
    monkeypatch.setattr(cli, "send_inventory", lambda c: None)
    cli.cycle(C(), {"last_inventory": 10 ** 12})
    cli.cycle(C(), {"last_inventory": 10 ** 12})
    assert calls == [True, False]                 # 1.º contacto da versão: força; seguintes: segue o intervalo normal


def test_version_change_requests_discovery(app, client, ag):
    from omxpatch.web.agent_api import _hash
    with app.app_context():
        a = db.session.get(Agent, ag.id)
        a.key_hash = _hash("omxa_vkeyvkeyvkey")
        a.version = "1.2.20261108"
        db.session.commit()
    r = client.c.post("/agent/v1/poll", json={"version": "1.27.20261109"}, headers={"Authorization": "Bearer omxa_vkeyvkeyvkey"})
    assert r.status_code == 200
    assert any(t["type"] == "update_scan" for t in r.get_json()["tasks"])
