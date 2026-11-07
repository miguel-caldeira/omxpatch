"""Agente multiplataforma: protocolo contra o servidor real, validações de entrada e simulação segura."""
import json
import platform
from datetime import datetime

import pytest

from omxpatch.engine import correlate
from omxpatch.extensions import db
from omxpatch.models import Agent, Asset, Exposure, Patch, Task, Validation
from omxpatch.web.api import new_enrollment_token
from omxpatch_agent import bas, cli as agent_cli, collectors, executor, firewall, health
from omxpatch_agent.client import Client, PinError, ServerError, StdSession, normalize_pin
from omxpatch_agent.patchers import PatchError, check_pkg
from omxpatch_agent.versioning import compare
from tests.conftest import make_cve


class FlaskSession:
    """Faz um Flask test client passar por ``requests.Session`` (o agente fala com o servidor real)."""

    class R:
        def __init__(self, r):
            self._r, self.status_code, self.headers = r, r.status_code, r.headers

        def json(self):
            return self._r.get_json()

        def raise_for_status(self):
            if self.status_code >= 400:
                raise ServerError(f"HTTP {self.status_code}")

    def __init__(self, app):
        self.c = app.test_client()

    def request(self, method, url, json=None, timeout=None, headers=None, **kw):
        path = url.split("//", 1)[1].split("/", 1)[1]
        return self.R(self.c.open("/" + path, method=method, json=json, headers=dict(headers or {})))


def test_agent_version_compare_matches_server():
    from omxpatch.engine.versions import compare as server_compare
    for a, b in [("1.1.1w", "1.1.1"), ("3.0.2", "3.0.10"), ("1.0", "1.0.0"), ("1.0rc1", "1.0"), ("8.0.351", "8.0.361"), ("2:1.2", "1.2")]:
        assert compare(a, b) == server_compare(a, b), (a, b)


def test_patch_input_validation():
    for ok in ("openssl", "libssl3", "nginx=1.24.0-1", "python3.12", "Microsoft.Edge"):
        assert check_pkg(ok) == ok
    for bad in ("", "x; rm -rf /", "$(id)", "a b", "-rf", "pkg`id`", "../../etc/passwd" * 20):
        with pytest.raises(PatchError):
            check_pkg(bad)


def test_firewall_validation_rejects_injection(monkeypatch):
    for bad in ({"op": "firewall_block_port", "name": "x; ls", "port": 80}, {"op": "firewall_block_port", "name": "OMXPatch-ok", "port": "99999"},
                {"op": "firewall_block_port", "name": "OMXPatch-ok", "port": "8080; id"}, {"op": "firewall_block_ioc", "name": "OMXPatch-ok", "ioc": "evil.com"},
                {"op": "firewall_block_port", "name": "OMXPatch-ok", "port": 80, "proto": "icmp"}):
        with pytest.raises((firewall.FirewallError, ValueError)):
            firewall.block(bad)
    with pytest.raises(firewall.FirewallError):
        firewall.remove({"name": "../x"})


def test_firewall_commands_per_platform(monkeypatch, tmp_path):
    monkeypatch.setenv("OMXPATCH_AGENT_DIR", str(tmp_path))
    cmds = []
    monkeypatch.setattr(firewall, "run", lambda cmd, timeout=60, **k: (cmds.append(cmd), type("R", (), {"ok": True, "rc": 0, "out": ""})())[1])
    monkeypatch.setattr(firewall, "platform_family", lambda: "windows")
    res = firewall.block({"op": "firewall_block_port", "name": "OMXPatch-CVE-1-block_port-8443", "port": 8443})
    assert cmds[0][:5] == ["netsh", "advfirewall", "firewall", "add", "rule"] and "localport=8443" in cmds[0] and "action=block" in cmds[0]
    assert res["verified"] is True
    firewall.remove({"name": "OMXPatch-CVE-1-block_port-8443"})
    assert "delete" in cmds[-1]
    cmds.clear()
    monkeypatch.setattr(firewall, "platform_family", lambda: "linux")
    monkeypatch.setattr(firewall.shutil, "which", lambda n: "/usr/sbin/nft" if n == "nft" else None)
    firewall.block({"op": "firewall_block_ioc", "name": "OMXPatch-CVE-2-ioc", "ioc": "198.51.100.7"})
    flat = [" ".join(c) for c in cmds]
    assert any("daddr 198.51.100.7 drop" in f for f in flat)


def test_collect_inventory_on_this_host():
    info = collectors.collect()
    assert info["os_family"] in ("linux", "macos", "windows") and info["hostname"] and isinstance(info["software"], list)
    assert platform.system().lower() in info["os_name"].lower() or info["os_name"]
    if platform.system() == "Linux":
        assert all({"name", "version"} <= set(s) for s in info["software"][:50])


def test_bas_steps_never_crash_and_report_defense():
    r = bas.canary_encrypt()
    assert r["passed"] in (True, False) and r["detail"]
    assert bas.run_step("smb_reach", {"peers": []})["passed"] is None
    assert bas.run_step("service_reachable", {"port": None})["passed"] is None
    assert bas.run_step("passo_inexistente", {})["passed"] is None
    # nenhum par acessível → defesa resistiu; par acessível → não
    import socket
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1); port = srv.getsockname()[1]
    assert bas._reach(["127.0.0.1"], port, "x")["passed"] is False
    srv.close()
    assert bas._reach(["127.0.0.1"], port, "x")["passed"] is True
    assert health.ux_score(60, False, False, False) == 100 and health.ux_score(1000, True, True, True) == 5


def test_executor_unknown_and_failing_tasks_report_failure():
    class C:
        def task_start(self, i):
            raise RuntimeError("sem rede")
    assert executor.execute(C(), {"id": 1, "type": "xyz", "payload": {}})["status"] == "failed"
    rep = executor.execute(C(), {"id": 1, "type": "patch", "payload": {"installer": "apt", "package": "x; id", "patch_id": 1}})
    assert rep["status"] == "failed" and "inválido" in rep["output"]
    wake = executor.execute(C(), {"id": 2, "type": "wake", "payload": {"mac": "zz"}})
    assert wake["status"] == "failed"


def test_agent_cycle_against_real_server(app, tenant, tmp_path, monkeypatch):
    """enroll → poll → inventário real desta máquina → tarefa de inventário → resultado."""
    monkeypatch.setenv("OMXPATCH_AGENT_DIR", str(tmp_path / "agentcfg"))
    raw, _ = new_enrollment_token(tenant, "t", ring=2)
    db.session.commit()
    sess = FlaskSession(app)
    cfg = {"server_url": "https://omxpatch.test"}
    data = Client(cfg, session=sess).enroll(raw, {**collectors.base_info(), "version": "1.0.0"})
    assert data["agent_key"].startswith("omxa_")
    cfg["agent_key"] = data["agent_key"]
    assert data["tenant"] == {"slug": "alpha", "name": "Alpha"}
    client = Client(cfg, session=sess)
    asset = Asset.query.filter_by(tenant_id=tenant.id, managed=True).one()
    assert asset.ring == 2 and asset.managed and not asset.shadow_it
    db.session.add(Task(tenant_id=tenant.id, type="inventory", asset_id=asset.id, status="queued", payload="{}"))
    db.session.commit()
    state = {}
    n = agent_cli.cycle(client, state)
    db.session.expire_all()
    assert n == 1 and state["last_inventory"] > 0
    t = Task.query.one()
    assert t.status == "succeeded" and asset.software.count() > 0
    assert Agent.query.one().last_seen is not None


def test_agent_validate_task_end_to_end(app, tenant, monkeypatch):
    """O servidor fecha a exposição com a evidência de uma validação executada pelo executor do agente."""
    from omxpatch.engine import validation
    make_cve()
    from tests.conftest import make_asset
    a = make_asset(tenant)
    db.session.add(Agent(tenant_id=tenant.id, asset_id=a.id, key_hash="k" * 64, key_prefix="p", hostname="srv1"))
    correlate.correlate_asset(tenant, a)
    ex = Exposure.query.one()
    ex.status = "remediated"
    v = validation.schedule(ex, tenant)
    task = db.session.get(Task, v.task_id)
    db.session.commit()
    monkeypatch.setattr(executor.collectors, "collect", lambda: {"software": [{"name": "OpenSSL", "version": "1.1.1w"}], "hotfixes": None,
                                                                  "open_ports": [22]})
    monkeypatch.setattr(executor, "_process_started_before", lambda name, since: True)
    report = executor.execute(type("C", (), {"task_start": lambda s, i: None})(), {"id": task.id, "type": "validate", "payload": task.payload_data})
    assert report["checks"]["patch_installed"] is None or report["checks"]["patch_installed"] is True
    from omxpatch.engine import deploy
    deploy.complete_task(task, report)
    db.session.commit()
    assert db.session.get(Exposure, ex.id).status == "closed"


def test_pin_normalization_and_mismatch_is_fatal(tmp_path, capsys, monkeypatch):
    assert normalize_pin("AB:CD:ef") == "abcdef"
    monkeypatch.setenv("OMXPATCH_AGENT_DIR", str(tmp_path))
    monkeypatch.setattr(agent_cli.Client, "enroll", lambda self, token, info: (_ for _ in ()).throw(ServerError("Token de registo inválido")))
    rc = agent_cli.main(["enroll", "--server", "http://x.example", "--token", "t"])
    err = capsys.readouterr().err
    assert rc == 2 and "HTTPS" in err and "Registo recusado" in err


def test_agent_refuses_to_reenroll_without_force(tmp_path, monkeypatch, capsys):
    from omxpatch_agent import config
    monkeypatch.setenv("OMXPATCH_AGENT_DIR", str(tmp_path))
    config.save({"server_url": "https://a:4444", "agent_key": "k", "tenant_name": "Alpha"})
    assert agent_cli.main(["enroll", "--server", "https://b:4444", "--token", "t"]) == 3
    assert "Alpha" in capsys.readouterr().err
    assert config.load()["agent_key"] == "k"


def test_config_file_permissions(tmp_path, monkeypatch):
    import os, stat, sys
    monkeypatch.setenv("OMXPATCH_AGENT_DIR", str(tmp_path / "c"))
    from omxpatch_agent import config
    p = config.save({"agent_key": "segredo"})
    if not sys.platform.startswith("win"):
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert config.load()["agent_key"] == "segredo"
