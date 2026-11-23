"""O agente como PROCURAÇÃO (proxy) dos comandos do Ansible/PowerShell: ponta a ponta com o Ansible real, o servidor real e o agente real."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import sys
import threading
import time
from pathlib import Path

import pytest

from omxpatch.engine import ansible_engine as eng, ansible_runner as ar
from omxpatch.extensions import db
from omxpatch.models import Agent, Asset, Task
from omxpatch.web.api import new_enrollment_token
from omxpatch_agent import cli as agent_cli, collectors, config as agent_config, executor, telemetry
from omxpatch_agent.client import Client
from tests.test_agent import FlaskSession

ANS = Path(__file__).resolve().parents[1] / "ansible"
EXE = shutil.which("ansible-playbook") or ("/tmp/venv/bin/ansible-playbook" if Path("/tmp/venv/bin/ansible-playbook").exists() else None)


class DlSession(FlaskSession):
    """FlaskSession com download (o agente transfere os ficheiros da consola por aqui)."""

    def download(self, url, dest, headers=None, bandwidth_kbps=0, timeout=0):
        path = "/" + url.split("//", 1)[1].split("/", 1)[1]
        r = self.c.get(path, headers=dict(headers or {}))
        if r.status_code != 200:
            return r.status_code, ""
        Path(dest).write_bytes(r.data)
        return 200, hashlib.sha256(r.data).hexdigest()


def _enroll(app, tenant, allow_exec: bool):
    raw, _ = new_enrollment_token(tenant, "t", ring=2)
    db.session.commit()
    sess = DlSession(app)
    cfg = {"server_url": "https://omxpatch.test"}
    data = Client(cfg, session=sess).enroll(raw, {**collectors.base_info(), "version": agent_cli.__version__})
    cfg.update(agent_key=data["agent_key"], agent_id=data["agent_id"], allow_exec=allow_exec)
    agent_config.save(cfg)
    return Client(cfg, session=sess), cfg


def _run_agent_in_background(client, stop):
    state = {"started": time.time(), "last_inventory": 10 ** 12}

    def loop():
        while not stop.is_set():
            try:
                agent_cli.cycle(client, state)
            except Exception:  # noqa: BLE001
                pass
            time.sleep(0.2)
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t


@pytest.fixture()
def quiet_agent(monkeypatch):
    from omxpatch_agent.updates import sync
    monkeypatch.setattr(sync, "run_and_upload", lambda *a, **k: {"scanned": True, "sent": True})
    monkeypatch.setattr(agent_cli, "send_inventory", lambda c: None)


def test_exec_is_refused_unless_both_sides_allow_it(app, tenant, quiet_agent):
    client, cfg = _enroll(app, tenant, allow_exec=False)
    task = {"id": 1, "payload": {"op": "run", "cmd": "echo x"}}
    telemetry.adopt_server_config({"exec_enabled": True})
    r = executor.HANDLERS["exec"](client, task)
    assert r["status"] == "failed" and "localmente" in r["output"] or "equipamento" in r["output"]         # o administrador local não permitiu
    cfg["allow_exec"] = True
    agent_config.save(cfg)
    telemetry.adopt_server_config({"exec_enabled": False})
    r = executor.HANDLERS["exec"](client, task)
    assert r["status"] == "failed" and "consola" in r["output"]                                         # a consola não ativou
    telemetry.adopt_server_config({"exec_enabled": True})
    r = executor.HANDLERS["exec"](client, {"id": 2, "payload": {"op": "run", "cmd": "echo olá; exit 3"}})
    assert r["status"] == "succeeded" and r["rc"] == 3 and base64.b64decode(r["stdout_b64"]).decode().strip() == "olá"
    r = executor.HANDLERS["exec"](client, {"id": 3, "payload": {"op": "run", "cmd": "sleep 5", "timeout": 1}})
    assert r["rc"] == 124
    evs, _ = telemetry.pending(50)
    assert any(e["msg"].startswith("exec:") and "cmd_sha256" in json.dumps(e) for e in evs)
    assert "olá" not in json.dumps(evs)                                                                    # a auditoria guarda o resumo, nunca o conteúdo


def test_agent_config_flag_and_cli(tmp_path, monkeypatch, capsys):
    agent_config.save({"agent_key": "k", "server_url": "https://x"})
    assert agent_cli.main(["config", "allow-exec", "on"]) == 0
    assert agent_config.load()["allow_exec"] is True and "on" in capsys.readouterr().out
    agent_cli.main(["config", "allow-exec", "off"])
    assert agent_config.load()["allow_exec"] is False


@pytest.mark.skipif(EXE is None, reason="ansible-core não instalado")
def test_ansible_commands_and_files_go_through_the_agent(app, tenant, tmp_path, monkeypatch, quiet_agent):
    app.config.update(AGENT_EXEC_ENABLED=True, RATE_AGENT_PER_MIN=0, ANSIBLE_ENABLED=True, ANSIBLE_PLAYBOOK=EXE, ANSIBLE_DIR=str(tmp_path / "pb"), AGENT_EXEC_TIMEOUT_SECONDS=60)
    pb = tmp_path / "pb"
    shutil.copytree(ANS / "connection_plugins", pb / "connection_plugins")
    dest = tmp_path / "alvo" / "ficheiro.txt"
    dest.parent.mkdir()
    (pb / "proxy.yml").write_text(
        "- hosts: all\n  gather_facts: false\n  tasks:\n"
        "    - ansible.builtin.command: echo olá-procuração\n      register: r\n"
        "    - ansible.builtin.copy: {content: 'conteúdo-copiado', dest: \"{{ alvo }}\"}\n"
        "    - ansible.builtin.slurp: {src: \"{{ alvo }}\"}\n      register: s\n"
        "    - ansible.builtin.debug:\n        msg: 'OMXPATCH_RESULT={\"status\": \"succeeded\", \"cmd\": \"{{ r.stdout }}\", \"file\": \"{{ s.content | b64decode }}\"}'\n")
    client, cfg = _enroll(app, tenant, allow_exec=True)
    asset = Asset.query.filter_by(tenant_id=tenant.id, managed=True).one()
    asset.ansible_transport, asset.os_family = "agent", "linux"
    db.session.commit()
    for k, v in {"OMXPATCH_DATABASE_URL": app.config["SQLALCHEMY_DATABASE_URI"], "OMXPATCH_DATA_DIR": app.config["DATA_DIR"], "OMXPATCH_AGENT_EXEC_ENABLED": "1",
                 "OMXPATCH_RATE_AGENT_PER_MIN": "0", "PYTHONPATH": str(Path(__file__).resolve().parents[1])}.items():
        monkeypatch.setenv(k, v)
    stop = threading.Event()
    t = _run_agent_in_background(client, stop)
    try:
        inv = eng.build_inventory([asset])
        h = inv["all"]["hosts"][f"asset{asset.id}"]
        assert h["ansible_connection"] == "omx_agent" and h["ansible_shell_type"] == "sh" and h["ansible_become"] is False and "ansible_password" not in h
        h["ansible_python_interpreter"] = sys.executable
        r = ar.run_playbook("proxy.yml", inv, {"alvo": str(dest)}, limit=f"asset{asset.id}", timeout_minutes=4)
    finally:
        stop.set()
        t.join(timeout=10)
    assert r["rc"] == 0, r["output"][-3000:]
    assert r["result"] == {"status": "succeeded", "cmd": "olá-procuração", "file": "conteúdo-copiado"}
    assert dest.read_text() == "conteúdo-copiado"                                                          # o ficheiro chegou ao alvo pelo agente
    db.session.expire_all()
    tasks = Task.query.filter_by(type="exec", asset_id=asset.id).all()
    assert len(tasks) >= 4 and all(x.status == "succeeded" and "limpo" in x.payload and x.result == "{}" for x in tasks)   # nada de comandos/saídas na base de dados
    blobs = Path(app.config["DATA_DIR"]) / "ansible-blobs"
    assert not blobs.exists() or not list(blobs.iterdir())


def test_fallback_to_agent_when_direct_connection_is_not_possible(app, tenant, tmp_path, quiet_agent):
    app.config.update(AGENT_EXEC_ENABLED=True, AGENT_EXEC_FALLBACK=True)
    client, cfg = _enroll(app, tenant, allow_exec=True)
    asset = Asset.query.filter_by(tenant_id=tenant.id, managed=True).one()
    asset.connection, asset.os_family = "ansible", "windows"                       # Windows sem credenciais: a ligação direta nem é tentável
    ag = Agent.query.filter_by(asset_id=asset.id).one()
    from omxpatch.models import utcnow
    ag.last_seen = utcnow()
    ag.status_json = json.dumps({"exec_allowed": True})
    db.session.commit()
    with pytest.raises(eng.EngineError):
        app.config["AGENT_EXEC_FALLBACK"] = False
        eng.create_job(tenant, None, "os", [asset.id], "assess", {})               # sem fallback: o utilizador vê o que falta
    app.config["AGENT_EXEC_FALLBACK"] = True
    (t,) = eng.create_job(tenant, None, "os", [asset.id], "assess", {})
    assert t.payload_data["transport"] == "agent"                                    # com fallback e agente permitido: segue pela procuração
    inv = eng.build_inventory([asset], {asset.id: "agent"})["all"]["hosts"][f"asset{asset.id}"]
    assert inv["ansible_connection"] == "omx_agent" and inv["ansible_shell_type"] == "powershell" and "ansible_winrm_transport" not in inv
    ag.status_json = json.dumps({"exec_allowed": False})
    db.session.commit()
    ok, why = eng.agent_usable(asset)
    assert not ok and "allow-exec" in why
    app.config["AGENT_EXEC_ENABLED"] = False
    assert "desativada na consola" in eng.agent_usable(asset)[1]


def test_blob_endpoint_only_serves_files_of_the_agents_own_active_task(app, tenant, tmp_path, quiet_agent):
    client, cfg = _enroll(app, tenant, allow_exec=True)
    asset = Asset.query.filter_by(tenant_id=tenant.id, managed=True).one()
    blobs = Path(app.config["DATA_DIR"]) / "ansible-blobs"
    blobs.mkdir(parents=True, exist_ok=True)
    data = b"segredo"
    sha = hashlib.sha256(data).hexdigest()
    (blobs / sha).write_bytes(data)
    h = {"Authorization": f"Bearer {cfg['agent_key']}"}
    c = app.test_client()
    assert c.get(f"/agent/v1/blob/{sha}", headers=h).status_code == 404                 # sem tarefa a referenciá-lo
    db.session.add(Task(tenant_id=tenant.id, type="exec", asset_id=asset.id, mode="agent", status="queued", payload=json.dumps({"op": "put", "sha256": sha, "dest": "/x"})))
    db.session.commit()
    assert c.get(f"/agent/v1/blob/{sha}", headers=h).data == data
    assert c.get("/agent/v1/blob/../../etc/passwd", headers=h).status_code == 404
    assert c.get(f"/agent/v1/blob/{'0' * 64}", headers=h).status_code == 404


def test_console_runs_a_command_through_the_agent(app, tenant, alpha_admin, alpha_user, quiet_agent):
    app.config.update(AGENT_EXEC_ENABLED=True, RATE_AGENT_PER_MIN=0)
    client, cfg = _enroll(app, tenant, allow_exec=True)
    ag = Agent.query.filter_by(tenant_id=tenant.id).one()
    from omxpatch.models import utcnow
    ag.last_seen, ag.os_family = utcnow(), "linux"
    ag.status_json = json.dumps({"exec_allowed": True})
    db.session.commit()
    assert alpha_user.post(f"/agents/{ag.id}/exec", {"script": "id"}).status_code == 403
    assert alpha_admin.post(f"/agents/{ag.id}/exec", {"script": "echo proxy-ok; echo erro >&2; exit 2"}).status_code == 302
    t = Task.query.filter_by(type="exec").one()
    assert t.payload_data["adhoc"] and t.payload_data["by"] == "admin@alpha.example"
    state = {"started": time.time(), "last_inventory": 10 ** 12}
    agent_cli.cycle(client, state)                                       # o agente recolhe, executa e devolve
    db.session.expire_all()
    page = alpha_admin.get(f"/agents/{ag.id}").data.decode()
    assert "proxy-ok" in page and "rc 2" in page and "erro" in page
    # sem permissão local: a consola recusa antes de criar a tarefa
    ag.status_json = json.dumps({"exec_allowed": False})
    db.session.commit()
    alpha_admin.post(f"/agents/{ag.id}/exec", {"script": "id"})
    assert Task.query.filter_by(type="exec").count() == 1
    from omxpatch.models import AuditLog
    assert any(a.action == "agent_exec" for a in AuditLog.query.all())
