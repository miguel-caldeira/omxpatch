"""I8 — instalar o agente através de SSH/WMI, sem agente prévio."""
from __future__ import annotations

import re

import pytest

from omxpatch.engine import agent_deploy, ansible_engine as eng
from omxpatch.extensions import db
from omxpatch.models import Agent, EnrollmentToken, Task
from omxpatch.transports import Result
from tests.test_ansible_engine import mk


class FakeT:
    """Transporte que regista o que recebe; ao «correr» o script faz o que o agente real faria: usar o token de registo."""
    instances: list = []

    def __init__(self, kind, root=True, rc=0, register=True):
        self.kind, self.root, self.rc, self.register = kind, root, rc, register
        self.files, self.cmds, self.closed = {}, [], False
        FakeT.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.closed = True

    def put(self, local, remote):
        self.files[remote] = open(local, "rb").read()

    def run(self, cmd, stdin=None, timeout=300):
        self.cmds.append(cmd)
        if cmd == "id -u":
            return Result(0, b"0\n" if self.root else b"1000\n")
        if cmd == "sudo -n true":
            return Result(1 if not self.root else 0, b"", b"password required")
        if ("omx-" in cmd or ".omx-" in cmd) and "del " not in cmd and "rm " not in cmd:
            if self.rc == 0 and self.register:
                tok = EnrollmentToken.query.order_by(EnrollmentToken.id.desc()).first()
                tok.uses = 1
                db.session.commit()
            return Result(self.rc, b"instalado omxe_SEGREDO123\n", b"")
        return Result(0)


@pytest.fixture()
def fake(monkeypatch, app):
    FakeT.instances.clear()
    app.config.update(AGENT_BASE_URL="https://omxpatchcli.oramix.local:4444", AGENT_SERVER_IP="", AGENT_INSTALL_WAIT=1, AGENT_EXEC_ENABLED=True)

    def maker(**kw):
        monkeypatch.setattr(agent_deploy, "_transport", lambda kind, v: FakeT(kind, **kw))
    monkeypatch.setattr("omxpatch.web.admin.agent_pin", lambda: "ab" * 32)
    return maker


def test_linux_install_over_ssh_uses_one_shot_token_and_cleans_up(app, tenant, fake):
    with app.app_context():
        fake(root=False)
        a = mk(tenant, "lin", os_family="linux", ip="127.0.0.1")
        r = agent_deploy.install(tenant, a, wait=1)
        t = FakeT.instances[-1]
        assert r["status"] == "failed" and "sudo" in r["output"]                                   # sem root nem sudo sem palavra-passe: recusa clara
        fake(root=True)
        r = agent_deploy.install(tenant, a, wait=1)
        t = FakeT.instances[-1]
        assert r["status"] == "succeeded" and "omxe_SEGREDO123" not in r["output"] and t.closed
        remote = next(iter(t.files))
        assert re.match(r"/tmp/\.omx-\w+\.sh$", remote) and b"omxe_" in t.files[remote] and f"rm -f {remote}" in t.cmds[-1]
        tok = EnrollmentToken.query.order_by(EnrollmentToken.id.desc()).first()
        assert tok.max_uses == 1 and tok.uses == 1 and tok.name.startswith("agentless-")


def test_windows_install_over_wmi_runs_powershell_file(app, tenant, fake):
    with app.app_context():
        fake()
        a = mk(tenant, "win", os_family="windows", ip="127.0.0.1")
        r = agent_deploy.install(tenant, a, wait=1)
        t = FakeT.instances[-1]
        assert r["status"] == "succeeded" and t.kind == "wmi"
        remote = next(iter(t.files))
        assert remote.startswith("C:\\Windows\\Temp\\omx-") and remote.endswith(".ps1") and t.files[remote].startswith(b"\xef\xbb\xbf")
        assert any(c.startswith("powershell -NoProfile -ExecutionPolicy Bypass -File") for c in t.cmds)


def test_failure_modes_are_reported(app, tenant, fake):
    with app.app_context():
        a = mk(tenant, "lin2", os_family="linux", ip="127.0.0.1")
        fake(rc=3)
        assert agent_deploy.install(tenant, a, wait=1)["status"] == "failed"
        fake(register=False)
        r = agent_deploy.install(tenant, a, wait=1)
        assert r["status"] == "failed" and "não se registou" in r["output"]


def test_job_flow_via_engine_without_assessment(app, tenant, fake):
    with app.app_context():
        fake()
        a = mk(tenant, "lin3", os_family="linux", ip="127.0.0.1")
        assert eng.eligible(a, "agent_install")
        tasks = eng.create_job(tenant, None, "agent_install", [a.id], "assess", {})            # sem avaliação nem confirmação
        t = tasks[0]
        assert t.type == "agent_inst" and t.payload_data["mode"] == "apply" and t.status == "queued"
        rep = eng.run_task(t)
        assert rep["status"] == "succeeded"
        ag = Agent(tenant_id=tenant.id, asset_id=a.id, key_hash="h" * 64, key_prefix="h", revoked=False)
        db.session.add(ag)
        db.session.flush()
        assert not eng.eligible(a, "agent_install")                                               # já tem agente
        t2 = Task(tenant_id=tenant.id, type="agent_inst", asset_id=a.id, mode="ansible")
        db.session.add(t2)
        db.session.flush()
        assert eng.run_task(t2)["output"].startswith("O ativo já tem")
