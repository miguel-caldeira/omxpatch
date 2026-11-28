"""Acesso sem agente ponta a ponta: SSH real (Linux) com o Ansible e o teste de ligação; WMI (Windows simulado)."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from omxpatch.connectors import store
from omxpatch.engine import ansible_engine as eng, ansible_runner as ar, connectivity
from omxpatch.extensions import db
from omxpatch.models import AnsibleCredential, Asset
from tests.fake_impacket import FakeWindows, install
from tests.test_transports import needs_sshd, sshd  # noqa: F401  (fixture)

EXE = shutil.which("ansible-playbook") or ("/tmp/venv/bin/ansible-playbook" if Path("/tmp/venv/bin/ansible-playbook").exists() else None)


def _asset(tenant, name, cred=None, **kw):
    a = Asset(tenant_id=tenant.id, uid=name, name=name, connection="ansible", managed=True, credential_id=cred.id if cred else None, **kw)
    db.session.add(a)
    db.session.flush()
    return a


def _cred(tenant, kind="password", user="u", **secret):
    c = AnsibleCredential(tenant_id=tenant.id, name=f"c-{user}-{kind}-{len(secret)}", kind=kind, username=user, secret=store.encrypt_json(secret))
    db.session.add(c)
    db.session.flush()
    return c


@needs_sshd
def test_connection_test_for_linux_over_ssh(app, tenant, sshd, tmp_path):
    (tmp_path / "d").mkdir()
    app.config["DATA_DIR"] = str(tmp_path / "d")
    with app.app_context():
        ok = _asset(tenant, "lin-ok", _cred(tenant, user=sshd["user"], password="Senha-Teste-1"), os_family="linux", ip="127.0.0.1", ansible_port=sshd["port"])
        res = connectivity.check(ok)
        names = {s["name"]: s for s in res["steps"]}
        assert res["transport"] == "SSH" and names["Resolução do nome"]["ok"] and names[f"Porta {sshd['port']} — SSH"]["ok"]
        assert names["Autenticação SSH"]["ok"] and names["Executar comando"]["ok"] and sshd["user"] in names["Autenticação SSH"]["detail"]
        assert "Linux" in names["Executar comando"]["detail"]
        bad = _asset(tenant, "lin-bad", _cred(tenant, user=sshd["user"], password="errada"), os_family="linux", ip="127.0.0.1", ansible_port=sshd["port"])
        names = {s["name"]: s for s in connectivity.check(bad)["steps"]}
        assert not names["Autenticação SSH"]["ok"] and "recusados" in names["Autenticação SSH"]["detail"] and names["Autenticação SSH"]["hint"]
        closed = _asset(tenant, "lin-closed", _cred(tenant, user="x", password="y"), os_family="linux", ip="127.0.0.1", ansible_port=1)
        res = connectivity.check(closed)
        assert not res["ok"] and res["steps"][-1]["name"].startswith("Porta 1") and "recusada" in res["steps"][-1]["detail"]
        nocred = _asset(tenant, "lin-nocred", None, os_family="linux", ip="127.0.0.1")
        res = connectivity.check(nocred)
        assert not res["ok"] and "utilizador" in res["steps"][0]["hint"]


def test_connection_test_for_windows_over_wmi(app, tenant, monkeypatch):
    install(monkeypatch, FakeWindows(user="Administrator", password="pw"))
    monkeypatch.setattr(connectivity, "_tcp", lambda host, port, timeout=4.0: (True, "aberta (1 ms)"))
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 0))])
    with app.app_context():
        a = _asset(tenant, "win-ok", _cred(tenant, user="Administrator", password="pw"), os_family="windows", ip="10.0.0.5")
        res = connectivity.check(a)
        names = {s["name"]: s for s in res["steps"]}
        assert res["ok"] and res["transport"] == "WMI/DCOM + SMB" and names["Porta 135 — RPC/DCOM (WMI)"]["ok"] and names["Porta 445 — SMB (partilha administrativa)"]["ok"]
        assert "Windows Server 2022" in names["Consulta WMI (Win32_OperatingSystem)"]["detail"]
        bad = _asset(tenant, "win-bad", _cred(tenant, user="Administrator", password="errada", ), os_family="windows", ip="10.0.0.6")
        res = connectivity.check(bad)
        assert not res["ok"] and "LocalAccountTokenFilterPolicy" in res["steps"][-1]["hint"] and "recusados" in res["steps"][-1]["detail"]


@needs_sshd
@pytest.mark.skipif(EXE is None, reason="ansible-core não instalado")
def test_ansible_over_ssh_with_the_inventory_the_console_generates(app, tenant, sshd, tmp_path):
    """O inventário gerado pela consola (credencial cifrada, known_hosts gravável, aceitar chave na 1.ª ligação, sshpass) funciona com o Ansible real."""
    (tmp_path / "dados").mkdir()
    app.config.update(ANSIBLE_ENABLED=True, ANSIBLE_PLAYBOOK=EXE, ANSIBLE_DIR=str(tmp_path / "pb"), DATA_DIR=str(tmp_path / "dados"))
    pb = tmp_path / "pb"
    pb.mkdir()
    dest = Path(f"/home/{sshd['user']}/prova-omx.txt")
    (pb / "ssh.yml").write_text("- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.command: echo olá-ssh\n      register: r\n"
                                f"    - ansible.builtin.copy: {{content: 'via-ssh', dest: {dest}}}\n    - ansible.builtin.slurp: {{src: {dest}}}\n      register: s\n"
                                "    - ansible.builtin.debug:\n        msg: 'OMXPATCH_RESULT={\"status\": \"succeeded\", \"cmd\": \"{{ r.stdout }}\", \"file\": \"{{ s.content | b64decode }}\"}'\n")
    for label, cred in (("senha", _cred(tenant, user=sshd["user"], password="Senha-Teste-1")), ("chave", _cred(tenant, "ssh_key", user=sshd["user"], ssh_key=sshd["key"]))):
        a = _asset(tenant, f"lin-{label}", cred, os_family="linux", ip="127.0.0.1", ansible_port=sshd["port"])
        db.session.commit()
        inv = eng.build_inventory([a])
        inv["all"]["hosts"][f"asset{a.id}"]["ansible_python_interpreter"] = "/usr/bin/python3"
        r = ar.run_playbook("ssh.yml", inv, {}, limit=f"asset{a.id}", timeout_minutes=3)
        assert r["rc"] == 0, (label, r["output"][-2500:])
        assert r["result"] == {"status": "succeeded", "cmd": "olá-ssh", "file": "via-ssh"}, label
        dest.unlink(missing_ok=True)
    assert (tmp_path / "dados" / "ansible" / "known_hosts").read_text().strip()                  # a chave do equipamento ficou registada (1.ª ligação)


def test_connection_test_page_and_permissions(app, tenant, alpha_admin, alpha_user, monkeypatch):
    install(monkeypatch, FakeWindows(user="Administrator", password="pw"))
    monkeypatch.setattr(connectivity, "_tcp", lambda host, port, timeout=4.0: (True, "aberta (1 ms)"))
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 0))])
    with app.app_context():
        a = _asset(tenant, "win-ui", _cred(tenant, user="Administrator", password="pw"), os_family="windows", ip="10.0.0.5")
        db.session.commit()
        aid = a.id
    page = alpha_admin.post(f"/ansible/test/{aid}").data.decode()
    assert "Teste de ligação" in page and "WMI/DCOM + SMB" in page and "Ligação OK" in page
    assert alpha_user.post(f"/ansible/test/{aid}").status_code == 200
    from tests.conftest import login_as
    assert login_as(app, "auditor@alpha.example").post(f"/ansible/test/{aid}").status_code == 403
    assert "Testar ligação" in alpha_admin.get("/ansible").data.decode()
