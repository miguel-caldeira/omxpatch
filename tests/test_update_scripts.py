from pathlib import Path

import pytest

R = Path(__file__).resolve().parents[1] / "packaging" / "installers"


def test_installers_use_upgrade():
    assert "install -q --upgrade --no-index" in (R / "ubuntu/install.sh").read_text()
    assert "install --quiet --upgrade --no-index" in (R / "windows/Install-OMXPatch.ps1").read_text(encoding="utf-8-sig")


def test_update_scripts_exist_and_verify_version():
    u = (R / "ubuntu/update.sh").read_text()
    assert "--force-reinstall" in u and "omxpatch.toml.bak" in u and "systemctl restart" in u
    w = (R / "windows/Update-OMXPatch.ps1").read_bytes()
    assert w.startswith(b"\xef\xbb\xbf")
    assert b"--force-reinstall" in w and (R / "windows/Atualizar.cmd").exists()


def test_scripts_show_installed_version():
    assert "Versão instalada" in (R / "ubuntu/install.sh").read_text() and "versão em execução" in (R / "ubuntu/update.sh").read_text()
    for f in ("windows/Install-OMXPatch.ps1", "windows/Update-OMXPatch.ps1"):
        t = (R / f).read_text(encoding="utf-8-sig")
        assert "healthz" in t and "Versao" in t


def test_console_shows_version(app, alpha_admin):
    from omxpatch import __version__
    r = alpha_admin.get("/dashboard") if alpha_admin.get("/dashboard").status_code == 200 else alpha_admin.get("/")
    assert f"v{__version__}".encode() in r.data
    assert alpha_admin.c.get("/healthz").get_json()["version"] == __version__
    from omxpatch import versioninfo
    assert versioninfo.read(app.config)["current"] == __version__


def test_installers_call_the_ansible_doctor():
    for f in ("ubuntu/install.sh", "ubuntu/update.sh"):
        s = (R / f).read_text()
        assert "ansible-doctor" in s and "wheels-ansible" in s and "collections" in s


def test_ansible_binary_is_found_next_to_the_python_of_the_venv(app, tmp_path, monkeypatch):
    import os
    import sys
    from omxpatch.engine import ansible_runner as ar
    fake = tmp_path / "bin"
    fake.mkdir()
    exe = fake / "ansible-playbook"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setattr(sys, "executable", str(fake / "python"))
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "nada"))
    monkeypatch.setenv("PATH", "/usr/bin-inexistente")
    app.config["ANSIBLE_PLAYBOOK"] = "ansible-playbook"
    with app.app_context():
        assert ar.binary() == str(exe)
        app.config["ANSIBLE_PLAYBOOK"] = "ansible-inexistente"
        assert ar.binary() is None


def test_ansible_doctor_reasons_and_config_edit(app, tmp_path, monkeypatch):
    from omxpatch.engine import ansible_doctor as ad
    monkeypatch.setattr("shutil.which", lambda n: None)
    monkeypatch.setattr("sys.executable", str(tmp_path / "bin" / "python"))
    monkeypatch.setattr("sys.prefix", str(tmp_path))
    with app.app_context():
        app.config["ANSIBLE_ENABLED"] = False
        d = ad.diagnose(fresh=True)
        assert d["reason"] == "disabled" and "enabled = true" in d["fix"]
        app.config["ANSIBLE_ENABLED"] = True
        d = ad.diagnose(fresh=True)
        assert d["reason"] == "missing_binary" and "ansible-doctor --fix" in d["fix"] and d["ok"] is False
        (tmp_path / "bin").mkdir()
        fake = tmp_path / "bin" / "ansible-playbook"
        fake.write_text("#!/bin/sh\necho 'ansible-playbook [core 2.22.0]'\n")
        fake.chmod(0o755)
        d = ad.diagnose(fresh=True)
        assert d["ok"] is True and d["found"] == str(fake) and "2.22" in d["version"]
        monkeypatch.setattr("sys.platform", "win32")
        assert ad.diagnose(fresh=True)["reason"] == "windows"
    cfg = tmp_path / "o.toml"
    cfg.write_text("[server]\nport = 1\n\n[ansible]\nenabled = false\nplaybook = \"ansible-playbook\"\n")
    assert ad.enable_in_config(str(cfg), "/x/ansible-playbook") is True
    t = cfg.read_text()
    assert "enabled = true" in t and "/x/ansible-playbook" in t and "port = 1" in t
    assert ad.enable_in_config(str(cfg), "/x/ansible-playbook") is False             # idempotente


def test_ansible_pages_show_the_reason(app, alpha_admin, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda n: None)
    app.config.update(ANSIBLE_ENABLED=True, ANSIBLE_PLAYBOOK="ansible-inexistente")
    from omxpatch.engine import ansible_doctor as ad
    ad._cache.clear()
    page = alpha_admin.get("/ansible").data.decode()
    assert "não está disponível" in page and "ansible-doctor --fix" in page


def _ansible_exe():
    import shutil
    from pathlib import Path
    return shutil.which("ansible-playbook") or ("/tmp/venv/bin/ansible-playbook" if Path("/tmp/venv/bin/ansible-playbook").exists() else None)


@pytest.mark.skipif(_ansible_exe() is None, reason="ansible-core não instalado")
def test_ansible_works_when_the_service_home_is_not_writable(app, tmp_path, monkeypatch):
    """O utilizador do serviço tem a «home» em /opt/omxpatch (só de leitura): o Ansible recusava-se a arrancar (nem --version) e o diagnóstico
    dava «coleções em falta» por engano. Com ANSIBLE_HOME na pasta de dados passa a funcionar."""
    from omxpatch.engine import ansible_doctor as ad, ansible_runner as ar
    monkeypatch.setenv("HOME", "/proc/inexistente")
    (tmp_path / "pb").mkdir()
    (tmp_path / "pb" / "hello.yml").write_text('- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.debug:\n        msg: \'OMXPATCH_RESULT={"status": "succeeded"}\'\n')
    app.config.update(ANSIBLE_ENABLED=True, ANSIBLE_PLAYBOOK=_ansible_exe(), ANSIBLE_DIR=str(tmp_path / "pb"), DATA_DIR=str(tmp_path / "dados"))
    with app.app_context():
        d = ad.diagnose(fresh=True)
        assert d["version"].startswith("ansible-playbook") and d["reason"] in ("ok", "missing_collections"), d
        r = ar.run_playbook("hello.yml", {"all": {"hosts": {"h": {"ansible_connection": "local"}}}}, {}, timeout_minutes=2)
        assert r["rc"] == 0 and r["result"] == {"status": "succeeded"}, r["output"][-500:]
        assert (tmp_path / "dados" / "ansible" / "tmp").is_dir()


def test_collection_listing_failure_is_unknown_not_missing(app, tmp_path, monkeypatch):
    from omxpatch.engine import ansible_doctor as ad
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "ansible-playbook").write_text("#!/bin/sh\necho 'ansible-playbook [core 2.22.0]'\n")
    (fake / "ansible-galaxy").write_text("#!/bin/sh\necho 'ERROR: Unable to create local directories' >&2\n")
    for f in fake.iterdir():
        f.chmod(0o755)
    app.config.update(ANSIBLE_ENABLED=True, ANSIBLE_PLAYBOOK=str(fake / "ansible-playbook"), DATA_DIR=str(tmp_path / "d"))
    with app.app_context():
        d = ad.diagnose(fresh=True)
        assert d["reason"] == "ok" and d["missing_collections"] == []                # a falha da listagem não vira «faltam coleções»
        (fake / "ansible-playbook").write_text("#!/bin/sh\necho 'ERROR: Unable to create local directories' >&2\nexit 1\n")
        d = ad.diagnose(fresh=True)
        assert d["reason"] == "broken" and "Unable to create" in d["version_error"] and d["ok"] is False
