from pathlib import Path

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


def _toml_editor():
    import re
    t = (R / "ubuntu/update.sh").read_text()
    return re.search(r"<<'PY'\n(.*?)\nPY\n", t, re.S).group(1)


def test_update_enables_ansible_in_config(tmp_path):
    import subprocess
    import sys
    code = _toml_editor()
    for before, expect in (("[server]\nport = 4434\n\n[ansible]\nenabled = false\nplaybook = \"/x/ap\"\n", None),
                           ("[server]\nport = 4434\n", "[ansible]"), ("[ansible]\nenabled = false\n", "playbook")):
        f = tmp_path / "o.toml"
        f.write_text(before)
        subprocess.run([sys.executable, "-c", code, str(f), "/opt/omxpatch/venv/bin/ansible-playbook"], check=True, capture_output=True)
        out = f.read_text()
        assert "enabled = true" in out and "enabled = false" not in out and "port = 4434" in out or "enabled = true" in out
        assert expect is None or expect in out
        assert "[server]" not in out or out.index("[server]") < out.index("[ansible]")
    import tomllib
    tomllib.loads(f.read_text())                                            # o resultado continua a ser TOML válido


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
