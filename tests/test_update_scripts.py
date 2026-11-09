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
