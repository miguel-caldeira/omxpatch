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
