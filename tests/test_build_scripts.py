"""Construtores nativos dos instaladores: sintaxe, estrutura e o utilitário de zip (os .exe/.pkg só se compilam no Windows/macOS: ver installers.yml)."""
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
B = ROOT / "packaging" / "build"


@pytest.mark.parametrize("script", ["linux/build.sh", "macos/build.sh", "macos/scripts/postinstall", "../build_installers.sh"])
def test_shell_scripts_have_valid_syntax(script):
    assert subprocess.run(["bash", "-n", str(B / script)], capture_output=True).returncode == 0


def test_workflow_and_inno_script_are_consistent():
    wf = yaml.safe_load((ROOT / ".github/workflows/installers.yml").read_text(encoding="utf-8"))
    jobs = wf["jobs"]
    assert {"linux", "windows", "macos", "juntar"} <= set(jobs) and jobs["juntar"]["needs"] == ["linux", "windows", "macos"]
    assert jobs["windows"]["runs-on"] == "windows-latest" and jobs["macos"]["runs-on"] == "macos-latest"
    iss = (B / "windows/omxpatch.iss").read_text(encoding="utf-8")
    for token in ("AppVer", "Mode", "OutName", "NORUN", "Install-OMXPatch.ps1", "Install-OMXPatchAgent.ps1", "/HOSTNAME", "/TOKEN"):
        assert token in iss
    assert iss.index("function CmdLineParamExists") < iss.index("function ShouldRun")           # Pascal exige a declaração antes do uso
    ps = (B / "windows/build.ps1").read_bytes()
    assert ps.startswith(b"\xef\xbb\xbf")                                                          # PowerShell 5.1 precisa de BOM para ler acentos
    assert (ROOT / "packaging/installers/windows-agent/Install-OMXPatchAgent.ps1").read_bytes().startswith(b"\xef\xbb\xbf")


def test_zipdir_uses_forward_slashes_and_root_folder(tmp_path):
    src = tmp_path / "pkg-1.0"
    (src / "sub" / "__pycache__").mkdir(parents=True)
    (src / "sub" / "a.txt").write_text("x")
    (src / "sub" / "__pycache__" / "a.pyc").write_text("x")
    (src / "b.py").write_text("y")
    out = tmp_path / "o.zip"
    subprocess.run([sys.executable, str(B / "zipdir.py"), str(src), str(out)], check=True, capture_output=True)
    names = sorted(zipfile.ZipFile(out).namelist())
    assert names == ["pkg-1.0/b.py", "pkg-1.0/sub/a.txt"]
    assert not any("\\" in n for n in names)


def test_windows_installer_scripts_accept_pause_and_keep_bom():
    t = (ROOT / "packaging/installers/windows/Install-OMXPatch.ps1").read_bytes()
    assert t.startswith(b"\xef\xbb\xbf") and b"[switch]$Pause" in t
