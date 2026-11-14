"""Ansible: resultado estruturado, inventário dinâmico, playbooks válidos e (se disponível) execução real em localhost."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from omxpatch.engine import ansible_runner as ar
from omxpatch.models import Asset
from tests.conftest import make_asset

ANSIBLE_DIR = Path(__file__).resolve().parent.parent / "ansible"
yaml = pytest.importorskip("yaml")


def test_parse_result_json_and_wrapped_yaml_formats():
    j = '    "msg": "OMXPATCH_RESULT={\\"status\\": \\"succeeded\\", \\"installed_version\\": \\"1.1.1w\\", \\"n\\": [1, 2]}"\n'
    assert ar.parse_result("ok: [h] => {\n" + j + "}") == {"status": "succeeded", "installed_version": "1.1.1w", "n": [1, 2]}
    y = ("ok: [asset1] => \n    msg: 'OMXPATCH_RESULT={\"status\": \"succeeded\", \"checks\": {\"patch_installed\": true,\n"
         "        \"service_restarted\": null}, \"software\": [{\"name\": \"openssl\", \"version\": \"3.0.13\"}],\n        \"ports_open\": []}'\n")
    r = ar.parse_result(y)
    assert r["checks"] == {"patch_installed": True, "service_restarted": None} and r["software"][0]["version"] == "3.0.13"
    assert ar.parse_result("sem resultado") is None
    two = j + j.replace("1.1.1w", "2.0")
    assert ar.parse_result(two)["installed_version"] == "2.0"            # o último


def test_dynamic_inventory(app, tenant):
    a = make_asset(tenant, "lin1", os_family="linux", ip="10.0.0.1", ansible_user="ops", ansible_port=2222)
    w = make_asset(tenant, "win1", os_family="windows", ip="10.0.0.2")
    inv = ar.inventory_for([a, w])
    h = inv["all"]["hosts"]
    assert h[f"asset{a.id}"]["ansible_user"] == "ops" and h[f"asset{a.id}"]["ansible_port"] == 2222
    assert h[f"asset{w.id}"]["ansible_connection"] == "winrm" and h[f"asset{w.id}"]["ansible_winrm_server_cert_validation"] == "validate"
    assert set(inv["windows"]["hosts"]) == {f"asset{w.id}"} and "macos" not in inv


def test_playbook_mapping_and_path_confinement(app):
    for (ttype, fam), pb in ar.PLAYBOOKS.items():
        assert (ANSIBLE_DIR / pb).is_file(), pb
    app.config["ANSIBLE_ENABLED"] = True
    app.config["ANSIBLE_PLAYBOOK"] = "python3"       # existe no PATH; o confinamento é verificado antes de executar
    app.config["ANSIBLE_DIR"] = str(ANSIBLE_DIR)
    with pytest.raises(ar.AnsibleUnavailable):
        ar.run_playbook("../tests/conftest.py", {})
    with pytest.raises(ar.AnsibleUnavailable):
        ar.run_playbook("nao_existe.yml", {})
    app.config["ANSIBLE_ENABLED"] = False
    with pytest.raises(ar.AnsibleUnavailable):
        ar.run_playbook("patch_linux.yml", {})


def test_all_yaml_files_parse_and_operational_playbooks_emit_result():
    files = list(ANSIBLE_DIR.rglob("*.yml")) + [ANSIBLE_DIR / "ansible.cfg"]
    for f in ANSIBLE_DIR.rglob("*.yml"):
        assert yaml.safe_load(f.read_text()) is not None, f
    for pb in ANSIBLE_DIR.glob("*_linux.yml"), ANSIBLE_DIR.glob("*_windows.yml"), ANSIBLE_DIR.glob("*_macos.yml"):
        for f in pb:
            text = f.read_text()
            if f.name.startswith(("patch_", "validate_", "inventory_", "mitigate_")):
                assert "OMXPATCH_RESULT=" in text, f.name


def test_role_covers_all_three_operating_systems():
    t = (ANSIBLE_DIR / "roles/omxpatch_agent/tasks/main.yml").read_text()
    for token in ("linux.yml", "macos.yml", "windows.yml", "omxpatch_enrollment_token"):
        assert token in t
    assert "no_log: true" in (ANSIBLE_DIR / "roles/omxpatch_agent/tasks/linux.yml").read_text()
    assert "no_log: true" in (ANSIBLE_DIR / "roles/omxpatch_agent/tasks/windows.yml").read_text()


@pytest.mark.skipif(not shutil.which("ansible-playbook"), reason="ansible-playbook não instalado")
def test_all_playbooks_syntax_check(tmp_path):
    import os
    from tests.test_ansible_engine import _stub_collections          # colecções simuladas: a Galaxy pode não estar acessível
    env = dict(os.environ, ANSIBLE_COLLECTIONS_PATH=_stub_collections(tmp_path / "coll"), ANSIBLE_LOCAL_TEMP=str(tmp_path / "tmp"), ANSIBLE_DEPRECATION_WARNINGS="False")
    for pb in sorted(ANSIBLE_DIR.glob("*.yml")):
        if pb.name == "requirements.yml":
            continue
        p = subprocess.run(["ansible-playbook", "-i", str(ANSIBLE_DIR / "inventory.example.ini"), "--syntax-check", str(pb)],
                           capture_output=True, text=True, cwd=ANSIBLE_DIR, timeout=180, env=env)
        assert p.returncode == 0, (pb.name, p.stdout[-800:], p.stderr[-800:])


@pytest.mark.skipif(not shutil.which("ansible-playbook") or not shutil.which("dpkg-query") or __import__("os").geteuid() != 0, reason="requer ansible, Debian/Ubuntu e root")
def test_real_inventory_and_validation_run_on_localhost(app, tenant):
    app.config.update(ANSIBLE_ENABLED=True, ANSIBLE_PLAYBOOK=shutil.which("ansible-playbook"), ANSIBLE_DIR=str(ANSIBLE_DIR))
    py = next((p for p in ("/usr/bin/python3.12", "/usr/bin/python3") if Path(p).exists() and
               subprocess.run([p, "-c", "import apt_pkg"], capture_output=True).returncode == 0), None)
    if py is None:
        pytest.skip("python3-apt indisponível")
    inv = {"all": {"hosts": {"asset1": {"ansible_connection": "local", "ansible_python_interpreter": py}}}, "linux": {"hosts": {"asset1": {}}}}
    r = ar.run_playbook("inventory_linux.yml", inv, {}, limit="asset1", timeout_minutes=5)
    assert r["rc"] == 0 and r["result"]["status"] == "succeeded" and len(r["result"]["software"]) > 10
    pkg = r["result"]["software"][0]["name"]
    v = ar.run_playbook("validate_linux.yml", inv, {"software": pkg, "patched_at_epoch": 1700000000,
                                                    "patch": {"package": pkg, "version_fixed": "0.0.1"}}, limit="asset1", timeout_minutes=5)
    assert v["rc"] == 0 and v["result"]["checks"]["patch_installed"] is True and v["result"]["software"]
