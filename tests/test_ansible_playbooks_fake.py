"""Corre os playbooks Windows e CyberArk de ponta a ponta contra módulos *simulados* (colecção ansible.windows de teste): exercita toda a lógica
Jinja, o encadeamento de tarefas, a verificação do SHA-256, a reposição dos serviços em caso de falha e o JSON final — sem precisar de um Windows.
Não substitui o teste em equipamentos reais."""
import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from omxpatch.engine import ansible_runner

ANS = Path(__file__).resolve().parents[1] / "ansible"
EXE = shutil.which("ansible-playbook") or ("/tmp/venv/bin/ansible-playbook" if Path("/tmp/venv/bin/ansible-playbook").exists() else None)
pytestmark = pytest.mark.skipif(EXE is None, reason="ansible-core não instalado")

SHELL = '''
import json, os, re
from ansible.module_utils.basic import AnsibleModule
def main():
    m = AnsibleModule(argument_spec={"_raw_params": {"type": "str"}, "chdir": {"type": "str"}, "cmd": {"type": "str"}}, check_invalid_arguments=False) if False else AnsibleModule(argument_spec={}, bypass_checks=True, check_invalid_arguments=False) if False else None
main()
'''


def _write_modules(root: Path) -> None:
    base = root / "ansible_collections" / "ansible" / "windows"
    (base / "plugins" / "modules").mkdir(parents=True)
    for p in (root / "ansible_collections", root / "ansible_collections" / "ansible", base):
        (p / "__init__.py").touch()
    (base / "galaxy.yml").write_text("namespace: ansible\nname: windows\nversion: 1.0.0\n")
    common = textwrap.dedent('''
        import json, os, re
        from ansible.module_utils.basic import AnsibleModule
        FAKE = json.load(open(os.environ["OMX_FAKE"]))
        LOG = os.environ["OMX_FAKE_LOG"]
        def log(kind, text):
            with open(LOG, "a") as fh:
                fh.write(json.dumps({"kind": kind, "text": text}) + "\\n")
    ''')
    mods = {
        "win_shell": common + textwrap.dedent('''
            m = AnsibleModule(argument_spec={"_raw_params": {"type": "str"}, "chdir": {"type": "str"}}, supports_check_mode=True)
            cmd = m.params["_raw_params"] or ""
            log("shell", cmd)
            for r in FAKE.get("shell", []):
                if re.search(r["match"], cmd, re.S):
                    if r.get("fail"):
                        m.fail_json(msg=r["fail"], rc=1, stdout="", stderr=r["fail"])
                    m.exit_json(changed=True, stdout=r.get("stdout", ""), stderr="", rc=0)
            m.exit_json(changed=True, stdout="", stderr="", rc=0)
        '''),
        "win_command": common + textwrap.dedent('''
            m = AnsibleModule(argument_spec={"_raw_params": {"type": "str"}, "chdir": {"type": "str"}}, supports_check_mode=True)
            cmd = m.params["_raw_params"] or ""
            log("command", cmd)
            for r in FAKE.get("command", []):
                if re.search(r["match"], cmd, re.S):
                    out = r.get("stdout", "")
                    m.exit_json(changed=True, stdout=out, stdout_lines=out.splitlines(), stderr="", rc=r.get("rc", 0))
            m.exit_json(changed=True, stdout="", stdout_lines=[], stderr="", rc=0)
        '''),
        "win_updates": common + textwrap.dedent('''
            m = AnsibleModule(argument_spec={"category_names": {"type": "list"}, "state": {"type": "str"}, "reboot": {"type": "bool"}, "reboot_timeout": {"type": "int"},
                                              "accept_list": {"type": "list"}}, supports_check_mode=True)
            log("win_updates", m.params["state"])
            ups = FAKE.get("updates", {})
            if m.params["state"] == "searched":
                m.exit_json(changed=False, updates=ups, found_update_count=len(ups), reboot_required=False)
            m.exit_json(changed=True, updates=ups, installed_update_count=len(ups), reboot_required=FAKE.get("reboot", False), failed=False)
        '''),
        "win_reboot": common + "m = AnsibleModule(argument_spec={'reboot_timeout': {'type': 'int'}})\nlog('reboot', '')\nm.exit_json(changed=True, rebooted=True)\n",
        "win_copy": common + "m = AnsibleModule(argument_spec={'src': {'type': 'path'}, 'dest': {'type': 'str'}})\nlog('copy', m.params['dest'])\nm.exit_json(changed=True)\n",
        "win_file": common + "m = AnsibleModule(argument_spec={'path': {'type': 'str'}, 'state': {'type': 'str'}})\nlog('file', m.params['state'] + ' ' + m.params['path'])\nm.exit_json(changed=True)\n",
        "win_stat": common + ("m = AnsibleModule(argument_spec={'path': {'type': 'str'}, 'checksum_algorithm': {'type': 'str'}})\n"
                              "m.exit_json(changed=False, stat={'exists': True, 'checksum': FAKE.get('sha256', '')})\n"),
    }
    for name, code in mods.items():
        (base / "plugins" / "modules" / f"{name}.py").write_text(code)
    nc = root / "ansible_collections" / "ansible" / "netcommon"
    (nc / "plugins" / "modules").mkdir(parents=True)
    (nc / "__init__.py").touch()
    (nc / "galaxy.yml").write_text("namespace: ansible\nname: netcommon\nversion: 1.0.0\n")
    (nc / "plugins" / "modules" / "cli_command.py").write_text("from ansible.module_utils.basic import AnsibleModule\nm = AnsibleModule(argument_spec={'command': {'type': 'str'}})\nm.exit_json(changed=False, stdout='')\n")


NET_GROUPS = ["net_checkpoint", "net_fortios", "net_panos", "net_cisco_ios", "net_cisco_nxos", "net_junos", "net_eos"]


def _net(host_group: str, host: str) -> str:
    return "".join(f"[{g}]\n{host if g == host_group else ''}\n" for g in NET_GROUPS)


def _run(tmp: Path, playbook: str, groups: str, fake: dict, extra: dict, host_vars: str = "") -> tuple[dict | None, str, list]:
    _write_modules(tmp / "coll")
    inv = tmp / "inv.ini"
    inv.write_text(groups + f"\n[all:vars]\nansible_connection=local\nansible_become=false\nansible_python_interpreter={os.environ.get('PYTHON', sys.executable)}\n" + host_vars)
    fakef, logf = tmp / "fake.json", tmp / "fake.log"
    fakef.write_text(json.dumps(fake))
    vars_f = tmp / "vars.json"
    vars_f.write_text(json.dumps(extra))
    env = dict(os.environ, ANSIBLE_COLLECTIONS_PATH=str(tmp / "coll"), OMX_FAKE=str(fakef), OMX_FAKE_LOG=str(logf), ANSIBLE_CALLBACK_RESULT_FORMAT="json",
               ANSIBLE_NOCOLOR="1", ANSIBLE_CONFIG=str(ANS / "ansible.cfg"), ANSIBLE_LOCAL_TEMP=str(tmp / "ltmp"), ANSIBLE_DEPRECATION_WARNINGS="False")
    r = subprocess.run([EXE, "-i", str(inv), str(ANS / playbook), "-e", f"@{vars_f}"], capture_output=True, text=True, env=env, cwd=str(ANS), timeout=200)
    out = r.stdout + r.stderr
    log = [json.loads(line) for line in logf.read_text().splitlines()] if logf.exists() else []
    return ansible_runner.parse_result(out), out, log


WINGET = """Name                Id                 Version   Available Source
-----------------------------------------------------------------
7-Zip               7zip.7zip          22.01     23.01     winget
Git                 Git.Git            2.40.0    2.43.0    winget
2 upgrades available.
"""
WUA_UPDATES = {"abc-1": {"title": "2024-02 Cumulative Update for Windows Server 2022 (KB5034439)", "kb": ["KB5034439"], "categories": ["Security Updates", "Critical Updates"],
                         "reboot_required": True},
               "abc-2": {"title": "Definition Update (KB2267602)", "kb": ["KB2267602"], "categories": ["Definition Updates"], "reboot_required": False}}


def test_windows_assess_apply_with_simulated_modules(tmp_path):
    fake = {"updates": WUA_UPDATES, "reboot": True,
            "shell": [{"match": "Get-Command winget", "stdout": json.dumps({"winget": "C:\\\\w\\\\winget.exe", "choco": "C:\\\\ProgramData\\\\chocolatey\\\\choco.exe"})}],
            "command": [{"match": "winget.*upgrade --include-unknown", "stdout": WINGET}, {"match": "choco.*outdated", "stdout": "git|2.40.0|2.43.0|false\nnodejs|18.0.0|20.1.0|false\npinned|1.0|2.0|true\n"}]}
    res, out, log = _run(tmp_path, "update_windows.yml", "[windows]\nw1", fake, {"omx_mode": "assess", "omx_scope": "all"})
    assert res and res["status"] == "succeeded" and res["mode"] == "assess", out[-3000:]
    kinds = [x["kind"] for x in log]
    assert "win_updates" in kinds and not any(x["kind"] == "reboot" for x in log)                   # avaliar nunca reinicia nem instala
    assert not any("upgrade --all" in x["text"] for x in log)
    assert {p["source"] for p in res["pending"]} == {"wua"} and res["pending"][0]["kb"] == "KB5034439" and res["pending"][0]["severity"] == "critical"
    assert "7zip.7zip" in res["raw_winget"] and "nodejs" in res["raw_choco"]
    # o servidor lê as colunas do winget/Chocolatey com os analisadores do agente
    from omxpatch_agent.updates import windows as winp
    assert [u["id"] for u in winp.parse_winget_upgrade(res["raw_winget"])] == ["7zip.7zip", "Git.Git"]
    assert [u["name"] for u in winp.parse_choco_outdated(res["raw_choco"])] == ["git", "nodejs"]
    res, out, log = _run(tmp_path / "b", "update_windows.yml", "[windows]\nw1", fake, {"omx_mode": "apply", "omx_scope": "all", "reboot_policy": "if_needed"})
    assert res and res["status"] == "succeeded" and res["mode"] == "apply" and res["reboot_pending"] is True, out[-3000:]
    texts = " | ".join(x["text"] for x in log)
    assert "upgrade --all" in texts and "upgrade all -y" in texts and any(x["kind"] == "reboot" for x in log)
    res, out, log = _run(tmp_path / "c", "update_windows.yml", "[windows]\nw1", fake, {"omx_mode": "apply", "omx_scope": "os", "reboot_policy": "never"})
    assert res["status"] == "succeeded" and not any(x["kind"] == "reboot" for x in log) and "upgrade --all" not in " ".join(x["text"] for x in log)


def _cyber_fake(version="13.0", sha="a" * 64, after="14.2", fail_cmd=False, svc="Running"):
    return {"sha256": sha, "shell": [
        {"match": "Uninstall.*DisplayName -match.*Get-Service", "stdout": json.dumps({"products": [{"DisplayName": "CyberArk Password Manager", "DisplayVersion": version}],
                                                                                     "services": [{"Name": "CyberArk Password Manager", "DisplayName": "CyberArk Password Manager", "Status": svc}], "free_bytes": 50 * 1024 ** 3})},
        {"match": "Select-Object -First 1\\)\\.DisplayVersion", "stdout": after + "\n"},
        {"match": "BOOM-upgrade", "fail": "instalador falhou (código 1603)"} if fail_cmd else {"match": "^$", "stdout": ""},
        {"match": "Copy-Item", "stdout": "7\n"}]}


APPLY = {"omx_mode": "apply", "cyberark_target_version": "14.2", "cyberark_media_src": "/srv/cpm.zip", "cyberark_media_sha256": "a" * 64,
         "cyberark_upgrade_cmd": "setup.exe /s /v/qn", "omx_component": "cpm"}
HV = "\n[cyberark_cpm:vars]\nomx_component=cpm\n"


def test_cyberark_windows_assess_and_apply_simulated(tmp_path):
    groups = "[cyberark_cpm]\nw1\n"
    res, out, log = _run(tmp_path, "cyberark_upgrade.yml", groups, _cyber_fake(), {"omx_mode": "assess"}, HV)
    assert res and res["status"] == "succeeded" and res["component"] == "cpm" and res["version"] == "13.0" and res["precheck_ok"] is True, out[-3000:]
    assert not [x for x in log if x["kind"] in ("copy",) or "Stop-Service" in x["text"]]               # avaliar não mexe em nada
    res, out, log = _run(tmp_path / "b", "cyberark_upgrade.yml", groups, _cyber_fake(), APPLY, HV)
    assert res["status"] == "succeeded" and res["version_after"] == "14.2" and res["version_before"] == "13.0", out[-3000:]
    texts = [x["text"] for x in log]
    stop = next(i for i, t in enumerate(texts) if "Stop-Service" in t)
    upg = next(i for i, t in enumerate(texts) if "setup.exe" in t)
    start = next(i for i, t in enumerate(texts) if "Start-Service" in t and "Stop-Service" not in t)
    bak = next(i for i, t in enumerate(texts) if "Copy-Item" in t)
    assert bak < stop < upg < start                                                                      # backup → parar → atualizar → arrancar
    # versão final diferente da esperada → falha e os serviços são repostos
    res, out, log = _run(tmp_path / "c", "cyberark_upgrade.yml", groups, _cyber_fake(after="13.0"), APPLY, HV)
    assert res["status"] == "failed" and "não é a esperada" in res["error"] and "Serviços repostos" in res["note"]
    # o comando do fabricante falha → falha, serviços repostos
    res, out, log = _run(tmp_path / "d", "cyberark_upgrade.yml", groups, _cyber_fake(fail_cmd=True), {**APPLY, "cyberark_upgrade_cmd": "BOOM-upgrade"}, HV)
    assert res["status"] == "failed" and "1603" in res["error"]
    assert [x for x in log if "Start-Service" in x["text"] and "SilentlyContinue" in x["text"]]
    # SHA-256 do pacote não confere → nem chega a parar os serviços
    res, out, log = _run(tmp_path / "e", "cyberark_upgrade.yml", groups, _cyber_fake(sha="b" * 64), APPLY, HV)
    assert res["status"] == "failed" and not [x for x in log if "Stop-Service" in x["text"] and "SilentlyContinue" not in x["text"] and "Start-Service" not in x["text"]]
    # sem comando do fabricante → recusa antes de tocar em nada
    res, out, log = _run(tmp_path / "f", "cyberark_upgrade.yml", groups, _cyber_fake(), {**APPLY, "cyberark_upgrade_cmd": ""}, HV)
    assert res is None or res["status"] == "failed"
    assert not [x for x in log if x["kind"] == "copy"]


# --------------------------------------------------------------------------- PSMP (Linux) com rpm/systemctl simulados


def _fake_bin(tmp: Path, state: Path, fail_rpm=False, after="14.2.0-9"):
    b = tmp / "bin"
    b.mkdir(parents=True, exist_ok=True)
    (b / "rpm").write_text(textwrap.dedent(f'''\
        #!/bin/sh
        echo "rpm $@" >> {state}/calls
        case "$*" in
          *"-q --qf"*) [ -f {state}/upgraded ] && printf '%s' '{after}' || printf '%s' '13.0.0-1';;
          *"-Uvh --test"*|*"-Uvh"*) {"echo 'error: Failed dependencies' >&2; exit 1" if fail_rpm else f"touch {state}/upgraded"};;
        esac
        '''))
    (b / "systemctl").write_text(f'#!/bin/sh\necho "systemctl $@" >> {state}/calls\ncase "$1" in is-active) echo active;; esac\n')
    for f in b.iterdir():
        f.chmod(0o755)
    return b


@pytest.mark.skipif(os.geteuid() != 0, reason="o playbook PSMP escreve em /var/lib e /var/tmp (precisa de root)")
def test_psmp_simulated(tmp_path):
    import hashlib
    media = tmp_path / "CARKpsmp-14.2.rpm"
    media.write_bytes(b"rpm-bytes")
    sha = hashlib.sha256(b"rpm-bytes").hexdigest()
    state = tmp_path / "state"
    state.mkdir()
    b = _fake_bin(tmp_path, state)
    os.environ["PATH"] = f"{b}:{os.environ['PATH']}"
    try:
        extra = {"omx_mode": "apply", "cyberark_target_version": "14.2.0", "cyberark_media_src": str(media), "cyberark_media_sha256": sha}
        res, out, _ = _run(tmp_path / "run", "cyberark_upgrade.yml", "[cyberark_psmp]\nl1", {}, {"omx_mode": "assess"})
        assert res and res["component"] == "psmp" and res["version"] == "13.0.0-1" and res["service"] == "active", out[-2500:]
        assert not (state / "upgraded").exists()                                    # avaliar não atualiza
        res, out, _ = _run(tmp_path / "run2", "cyberark_upgrade.yml", "[cyberark_psmp]\nl1", {}, extra)
        assert res["status"] == "succeeded" and res["version_after"] == "14.2.0-9" and (state / "upgraded").exists(), out[-2500:]
        calls = (state / "calls").read_text()
        assert calls.index("systemctl stop") < calls.index("rpm -Uvh") < calls.rindex("systemctl start")
        # rpm falha → serviço reposto e resultado de falha com a nota de restauro
        (state / "upgraded").unlink()
        (state / "calls").unlink()
        _fake_bin(tmp_path, state, fail_rpm=True)
        res, out, _ = _run(tmp_path / "run3", "cyberark_upgrade.yml", "[cyberark_psmp]\nl1", {}, extra)
        assert res["status"] == "failed" and "Serviço reposto" in res["note"] and "systemctl start" in (state / "calls").read_text()
        # SHA-256 errado → nada é executado
        (state / "calls").unlink()
        res, out, _ = _run(tmp_path / "run4", "cyberark_upgrade.yml", "[cyberark_psmp]\nl1", {}, {**extra, "cyberark_media_sha256": "0" * 64})
        assert res["status"] == "failed" and "rpm -Uvh" not in (state / "calls").read_text() if (state / "calls").exists() else True
    finally:
        os.environ["PATH"] = os.environ["PATH"].split(":", 1)[1]


# --------------------------------------------------------------------------- equipamentos de rede: API/SSH simulados


def _https_server(tmp: Path):
    import datetime
    import http.server
    import ssl
    import threading
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2035, 1, 1)).sign(key, hashes.SHA256()))
    (tmp / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            seen.append((self.path, self.headers.get("Authorization"), self.headers.get("X-PAN-KEY")))
            from urllib.parse import unquote
            p = unquote(self.path)
            if "monitor/system/status" in p:
                body, ct = FGT_STATUS_T, "application/json"
            elif "monitor/system/firmware" in p:
                body, ct = FGT_FW_T, "application/json"
            elif "<show><system><info>" in p:
                body, ct = PAN_INFO_T, "application/xml"
            elif "<request><system><software><info>" in p:
                body, ct = PAN_SW_T, "application/xml"
            else:
                body, ct = "<response status='success'/>", "application/xml"
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.end_headers()
            self.wfile.write(body.encode())
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(tmp / "c.pem"), str(tmp / "k.pem"))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, seen


FGT_STATUS_T = json.dumps({"results": {"model_name": "FortiGate", "model_number": "60F", "hostname": "fgt"}, "version": "v7.2.5", "serial": "S1"})
FGT_FW_T = json.dumps({"results": {"current": {"version": "v7.2.5"}, "available": [{"version": "v7.2.8"}]}})
PAN_INFO_T = "<response status='success'><result><system><hostname>pa</hostname><model>PA-440</model><serial>1</serial><sw-version>10.2.4-h4</sw-version></system></result></response>"
PAN_SW_T = "<response status='success'><result><sw-updates><versions><entry><version>10.2.9</version><downloaded>no</downloaded></entry></versions></sw-updates></result></response>"


def test_network_assess_runs_against_simulated_devices(tmp_path):
    from omxpatch.engine import netassess
    srv, seen = _https_server(tmp_path)
    port = srv.server_address[1]
    try:
        hv = f"\n[net_fortios:vars]\nansible_host=127.0.0.1\nansible_port={port}\nomx_api_token=TOK123\nomx_validate_certs=false\n" \
             f"[net_panos:vars]\nansible_host=127.0.0.1\nansible_port={port}\nomx_api_token=PANKEY\nomx_validate_certs=false\n"
        res, out, _ = _run(tmp_path / "f", "net_assess.yml", _net("net_fortios", "fw1"), {}, {}, hv)
        assert res and res["status"] == "succeeded" and res["platform"] == "fortios", out[-3000:]
        facts = netassess.parse_fortios(res["raw"])
        assert facts["version"] == "7.2.5" and facts["available"] == ["7.2.8"]
        assert all(a == "Bearer TOK123" for _, a, _ in seen if a)
        assert "TOK123" not in out                                                    # o token nunca aparece no registo do Ansible
        seen.clear()
        res, out, _ = _run(tmp_path / "p", "net_assess.yml", _net("net_panos", "pa1"), {}, {}, hv)
        assert res and res["platform"] == "panos", out[-3000:]
        facts = netassess.parse_panos(res["raw"])
        assert facts["version"] == "10.2.4-h4" and facts["available"] == ["10.2.9"]
        assert all(k == "PANKEY" for _, _, k in seen if k) and "PANKEY" not in out
        assert any("%3Ccheck%3E" in p or "<check>" in p for p, _, _ in seen)         # pede a verificação de versões (só leitura no servidor de atualizações)
        # Check Point: SSH simulado por «raw» local com um clish falso
        b = tmp_path / "cp"
        b.mkdir()
        (b / "clish").write_text("#!/bin/sh\nprintf 'Product version Check Point Gaia R81.20\\nOS build 631\\n'\n")
        (b / "clish").chmod(0o755)
        os.environ["PATH"] = f"{b}:{os.environ['PATH']}"
        try:
            res, out, _ = _run(tmp_path / "c", "net_assess.yml", _net("net_checkpoint", "cp1"), {}, {})
        finally:
            os.environ["PATH"] = os.environ["PATH"].split(":", 1)[1]
        assert res and netassess.parse_checkpoint(res["raw"])["version"] == "R81.20", out[-3000:]
    finally:
        srv.shutdown()
