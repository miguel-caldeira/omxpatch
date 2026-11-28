"""Transportes sem agente: SSH real (sshd local) e WMI/SMB contra um Windows simulado."""
from __future__ import annotations

import os
import pwd
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from omxpatch.transports import AuthError, ConnectError, TransportError
from omxpatch.transports.ssh import SSHTransport
from omxpatch.transports.wmi import WMITransport, share_path, split_account
from tests.fake_impacket import FakeWindows, install


# --------------------------------------------------------------------------------------------------------------------- WMI (simulado)
def test_account_and_path_helpers():
    assert split_account("CONTOSO\\ana") == ("ana", "CONTOSO") and split_account("ana@contoso.local") == ("ana", "contoso.local") and split_account("Administrator") == ("Administrator", "")
    assert share_path(r"C:\Windows\Temp\a.txt") == ("C$", r"Windows\Temp\a.txt") and share_path("d:/dados/x") == ("D$", r"dados\x")
    with pytest.raises(TransportError):
        share_path("relativo\\x")


def test_wmi_runs_commands_with_stdin_rc_and_cleanup(monkeypatch):
    win = install(monkeypatch, FakeWindows())
    with WMITransport("srv", "admin", "pw") as t:
        r = t.run("echo olá; echo erro >&2; exit 7")
        assert (r.rc, r.out.strip(), r.err.strip()) == (7, "olá", "erro")
        r = t.run("cat", stdin="entrada via stdin\n".encode())
        assert r.rc == 0 and r.out == "entrada via stdin\n"
        assert t.run("echo 100%").out.strip() == "100%"                                  # % é escapado no .cmd e volta ao original
        assert t.query("SELECT Caption FROM Win32_OperatingSystem")[0]["Caption"].startswith("Microsoft Windows")
    assert all(c.startswith("cmd.exe /Q /c C:\\Windows\\Temp\\omx-") for c in win.created)
    assert not [k for k in win.files if "omx-" in k[1]]                                      # ficheiros temporários apagados (a saída pode ter segredos)


def test_wmi_files_and_errors(monkeypatch, tmp_path):
    win = install(monkeypatch, FakeWindows())
    src = tmp_path / "a.bin"
    src.write_bytes(b"\x00\x01dados")
    t = WMITransport("srv", "admin", "pw")
    t.put(str(src), r"C:\Temp\a.bin")
    assert t.get(r"C:\Temp\a.bin") == b"\x00\x01dados"
    with pytest.raises(TransportError, match="inexistente"):
        t.get(r"C:\Temp\nao.txt")
    t.close()
    with pytest.raises(AuthError, match="recusados"):
        WMITransport("srv", "admin", "errada").connect()
    install(monkeypatch, FakeWindows(deny_dcom=True))
    with pytest.raises(AuthError, match="DCOM"):
        WMITransport("srv", "admin", "pw").connect()


def test_wmi_command_timeout_does_not_hang(monkeypatch):
    install(monkeypatch, FakeWindows(hang=True))
    t0 = time.time()
    r = WMITransport("srv", "admin", "pw").run("echo x", timeout=1)
    assert r.rc == 124 and "Tempo excedido" in r.err and time.time() - t0 < 6


def test_wmi_domain_account_is_split(monkeypatch):
    install(monkeypatch, FakeWindows(user="ana"))
    t = WMITransport("srv", "CONTOSO\\ana", "pw")
    assert (t.user, t.domain) == ("ana", "CONTOSO")
    t.connect()
    t.close()


# --------------------------------------------------------------------------------------------------------------------- SSH (sshd real)
SSHD = shutil.which("sshd") or "/usr/sbin/sshd"
needs_sshd = pytest.mark.skipif(not (Path(SSHD).exists() and shutil.which("ssh-keygen") and os.geteuid() == 0), reason="precisa de sshd, ssh-keygen e root")


@pytest.fixture(scope="module")
def sshd(tmp_path_factory):
    d = tmp_path_factory.mktemp("sshd")
    os.makedirs("/run/sshd", exist_ok=True)                    # diretório de separação de privilégios do sshd
    user = "omxtest"
    try:
        pwd.getpwnam(user)
    except KeyError:
        subprocess.run(["useradd", "-m", "-s", "/bin/bash", user], check=True)
    subprocess.run(["chpasswd"], input=f"{user}:Senha-Teste-1\n".encode(), check=True)
    home = Path(pwd.getpwnam(user).pw_dir)
    (home / ".ssh").mkdir(exist_ok=True)
    key = d / "id_ed25519"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    (home / ".ssh" / "authorized_keys").write_text((d / "id_ed25519.pub").read_text())
    subprocess.run(["chown", "-R", f"{user}:{user}", str(home / ".ssh")], check=True)
    os.chmod(home / ".ssh", 0o700)
    os.chmod(home / ".ssh" / "authorized_keys", 0o600)
    hostkey = d / "host_key"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(hostkey)], check=True)
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    cfg = d / "sshd_config"
    cfg.write_text(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {hostkey}\nPidFile {d}/sshd.pid\nPasswordAuthentication yes\nPubkeyAuthentication yes\nUsePAM no\n"
                   f"PermitRootLogin no\nAllowUsers {user}\nSubsystem sftp internal-sftp\nStrictModes no\n")
    proc = subprocess.Popen([SSHD, "-D", "-e", "-f", str(cfg)], stderr=subprocess.PIPE)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    yield {"port": port, "user": user, "key": key.read_text(), "dir": d, "hostkey_pub": (d / "host_key.pub").read_text()}
    proc.terminate()
    proc.wait(timeout=10)


@needs_sshd
def test_ssh_password_and_key_login_commands_files(sshd, tmp_path):
    kh = str(tmp_path / "known_hosts")
    with SSHTransport("127.0.0.1", sshd["user"], password="Senha-Teste-1", port=sshd["port"], known_hosts=kh) as t:
        r = t.run("echo olá; echo erro >&2; exit 3")
        assert (r.rc, r.out.strip(), r.err.strip()) == (3, "olá", "erro")
        assert t.run("cat", stdin=b"via stdin").out == "via stdin"
        assert t.run("sleep 5", timeout=1).rc == 124
        src = tmp_path / "f.txt"
        src.write_text("conteúdo")
        t.put(str(src), f"/home/{sshd['user']}/f.txt")
        assert t.get(f"/home/{sshd['user']}/f.txt") == "conteúdo".encode()
    assert "127.0.0.1" in Path(kh).read_text() or f"[127.0.0.1]:{sshd['port']}" in Path(kh).read_text()          # chave aceite na 1.ª ligação e registada
    with SSHTransport("127.0.0.1", sshd["user"], key_pem=sshd["key"], port=sshd["port"], known_hosts=kh, accept_new=False) as t:         # agora já é conhecida
        assert t.run("id -un").out.strip() == sshd["user"]


@needs_sshd
def test_ssh_failures_are_classified(sshd, tmp_path):
    kh = str(tmp_path / "known_hosts")
    with pytest.raises(AuthError, match="recusados"):
        SSHTransport("127.0.0.1", sshd["user"], password="errada", port=sshd["port"], known_hosts=kh).connect()
    with pytest.raises(ConnectError, match="desconhecida"):
        SSHTransport("127.0.0.1", sshd["user"], password="Senha-Teste-1", port=sshd["port"], known_hosts=str(tmp_path / "vazio"), accept_new=False).connect()
    with pytest.raises(ConnectError):
        SSHTransport("127.0.0.1", sshd["user"], password="x", port=1, known_hosts=kh, timeout=2).connect()
    with SSHTransport("127.0.0.1", sshd["user"], password="Senha-Teste-1", port=sshd["port"], known_hosts=kh) as t:
        t.connect()
    # a chave do equipamento mudou: recusado (nunca aceite em silêncio)
    import paramiko
    other = paramiko.Ed25519Key.generate() if hasattr(paramiko.Ed25519Key, "generate") else None
    hk = paramiko.HostKeys(kh)
    name = next(iter(hk.keys()))
    hk[name]["ssh-ed25519"] = other or paramiko.RSAKey.generate(2048)
    hk.save(kh)
    with pytest.raises(ConnectError, match="mudou|desconhecida|chave"):
        SSHTransport("127.0.0.1", sshd["user"], password="Senha-Teste-1", port=sshd["port"], known_hosts=kh).connect()


# --------------------------------------------------------------------------------------------------------------------- Ansible real sobre a ligação omx_wmi (Windows simulado)
@pytest.mark.skipif(not (shutil.which("ansible-playbook") or Path("/tmp/venv/bin/ansible-playbook").exists()), reason="ansible-core não instalado")
def test_ansible_modules_run_over_the_wmi_connection(tmp_path):
    """Ansible real + ligação omx_wmi + transporte WMI/SMB (sobre um Windows simulado): comandos, módulos Python por stdin e leitura de ficheiros."""
    import json
    import sys as _sys
    exe = shutil.which("ansible-playbook") or "/tmp/venv/bin/ansible-playbook"
    root = Path(__file__).resolve().parents[1]
    fake = tmp_path / "fakepy"
    fake.mkdir()
    (fake / "sitecustomize.py").write_text(f"import sys\nsys.path.insert(0, {str(root)!r})\nfrom tests.fake_impacket import FakeWindows, install\ninstall(None, FakeWindows(user='admin', password='pw'))\n")
    f = tmp_path / "alvo.txt"
    f.write_text("ficheiro-do-alvo")
    pb = tmp_path / "pb.yml"
    pb.write_text("- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.command: echo olá-wmi\n      register: r\n"
                  f"    - ansible.builtin.slurp: {{src: {f}}}\n      register: s\n"
                  "    - ansible.builtin.debug:\n        msg: 'OMXPATCH_RESULT={\"status\": \"succeeded\", \"cmd\": \"{{ r.stdout }}\", \"file\": \"{{ s.content | b64decode }}\"}'\n")
    inv = {"all": {"hosts": {"win1": {"ansible_connection": "omx_wmi", "ansible_shell_type": "sh", "ansible_host": "srv-fake", "ansible_user": "admin", "ansible_password": "pw",
                                      "ansible_python_interpreter": _sys.executable}}}}
    (tmp_path / "inv.json").write_text(json.dumps(inv))
    env = dict(os.environ, PYTHONPATH=f"{fake}:{root}", ANSIBLE_CONNECTION_PLUGINS=str(root / "ansible" / "connection_plugins"), ANSIBLE_CALLBACK_RESULT_FORMAT="json",
               ANSIBLE_NOCOLOR="1", ANSIBLE_LOCAL_TEMP=str(tmp_path / "lt"), ANSIBLE_HOME=str(tmp_path / "ah"), ANSIBLE_DEPRECATION_WARNINGS="False")
    r = subprocess.run([exe, "-i", str(tmp_path / "inv.json"), str(pb)], capture_output=True, text=True, env=env, timeout=240)
    out = r.stdout + r.stderr
    assert r.returncode == 0, out[-3000:]
    from omxpatch.engine.ansible_runner import parse_result
    assert parse_result(out) == {"status": "succeeded", "cmd": "olá-wmi", "file": "ficheiro-do-alvo"}
    # credenciais erradas → UNREACHABLE com a causa (não um erro críptico)
    inv["all"]["hosts"]["win1"]["ansible_password"] = "errada"
    (tmp_path / "inv.json").write_text(json.dumps(inv))
    r = subprocess.run([exe, "-i", str(tmp_path / "inv.json"), str(pb)], capture_output=True, text=True, env=env, timeout=240)
    assert r.returncode != 0 and "UNREACHABLE" in r.stdout + r.stderr and "recusados" in r.stdout + r.stderr
