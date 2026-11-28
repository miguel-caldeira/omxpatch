"""Transporte SSH (paramiko): palavra-passe ou chave privada, chave do equipamento aceite na 1.ª ligação (TOFU) ou exigida, sudo opcional."""
from __future__ import annotations

import io
import os
import shlex
import socket
import time

from .base import AuthError, ConnectError, Result, Transport, TransportError


def _load_key(pem: str, passphrase: str = ""):
    import paramiko
    last = None
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key(io.StringIO(pem), password=passphrase or None)
        except Exception as exc:  # noqa: BLE001 - tenta o tipo seguinte
            last = exc
    raise AuthError(f"Chave SSH privada inválida ou frase-passe errada: {last}")


class SSHTransport(Transport):
    kind = "ssh"
    shell = "sh"

    def __init__(self, host: str, user: str, password: str = "", key_pem: str = "", passphrase: str = "", port: int = 22, known_hosts: str = "",
                 accept_new: bool = True, timeout: int = 20, sudo: bool = False, sudo_password: str = ""):
        self.host, self.user, self.password, self.key_pem, self.passphrase = host, user, password, key_pem, passphrase
        self.port, self.known_hosts, self.accept_new, self.timeout = int(port or 22), known_hosts, accept_new, timeout
        self.sudo, self.sudo_password = sudo, sudo_password
        self._c = None

    # ------------------------------------------------------------------------------------------------------ ligação
    def connect(self):
        if self._c is not None:
            return self._c
        import paramiko
        c = paramiko.SSHClient()
        kh = self.known_hosts
        if kh:
            os.makedirs(os.path.dirname(kh) or ".", exist_ok=True)
            if os.path.exists(kh):
                c.load_host_keys(kh)
        if self.accept_new:
            outer = self

            class AcceptNew(paramiko.MissingHostKeyPolicy):
                def missing_host_key(self, client, hostname, key):
                    client._host_keys.add(hostname, key.get_name(), key)
                    if outer.known_hosts:
                        client.save_host_keys(outer.known_hosts)
            c.set_missing_host_key_policy(AcceptNew())
        else:
            c.set_missing_host_key_policy(paramiko.RejectPolicy())
        pkey = _load_key(self.key_pem, self.passphrase) if self.key_pem else None
        try:
            c.connect(self.host, port=self.port, username=self.user, password=self.password or None, pkey=pkey, timeout=self.timeout, banner_timeout=self.timeout,
                      auth_timeout=self.timeout, allow_agent=False, look_for_keys=False)
        except paramiko.BadHostKeyException as exc:
            raise ConnectError(f"A chave SSH de {self.host} mudou (possível ataque ou reinstalação): apague a linha em {self.known_hosts or 'known_hosts'}.") from exc
        except paramiko.AuthenticationException as exc:
            raise AuthError(f"SSH: utilizador ou palavra-passe/chave recusados para {self.user}@{self.host}.") from exc
        except paramiko.SSHException as exc:
            msg = str(exc)
            if "not found in known_hosts" in msg or "Server" in msg and "known_hosts" in msg:
                raise ConnectError(f"Chave SSH de {self.host} desconhecida e a aceitação na 1.ª ligação está desligada (ANSIBLE_SSH_ACCEPT_NEW).") from exc
            raise ConnectError(f"SSH: {msg}") from exc
        except (socket.timeout, TimeoutError) as exc:
            raise ConnectError(f"SSH: tempo excedido a ligar a {self.host}:{self.port} (firewall/rede?).") from exc
        except OSError as exc:
            raise ConnectError(f"SSH: não foi possível ligar a {self.host}:{self.port}: {exc}") from exc
        self._c = c
        return c

    def close(self) -> None:
        if self._c is not None:
            self._c.close()
            self._c = None

    # ------------------------------------------------------------------------------------------------------ comandos
    def run(self, cmd: str, stdin: bytes | None = None, timeout: int = 300) -> Result:
        c = self.connect()
        if self.sudo:
            cmd = f"sudo -S -p '' sh -c {shlex.quote(cmd)}" if self.sudo_password else f"sudo -n sh -c {shlex.quote(cmd)}"
            stdin = (self.sudo_password + "\n").encode() + (stdin or b"") if self.sudo_password else stdin
        chan = c.get_transport().open_session()
        chan.settimeout(timeout)
        chan.exec_command(cmd)
        if stdin:
            chan.sendall(stdin)
        chan.shutdown_write()
        out, err, t0 = bytearray(), bytearray(), time.time()
        while True:
            got = False
            while chan.recv_ready():
                out += chan.recv(65536)
                got = True
            while chan.recv_stderr_ready():
                err += chan.recv_stderr(65536)
                got = True
            if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                break
            if time.time() - t0 > timeout:
                chan.close()
                return Result(124, bytes(out), bytes(err) + f"\nTempo excedido ({timeout}s)".encode())
            if not got:
                time.sleep(0.05)
        return Result(chan.recv_exit_status(), bytes(out), bytes(err))

    def put(self, local_path: str, remote_path: str) -> None:
        c = self.connect()
        try:
            sftp = c.open_sftp()
            try:
                sftp.put(local_path, remote_path)
            finally:
                sftp.close()
        except Exception:  # noqa: BLE001 - SFTP desativado: copia por «cat»
            with open(local_path, "rb") as fh:
                r = self.run(f"cat > {shlex.quote(remote_path)}", fh.read())
            if r.rc != 0:
                raise TransportError(f"Falha ao copiar para {remote_path}: {r.err.strip()}")

    def get(self, remote_path: str) -> bytes:
        c = self.connect()
        try:
            sftp = c.open_sftp()
            try:
                with sftp.open(remote_path, "rb") as fh:
                    return fh.read()
            finally:
                sftp.close()
        except Exception:  # noqa: BLE001
            r = self.run(f"cat {shlex.quote(remote_path)}")
            if r.rc != 0:
                raise TransportError(f"Falha ao ler {remote_path}: {r.err.strip()}")
            return r.stdout
