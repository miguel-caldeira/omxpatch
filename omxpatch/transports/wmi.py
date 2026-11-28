"""Transporte WMI/DCOM + SMB para Windows, SEM agente, SEM WinRM e SEM SSH (impacket).

* a execução usa o WMI sobre DCOM (``Win32_Process.Create``, TCP 135 + portas RPC dinâmicas);
* a entrada (stdin), a saída, o código de saída e os ficheiros seguem pela partilha administrativa (``C$``, TCP 445);
* o comando corre numa janela de sistema (cmd.exe), sob a conta usada na ligação; PowerShell é chamado por ``powershell.exe -EncodedCommand``.

Precisa de uma conta do grupo «Administradores» do equipamento (ou de domínio com esses direitos), das regras de firewall «Windows Management
Instrumentation (DCOM-In/WMI-In)» e «Partilha de Ficheiros e Impressoras (SMB-In)», e — para contas locais — de LocalAccountTokenFilterPolicy=1."""
from __future__ import annotations

import io
import re
import time
import uuid

from .base import AuthError, ConnectError, Result, Transport, TransportError

TEMP_DIR = r"C:\Windows\Temp"


def split_account(user: str, domain: str = "") -> tuple[str, str]:
    """«DOMINIO\\utilizador» ou «utilizador@dominio» → (utilizador, domínio); conta local → domínio vazio."""
    if "\\" in user:
        d, u = user.split("\\", 1)
        return u, d
    if "@" in user and not domain:
        u, d = user.rsplit("@", 1)
        return u, d
    return user, domain


def share_path(path: str) -> tuple[str, str]:
    """``C:\\Windows\\Temp\\x`` → (``C$``, ``Windows\\Temp\\x``)."""
    m = re.match(r"^([A-Za-z]):[\\/](.*)$", path)
    if not m:
        raise TransportError(f"Caminho Windows inválido (esperado C:\\…): {path}")
    return m.group(1).upper() + "$", m.group(2).replace("/", "\\")


def _classify(exc: Exception, host: str) -> TransportError:
    """Traduz as exceções (variadas) do impacket para erros com causa e remédio."""
    msg = str(exc)
    low = msg.lower()
    if any(k in low for k in ("logon_failure", "logon failure", "wrong_password", "unknown user", "account_restriction", "password_expired", "account_disabled", "account_locked")):
        return AuthError(f"Windows: utilizador ou palavra-passe recusados em {host} ({msg.strip()[:120]}). Use DOMINIO\\utilizador para contas de domínio.")
    if any(k in low for k in ("access_denied", "access denied", "rpc_s_access_denied", "e_accessdenied")):
        return AuthError(f"Windows: acesso negado em {host} — a conta tem de ser administrador local; para contas locais ative LocalAccountTokenFilterPolicy=1; "
                         "verifique as permissões DCOM/WMI (grupo «Utilizadores COM distribuídos»).")
    if any(k in low for k in ("connection refused", "timed out", "timeout", "no route", "unreachable", "name or service not known", "nodename nor servname", "network is unreachable",
                              "connection reset", "errno 111", "errno 110", "errno 113")):
        return ConnectError(f"Windows: sem ligação a {host} — confirme o nome/IP e a firewall: TCP 135 (RPC/DCOM), 445 (SMB) e as portas RPC dinâmicas 49152–65535 "
                            "(regras «Windows Management Instrumentation» e «Partilha de Ficheiros e Impressoras»). " + msg.strip()[:120])
    return TransportError(f"Windows (WMI/SMB) em {host}: {msg.strip()[:300]}")


class WMITransport(Transport):
    kind = "wmi"
    shell = "powershell"

    def __init__(self, host: str, user: str, password: str, domain: str = "", timeout: int = 30, smb_port: int = 445):
        self.host = host
        self.user, self.domain = split_account(user, domain)
        self.password, self.timeout, self.smb_port = password, timeout, int(smb_port or 445)
        self._smb = self._dcom = self._proc = self._services = None

    # ------------------------------------------------------------------------------------------------------ ligação
    def connect(self):
        if self._proc is not None:
            return self
        try:
            from impacket.dcerpc.v5.dcom import wmi
            from impacket.dcerpc.v5.dcomrt import DCOMConnection
            from impacket.dcerpc.v5.dtypes import NULL
            from impacket.smbconnection import SMBConnection
        except ImportError as exc:
            raise TransportError("Falta a biblioteca «impacket» (necessária para o WMI): sudo /opt/omxpatch/venv/bin/omxpatch ansible-doctor --fix") from exc
        try:
            smb = SMBConnection(self.host, self.host, sess_port=self.smb_port, timeout=self.timeout)
            smb.login(self.user, self.password, self.domain)
            self._smb = smb
            dcom = DCOMConnection(self.host, self.user, self.password, self.domain, "", "", None, oxidResolver=True, doKerberos=False)
            self._dcom = dcom
            iface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            login = wmi.IWbemLevel1Login(iface)
            self._services = login.NTLMLogin("//./root/cimv2", NULL, NULL)
            login.RemRelease()
            self._proc, _ = self._services.GetObject("Win32_Process")
        except TransportError:
            raise
        except Exception as exc:  # noqa: BLE001 - o impacket levanta muitos tipos
            self.close()
            raise _classify(exc, self.host) from exc
        return self

    def close(self) -> None:
        for obj, meth in ((self._dcom, "disconnect"), (self._smb, "logoff")):
            try:
                if obj is not None:
                    getattr(obj, meth)()
            except Exception:  # noqa: BLE001
                pass
        self._smb = self._dcom = self._proc = self._services = None

    # ------------------------------------------------------------------------------------------------------ ficheiros (SMB)
    def _write(self, path: str, data: bytes) -> None:
        share, rel = share_path(path)
        bio = io.BytesIO(data)
        self._smb.putFile(share, rel, bio.read)

    def _read(self, path: str) -> bytes | None:
        share, rel = share_path(path)
        buf = io.BytesIO()
        try:
            self._smb.getFile(share, rel, buf.write)
        except Exception as exc:  # noqa: BLE001
            low = str(exc).lower()
            if "not_found" in low or "no_such_file" in low or "name_not_found" in low or "path_not_found" in low:
                return None
            raise _classify(exc, self.host) from exc
        return buf.getvalue()

    def _delete(self, *paths: str) -> None:
        for p in paths:
            try:
                share, rel = share_path(p)
                self._smb.deleteFile(share, rel)
            except Exception:  # noqa: BLE001
                pass

    def put(self, local_path: str, remote_path: str) -> None:
        self.connect()
        try:
            with open(local_path, "rb") as fh:
                self._write(remote_path, fh.read())
        except TransportError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise _classify(exc, self.host) from exc

    def get(self, remote_path: str) -> bytes:
        self.connect()
        data = self._read(remote_path)
        if data is None:
            raise TransportError(f"Ficheiro inexistente em {self.host}: {remote_path}")
        return data

    # ------------------------------------------------------------------------------------------------------ comandos (WMI)
    def run(self, cmd: str, stdin: bytes | None = None, timeout: int = 300) -> Result:
        """Executa ``cmd`` (linha de comandos do cmd.exe) e devolve rc/stdout/stderr. O stdin segue por ficheiro (``< ficheiro``)."""
        self.connect()
        tok = uuid.uuid4().hex[:16]
        base = rf"{TEMP_DIR}\omx-{tok}"
        f_cmd, f_in, f_out, f_err, f_rc, f_rct = (f"{base}.{x}" for x in ("cmd", "in", "out", "err", "rc", "rc.tmp"))
        batch = ("@echo off\r\nchcp 65001 >nul\r\n"
                 f"{cmd.replace('%', '%%')} < {f_in if stdin else 'NUL'} > {f_out} 2> {f_err}\r\n"
                 f"echo %ERRORLEVEL% > {f_rct}\r\nmove /Y {f_rct} {f_rc} >nul\r\n")
        try:
            if stdin:
                self._write(f_in, stdin)
            self._write(f_cmd, batch.encode("utf-8"))
            try:
                self._proc.Create(rf"cmd.exe /Q /c {f_cmd}", TEMP_DIR, None)
            except Exception as exc:  # noqa: BLE001
                raise _classify(exc, self.host) from exc
            t0, wait = time.time(), 0.15
            rc_raw = None
            while rc_raw is None:
                rc_raw = self._read(f_rc)
                if rc_raw is not None:
                    break
                if time.time() - t0 > timeout:
                    return Result(124, self._read(f_out) or b"", (self._read(f_err) or b"") + f"\nTempo excedido ({timeout}s)".encode())
                time.sleep(wait)
                wait = min(wait * 1.5, 1.0)
            try:
                rc = int(rc_raw.decode("ascii", "ignore").strip() or "1")
            except ValueError:
                rc = 1
            return Result(rc, self._read(f_out) or b"", self._read(f_err) or b"")
        finally:
            self._delete(f_cmd, f_in, f_out, f_err, f_rc, f_rct)

    def query(self, wql: str) -> list[dict]:
        """Consulta WMI (diagnóstico): devolve as propriedades dos objetos."""
        self.connect()
        out = []
        try:
            enum = self._services.ExecQuery(wql)
            while True:
                try:
                    obj = enum.Next(0xFFFFFFFF, 1)[0]
                except Exception:  # noqa: BLE001 - fim da enumeração
                    break
                out.append({k: v.get("value") if isinstance(v, dict) else v for k, v in obj.getProperties().items()})
        except Exception as exc:  # noqa: BLE001
            raise _classify(exc, self.host) from exc
        return out
