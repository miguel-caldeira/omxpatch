"""Windows simulado para testar o transporte WMI sem um Windows: faz-se passar por «impacket» (SMB + DCOM/WMI) e «executa» os ficheiros .cmd que o
transporte escreve na partilha, interpretando só o que o transporte gera (redireções e «move») — os comandos do teste são comandos de shell POSIX."""
from __future__ import annotations

import re
import subprocess
import sys
import types


class SessionError(Exception):
    pass


class FakeWindows:
    def __init__(self, user="admin", password="pw", domain="", hang=False, deny_dcom=False):
        self.user, self.password, self.domain, self.hang, self.deny_dcom = user, password, domain, hang, deny_dcom
        self.files: dict[tuple[str, str], bytes] = {}
        self.created: list[str] = []
        self.queries: list[str] = []

    @staticmethod
    def key(share, rel):
        return share.upper(), rel.replace("/", "\\").lower()

    def resolve(self, path):          # C:\Windows\Temp\x -> chave
        return self.key(path[0].upper() + "$", path[3:])


def install(monkeypatch, win: FakeWindows):
    def mod(name, **attrs):
        m = types.ModuleType(name)
        m.__dict__.update(attrs)
        if monkeypatch is None:
            sys.modules[name] = m            # instalação global (processos do Ansible)
        else:
            monkeypatch.setitem(sys.modules, name, m)
        return m

    class SMBConnection:
        def __init__(self, host, host2, sess_port=445, timeout=30):
            self.host = host

        def login(self, user, pw, domain=""):
            if user != win.user or pw != win.password:
                raise SessionError("SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid.)")

        def getFile(self, share, path, cb):
            k = win.key(share, path)
            if k not in win.files:
                raise SessionError("SMB SessionError: STATUS_OBJECT_NAME_NOT_FOUND(The object name is not found.)")
            cb(win.files[k])

        def putFile(self, share, path, cb):
            data = b""
            while True:
                chunk = cb(65536)
                if not chunk:
                    break
                data += chunk
            win.files[win.key(share, path)] = data

        def deleteFile(self, share, path):
            win.files.pop(win.key(share, path), None)

        def logoff(self):
            pass

    class Proc:
        def Create(self, command, cwd, extra):
            win.created.append(command)
            if win.hang:
                return
            m = re.match(r"cmd\.exe /Q /c (\S+)$", command)
            batch = win.files[win.resolve(m.group(1))].decode("utf-8")
            for line in batch.splitlines():
                mm = re.match(r"^(?P<cmd>.*) < (?P<inp>\S+) > (?P<out>\S+) 2> (?P<err>\S+)$", line)
                if mm:
                    stdin = b"" if mm["inp"] == "NUL" else win.files[win.resolve(mm["inp"])]
                    command = "echo 'Microsoft Windows [Version 10.0.20348.1]'" if mm["cmd"].strip() == "ver" else mm["cmd"].replace("%%", "%")
                    r = subprocess.run(command, shell=True, input=stdin, capture_output=True, executable="/bin/sh")
                    win.files[win.resolve(mm["out"])], win.files[win.resolve(mm["err"])] = r.stdout, r.stderr
                    rc = r.returncode
                mv = re.match(r"^move /Y (\S+) (\S+) >nul$", line)
                if mv:
                    win.files[win.resolve(mv.group(2))] = win.files.pop(win.resolve(mv.group(1)))
                echo = re.match(r"^echo %ERRORLEVEL% > (\S+)$", line)
                if echo:
                    win.files[win.resolve(echo.group(1))] = f"{rc} \r\n".encode()

    class Obj:
        def getProperties(self):
            return {"Caption": {"value": "Microsoft Windows Server 2022 Standard"}, "Version": {"value": "10.0.20348"}, "CSName": {"value": "SRV-FAKE"}}

    class Enum:
        def __init__(self):
            self.done = False

        def Next(self, timeout, count):
            if self.done:
                raise Exception("WBEM_S_FALSE")
            self.done = True
            return [Obj()]

    class Services:
        def GetObject(self, name):
            return Proc(), None

        def ExecQuery(self, q):
            win.queries.append(q)
            return Enum()

    class IWbemLevel1Login:
        def __init__(self, iface):
            pass

        def NTLMLogin(self, ns, a, b):
            return Services()

        def RemRelease(self):
            pass

    class DCOMConnection:
        def __init__(self, host, user, pw, domain, lm, nt, aes, oxidResolver=True, doKerberos=False):
            if win.deny_dcom:
                raise Exception("DCOM SessionError: rpc_s_access_denied")
            if user != win.user or pw != win.password:
                raise Exception("DCOM: STATUS_LOGON_FAILURE")

        def CoCreateInstanceEx(self, clsid, iid):
            return object()

        def disconnect(self):
            pass

    mod("impacket")
    mod("impacket.smbconnection", SMBConnection=SMBConnection, SessionError=SessionError)
    mod("impacket.dcerpc")
    mod("impacket.dcerpc.v5")
    wmi = mod("impacket.dcerpc.v5.dcom.wmi", CLSID_WbemLevel1Login="clsid", IID_IWbemLevel1Login="iid", IWbemLevel1Login=IWbemLevel1Login)
    mod("impacket.dcerpc.v5.dcom", wmi=wmi)
    mod("impacket.dcerpc.v5.dcomrt", DCOMConnection=DCOMConnection)
    mod("impacket.dcerpc.v5.dtypes", NULL=None)
    return win
