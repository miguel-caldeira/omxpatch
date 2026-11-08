"""Cliente HTTPS do agente, **sem dependências** (só biblioteca padrão): o agente corre em Python 3.7+ (testado de 3.8 a 3.13).

O servidor de agentes (porta 4444) usa por omissão um certificado autoassinado (``omxpatchcli.oramix.local``): o agente
fixa-o pela impressão digital (``pin_sha256``: SHA-256, ou o *thumbprint* SHA-1 do Windows) ou valida-o contra um CA da organização
(``ca_file``). Com a impressão digital fixada o nome do servidor é irrelevante: o agente pode falar com a consola **só por IP**
(``https://10.0.0.5:4444``), sem DNS, ficheiro hosts nem CA. ``server_url`` aceita vários endereços separados por vírgula (ordem de preferência)."""
from __future__ import annotations

import hashlib
import http.client
import json as jsonlib
import ssl
import time
from urllib.parse import urlsplit

from . import __version__


class ServerError(RuntimeError):
    pass


class PinError(ServerError):
    pass


class Response:
    def __init__(self, status: int, headers: dict, body: bytes):
        self.status_code, self.headers, self.body = status, headers, body

    def json(self):
        return jsonlib.loads(self.body.decode("utf-8")) if self.body else None

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise ServerError(f"HTTP {self.status_code}")


def normalize_pin(pin: str) -> str:
    return (pin or "").replace(":", "").replace(" ", "").strip().lower()


def pin_algorithm(pin: str):
    """64 hex = SHA-256 (recomendado); 40 hex = SHA-1 (o «Thumbprint» do Windows)."""
    return {64: hashlib.sha256, 40: hashlib.sha1}.get(len(pin))  # nosec B324 - SHA-1 só como identificador do certificado fixado


def pin_matches(der: bytes, pin: str) -> bool:
    algo = pin_algorithm(pin)
    return algo is not None and algo(der).hexdigest() == pin


def is_ip_host(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address((host or "").strip("[]").split("%")[0])
        return True
    except ValueError:
        return False


def split_urls(value: str) -> list:
    return [u.strip().rstrip("/") for u in str(value or "").split(",") if u.strip()]


class StdSession:
    """Sessão HTTP mínima (``request`` / ``download``) com *pinning* do certificado."""

    def __init__(self, pin_sha256: str = "", ca_file: str = ""):
        self.pin, self.ca_file = normalize_pin(pin_sha256), ca_file
        if self.pin and pin_algorithm(self.pin) is None:
            raise PinError("Impressão digital inválida: use SHA-256 (64 hex) ou o thumbprint SHA-1 (40 hex)")

    def _connect(self, url: str, timeout: int):
        u = urlsplit(url)
        host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
        if u.scheme != "https":
            return http.client.HTTPConnection(host, port, timeout=timeout), u
        if self.pin:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE        # a confiança vem da impressão digital
        else:
            if is_ip_host(host) and not self.ca_file:
                raise PinError("Ligação por IP sem impressão digital (pin_sha256) nem CA: não há forma de confiar no servidor")
            ctx = ssl.create_default_context(cafile=self.ca_file or None)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        conn.connect()
        if self.pin:
            der = conn.sock.getpeercert(binary_form=True)
            if not pin_matches(der, self.pin):
                conn.close()
                raise PinError("O certificado do servidor não corresponde à impressão digital esperada (pin_sha256)")
        return conn, u

    def request(self, method: str, url: str, json=None, timeout: int = 60, headers: dict | None = None) -> Response:
        conn, u = self._connect(url, timeout)
        try:
            h = dict(headers or {})
            body = None
            if json is not None:
                body = jsonlib.dumps(json).encode("utf-8")
                h["Content-Type"] = "application/json"
            conn.request(method, (u.path or "/") + (f"?{u.query}" if u.query else ""), body=body, headers=h)
            r = conn.getresponse()
            return Response(r.status, {k.lower(): v for k, v in r.getheaders()}, r.read())
        except (OSError, http.client.HTTPException) as exc:
            raise ServerError(str(exc)) from exc
        finally:
            conn.close()

    def download(self, url: str, dest, headers: dict | None = None, bandwidth_kbps: int = 0, timeout: int = 300) -> tuple[int, str]:
        """Grava o corpo em ``dest`` com limite de largura de banda; devolve (estado, SHA-256)."""
        conn, u = self._connect(url, timeout)
        h = hashlib.sha256()
        try:
            conn.request("GET", u.path + (f"?{u.query}" if u.query else ""), headers=dict(headers or {}))
            r = conn.getresponse()
            if r.status != 200:
                return r.status, ""
            with open(dest, "wb") as fh:
                while True:
                    chunk = r.read(64 * 1024)
                    if not chunk:
                        break
                    fh.write(chunk)
                    h.update(chunk)
                    if bandwidth_kbps > 0:
                        time.sleep(len(chunk) * 8 / (bandwidth_kbps * 1000))
            return 200, h.hexdigest()
        except (OSError, http.client.HTTPException) as exc:
            raise ServerError(str(exc)) from exc
        finally:
            conn.close()


class Client:
    def __init__(self, cfg: dict, session=None):
        self.cfg = cfg
        self.bases = split_urls(cfg["server_url"])
        self.base = self.bases[0]
        self.s = session or StdSession(cfg.get("pin_sha256", ""), cfg.get("ca_file", ""))
        self.headers = {"User-Agent": f"OMXPatchAgent/{__version__}"}
        if cfg.get("agent_key"):
            self.headers["Authorization"] = f"Bearer {cfg['agent_key']}"

    def _req(self, method: str, path: str, retries: int = 3, timeout: int = 60, **kw) -> Response:
        last = None
        for i in range(retries):
            for base in [self.base] + [b for b in self.bases if b != self.base]:     # endereço atual primeiro, depois os alternativos
                try:
                    r = self.s.request(method, base + path, timeout=timeout, headers=self.headers, **kw)
                    if r.status_code >= 500:
                        raise ServerError(f"HTTP {r.status_code}")
                    self.base = base
                    return r
                except PinError:
                    raise                               # um certificado diferente nunca se resolve a repetir
                except ServerError as exc:
                    last = exc
            time.sleep(min(2 ** i, 15))
        raise ServerError(str(last))

    def enroll(self, token: str, info: dict) -> dict:
        r = self._req("POST", "/agent/v1/enroll", json={"token": token, **info})
        if r.status_code != 201:
            try:
                msg = r.json().get("error", f"HTTP {r.status_code}")
            except (ValueError, AttributeError):
                msg = f"HTTP {r.status_code}"
            raise ServerError(msg)
        return r.json()

    def poll(self) -> dict:
        r = self._req("POST", "/agent/v1/poll", json={"version": __version__})
        if r.status_code == 401:
            raise ServerError("Chave de agente inválida ou revogada")
        r.raise_for_status()
        return r.json()

    def inventory(self, report: dict) -> dict:
        r = self._req("POST", "/agent/v1/inventory", json=report, timeout=300)
        r.raise_for_status()
        return r.json()

    def task_start(self, task_id: int) -> None:
        self._req("POST", f"/agent/v1/tasks/{task_id}/start", json={}, retries=1)

    def task_result(self, task_id: int, report: dict) -> dict:
        r = self._req("POST", f"/agent/v1/tasks/{task_id}/result", json=report, timeout=120)
        r.raise_for_status()
        return r.json()

    def download(self, patch_id: int, dest, expected_sha256: str, bandwidth_kbps: int = 0) -> str:
        """Transfere o pacote e verifica o SHA-256 antes de o usar."""
        status, digest = self.s.download(f"{self.base}/agent/v1/package/{patch_id}", dest, self.headers, bandwidth_kbps)
        if status != 200:
            raise ServerError(f"Pacote indisponível (HTTP {status})")
        if expected_sha256 and digest != expected_sha256.lower():
            raise ServerError("SHA-256 do pacote não corresponde ao esperado — transferência rejeitada")
        return digest
