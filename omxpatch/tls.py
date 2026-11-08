"""HTTPS do OMXPatch: certificado autoassinado e contexto TLS (mínimo TLS 1.2).

No primeiro arranque é gerado um certificado autoassinado válido por ``TLS_DAYS`` (2 anos por omissão)
para o nome ``TLS_HOSTNAME`` (``omxpatch.oramix.local``), ``localhost`` e os endereços IP da máquina, para
que a plataforma responda tanto pelo nome como pelo IP. O certificado é renovado automaticamente quando
faltam menos de 30 dias ou quando os IPs da máquina deixam de estar incluídos. Um certificado próprio
(ex.: da PKI da organização) é indicado em ``[server] tls_cert`` / ``tls_key`` e nunca é substituído.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

RENEW_DAYS = 30
MARK = "OMXPatch self-signed"


PROFILES = {
    "console": {"prefix": "TLS_", "file": "omxpatch", "default": "omxpatch.oramix.local", "label": "consola (porta de gestão)"},
    "agent": {"prefix": "AGENT_TLS_", "file": "omxpatchcli", "default": "omxpatchcli.oramix.local", "label": "agentes → consola"},
}


def paths(cfg, profile: str = "console") -> tuple[Path, Path, bool]:
    """(certificado, chave, gerido pelo OMXPatch). Dois certificados independentes: ``console`` e ``agent``."""
    pr = PROFILES[profile]
    if cfg.get(pr["prefix"] + "CERT") and cfg.get(pr["prefix"] + "KEY"):
        return Path(cfg[pr["prefix"] + "CERT"]), Path(cfg[pr["prefix"] + "KEY"]), False
    folder = Path(cfg["DATA_DIR"]) / "tls"
    return folder / f"{pr['file']}.crt", folder / f"{pr['file']}.key", True


def local_ips() -> list[str]:
    """Endereços IP desta máquina (sem loopback): resolução do nome da máquina e interface de saída."""
    found: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.add(info[4][0].split("%")[0])
    except OSError:
        pass
    for family, probe in ((socket.AF_INET, ("192.0.2.1", 80)), (socket.AF_INET6, ("2001:db8::1", 80))):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as s:   # não envia tráfego: só escolhe a rota
                s.connect(probe)
                found.add(s.getsockname()[0].split("%")[0])
        except OSError:
            pass
    out = []
    for ip in sorted(found):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not (addr.is_loopback or addr.is_link_local or addr.is_unspecified):
            out.append(str(addr))
    return out


def urlsplit_host(url: str) -> str:
    from urllib.parse import urlsplit
    return urlsplit(url.strip()).hostname or ""


def wanted_names(cfg, profile: str = "console") -> tuple[list[str], list[str]]:
    pr = PROFILES[profile]
    host = str(cfg.get(pr["prefix"] + "HOSTNAME") or pr["default"]).lower()
    dns = [host, "localhost"]
    short = host.split(".")[0]
    if short and short not in dns:
        dns.append(short)
    extra = [h.strip().lower() for h in str(cfg.get(pr["prefix"] + "EXTRA_NAMES") or "").split(",") if h.strip()]
    ips = ["127.0.0.1", "::1"] + local_ips()
    if profile == "agent":                       # IPs publicados aos agentes (modo «só IP»): também no SAN
        for raw in (str(cfg.get("AGENT_SERVER_IP") or "").split(",") + [urlsplit_host(u) for u in str(cfg.get("AGENT_SERVER_URLS") or "").split(",")]):
            raw = raw.strip().strip("[]")
            try:
                ipaddress.ip_address(raw)
                ips.append(raw)
            except ValueError:
                pass
    for e in extra:
        try:
            ipaddress.ip_address(e)
            ips.append(e)
        except ValueError:
            dns.append(e)
    return list(dict.fromkeys(dns)), list(dict.fromkeys(ips))


def generate(cfg, cert_path: Path, key_path: Path, profile: str = "console") -> dict:
    dns, ips = wanted_names(cfg, profile)
    days = int(cfg.get("TLS_DAYS", 730))
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns[0]),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OMXPatch"),
                      x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, MARK)])
    now = datetime.now(timezone.utc)
    san = [x509.DNSName(d) for d in dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, content_commitment=False,
                                         data_encipherment=False, key_agreement=True, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return info(cert_path)


def info(cert_path: Path) -> dict:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns = san.get_values_for_type(x509.DNSName)
        ips = [str(i) for i in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        dns, ips = [], []
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    ou = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)]
    return {"subject": cert.subject.rfc4514_string(), "dns": dns, "ips": ips, "not_before": not_before,
            "not_after": not_after, "days_left": (not_after - datetime.now(timezone.utc)).days,
            "self_signed": cert.issuer == cert.subject, "managed": MARK in ou,
            "sha256": cert.fingerprint(hashes.SHA256()).hex(":").upper(),
            "sha1": cert.fingerprint(hashes.SHA1()).hex(":").upper(),   # nosec B303 - o «Thumbprint» do Windows é SHA-1; só para identificar
            "path": str(cert_path)}


def ensure(cfg, log=print, force: bool = False, profile: str = "console") -> dict:
    """Garante um certificado válido; gera/renova o autoassinado gerido pelo OMXPatch quando necessário."""
    cert_path, key_path, managed = paths(cfg, profile)
    if not managed:
        if not cert_path.is_file() or not key_path.is_file():
            raise FileNotFoundError(f"Certificado/chave TLS não encontrados: {cert_path} / {key_path}")
        return info(cert_path)
    reason = "pedido" if force else ""
    if not reason and not (cert_path.is_file() and key_path.is_file()):
        reason = "não existe"
    if not reason:
        current = info(cert_path)
        dns, ips = wanted_names(cfg, profile)
        if current["days_left"] < RENEW_DAYS and profile == "agent" and _promote(cfg, profile, log):
            return info(cert_path)
        elif current["days_left"] < RENEW_DAYS and profile == "agent" and next_paths(cfg, profile)[0].is_file():
            return current           # seguinte ainda em período de publicação: os agentes fixados ignoram a validade do atual
        elif current["days_left"] < RENEW_DAYS:
            reason = f"expira em {current['days_left']} dias"
        elif profile != "agent" and (not set(dns) <= set(current["dns"]) or not set(ips) <= set(current["ips"])):
            # No perfil dos agentes a confiança vem da impressão digital (thumbprint), não dos nomes/IPs do certificado:
            # regenerá-lo por uma mudança de IP faria mudar o thumbprint e deixaria toda a frota sem ligação.
            reason = "nomes/IPs da máquina alterados"
        else:
            return current
    data = generate(cfg, cert_path, key_path, profile)
    log(f"Certificado TLS {PROFILES[profile]['label']} autoassinado gerado ({reason}): {', '.join(data['dns'] + data['ips'])}; válido até "
        f"{data['not_after']:%Y-%m-%d}; SHA-256 {data['sha256']}")
    return data


PREPARE_DAYS = 60        # o certificado seguinte é criado (e o seu thumbprint publicado aos agentes) quando faltam menos de 60 dias
ROTATE_GRACE_DAYS = 7    # o seguinte só substitui o atual depois de publicado há pelo menos 7 dias (agentes que contactam diariamente)


def next_paths(cfg, profile: str = "agent") -> tuple[Path, Path]:
    cert, key, _ = paths(cfg, profile)
    return cert.with_name(cert.stem + ".next.crt"), key.with_name(key.stem + ".next.key")


def agent_pins(cfg, profile: str = "agent") -> list[str]:
    """Impressões digitais SHA-256 (hex) a publicar aos agentes: o certificado atual e, se já preparado, o seguinte."""
    cert, _, managed = paths(cfg, profile)
    out = []
    ncert, _nk = next_paths(cfg, profile)
    for c in (cert, ncert):
        if c.is_file():
            out.append(info(c)["sha256"].replace(":", "").lower())
    return out if managed else out[:1]


def maintain(cfg, log=print, profile: str = "agent") -> str:
    """Tarefa periódica (worker): prepara o certificado seguinte quando o atual se aproxima do fim. Devolve o que fez."""
    cert, key, managed = paths(cfg, profile)
    ncert, nkey = next_paths(cfg, profile)
    if not managed or not cert.is_file():
        return ""
    if info(cert)["days_left"] < PREPARE_DAYS and not ncert.is_file():
        data = generate(cfg, ncert, nkey, profile)
        log(f"Certificado {PROFILES[profile]['label']} seguinte preparado (thumbprint publicado aos agentes): SHA-256 {data['sha256']}")
        return "prepared"
    return ""


def _promote(cfg, profile: str, log) -> bool:
    cert, key, _ = paths(cfg, profile)
    ncert, nkey = next_paths(cfg, profile)
    if not (ncert.is_file() and nkey.is_file()):
        return False
    age_days = (datetime.now(timezone.utc).timestamp() - ncert.stat().st_mtime) / 86400
    if age_days < ROTATE_GRACE_DAYS:
        return False
    os.replace(ncert, cert)
    os.replace(nkey, key)
    log(f"Certificado {PROFILES[profile]['label']} substituído pelo seguinte (publicado há {age_days:.0f} dias)")
    return True


def context(cfg, profile: str = "console") -> ssl.SSLContext:
    cert_path, key_path, _ = paths(cfg, profile)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3 if str(cfg.get("TLS_MIN_VERSION")) == "1.3" else ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_CIPHER_SERVER_PREFERENCE
    # TLS 1.2: só suites AEAD com sigilo perfeito (ECDHE); o TLS 1.3 usa sempre suites seguras
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!3DES:!RC4:!SHA1")
    ctx.load_cert_chain(str(cert_path), str(key_path))
    return ctx
