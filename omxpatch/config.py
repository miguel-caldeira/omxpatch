"""Configuração do OMXPatch (mesmo modelo do OMXVuln).

Ordem de precedência (maior para menor):
  1. variáveis de ambiente ``OMXPATCH_<CHAVE>`` (ex.: ``OMXPATCH_OMXVULN_URL``)
  2. ficheiro TOML (``OMXPATCH_CONFIG`` ou ``omxpatch.toml`` no diretório de dados / atual)
  3. valores por omissão definidos em ``DEFAULTS``

Os segredos (tokens do OMXVuln/OMXGRC, API de IA, SMTP, chave de sessão) vêm do ambiente ou do ficheiro de
configuração; os das integrações por organização ficam cifrados (Fernet) na base de dados.
"""
from __future__ import annotations

import os
import secrets
import sys
from datetime import timedelta
from pathlib import Path

try:  # Python >= 3.11
    import tomllib
except ModuleNotFoundError:  # Python 3.9/3.10
    import tomli as tomllib

APP_NAME = "OMXPatch"
OVERRIDES_NAME = "omxpatch.overrides.toml"

DEFAULTS: dict[str, object] = {
    # Servidor / integração em NGINX ou IIS
    "HOST": "", "PORT": 4434, "TLS_ENABLED": True,   # PORT: consola de gestão (HTTPS)
    "AGENT_PORT": 4444,                # agentes → consola (HTTPS, certificado próprio)
    "AGENT_TLS_HOSTNAME": "omxpatchcli.oramix.local", "AGENT_TLS_EXTRA_NAMES": "", "AGENT_TLS_CERT": "", "AGENT_TLS_KEY": "",
    "AGENT_SERVER_IP": "",             # IP do servidor: os scripts de instalação acrescentam-no ao ficheiro hosts dos postos
    "AGENT_BASE_URL": "",
    "AGENT_ADDRESS_MODE": "name",      # name = os agentes usam o nome (DNS/hosts); ip = só o IP do servidor + thumbprint do certificado
    "AGENT_SERVER_URLS": "",           # endereços alternativos publicados aos agentes (vírgula), p.ex. https://10.0.0.5:4444,https://10.0.1.5:4444
    "TLS_ENABLED": True, "TLS_HOSTNAME": "omxpatch.oramix.local",
    "TLS_EXTRA_NAMES": "", "TLS_CERT": "", "TLS_KEY": "", "TLS_DAYS": 730, "TLS_MIN_VERSION": "1.2",
    "URL_PREFIX": "", "TRUSTED_PROXIES": 1, "SESSION_COOKIE_SECURE": False, "SESSION_HOURS": 8,
    "FRAME_ANCESTORS": "'self'", "SECRET_KEY": "", "DATABASE_URL": "", "MAX_UPLOAD_MB": 500, "THREADS": 8,
    "BASE_URL": "",
    # Worker (sincronização de inteligência, correlação, campanhas, anéis, validação, modo autónomo)
    "EMBEDDED_WORKER": True, "WORKER_POLL_SECONDS": 15,
    "INTEL_SYNC_HOURS": 24,           # NVD / KEV / EPSS / MITRE / feeds
    "CORRELATE_MINUTES": 15,
    "PASSWORD_MIN_LENGTH": 12, "MFA_ISSUER": "OMXPatch", "LOGIN_MAX_FAILURES": 5, "LOGIN_LOCK_MINUTES": 15,
    "ALLOW_LOOPBACK_OUTBOUND": False,
    "LICENSE_GRACE_DAYS": 15, "LICENSE_WARN_DAYS": 30,
    # Agentes (clientes Windows / Linux / macOS)
    "AGENT_HEARTBEAT_SECONDS": 300,   # intervalo de contacto pedido aos agentes
    "AGENT_OFFLINE_MINUTES": 20,      # sem contacto durante este tempo = offline
    "AGENT_TASK_TIMEOUT_MINUTES": 120,
    "AGENT_PACKAGE_DIR": "",          # vazio: <dados>/packages (repositório local de patches)
    "BANDWIDTH_DEFAULT_KBPS": 0,      # 0 = sem limite (por campanha pode ser limitado)
    # Ansible (articulação de toda a solução; também modo sem agente)
    "ANSIBLE_ENABLED": True, "ANSIBLE_PLAYBOOK": "ansible-playbook",
    "ANSIBLE_DIR": "",                # vazio: pasta ansible/ do pacote
    "ANSIBLE_INVENTORY": "",          # vazio: inventário gerado a partir dos ativos sem agente
    "ANSIBLE_TIMEOUT_MINUTES": 90,
    # Inteligência de vulnerabilidades
    "KEV_ENABLED": True,
    "KEV_URL": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "EPSS_ENABLED": True, "EPSS_URL": "https://api.first.org/data/v1/epss",
    "NVD_ENABLED": True, "NVD_URL": "https://services.nvd.nist.gov/rest/json/cves/2.0", "NVD_API_KEY": "",
    "NVD_BUDGET": 40,                 # CVE consultados por execução
    "MITRE_ENABLED": True, "MITRE_URL": "https://cveawg.mitre.org/api/cve",
    "THREAT_FEEDS": "",               # URLs (um por linha) de feeds JSON {"cve": "...", "malware": [...], "exploit": "..."}
    "VENDOR_ADVISORIES": "",          # URLs de avisos de fabricantes (CSAF/JSON simples)
    # OMXVuln (ferramenta irmã) — origem de vulnerabilidades e destino do estado de remediação
    "OMXVULN_URL": "", "OMXVULN_TOKEN": "", "OMXVULN_TENANT_ID": 0, "OMXVULN_VERIFY_TLS": True,
    "OMXVULN_SYNC_MINUTES": 30, "OMXVULN_PUSH_STATUS": True, "OMXVULN_RESCAN": True,
    # OMXGRC (ferramenta irmã) — evidências, indicadores e conformidade
    "OMXGRC_URL": "", "OMXGRC_TOKEN": "", "OMXGRC_VERIFY_TLS": True, "OMXGRC_PUSH_MINUTES": 60,
    "OMXGRC_EVIDENCE_PATH": "/api/v1/evidence", "OMXGRC_METRICS_PATH": "/api/v1/metrics",
    # IA (Módulo 9). Sem chave, o planeador determinístico funciona na mesma; a IA só interpreta a pergunta e narra.
    "AI_ENABLED": False, "AI_API_KEY": "", "AI_URL": "https://api.anthropic.com/v1/messages",
    "AI_MODEL": "claude-sonnet-5-5", "AI_TIMEOUT": 60,
    # Anéis de teste (Módulo 7) — critérios de promoção por omissão
    "RING_MIN_SUCCESS": 95.0, "RING_MAX_CRASH": 1.0, "RING_MIN_UX": 80.0, "RING_MIN_DEVICES": 1,
    "RING_SOAK_HOURS": 24,
    # Notificações
    "SMTP_HOST": "", "SMTP_PORT": 587, "SMTP_USERNAME": "", "SMTP_PASSWORD": "", "SMTP_STARTTLS": True,
    "SMTP_SSL": False, "SMTP_TIMEOUT": 30, "MAIL_FROM": "omxpatch@localhost", "NOTIFY_ASYNC": True,
    # SIEM (syslog) — auditoria e eventos de remediação
    "SYSLOG_ENABLED": False, "SYSLOG_HOST": "", "SYSLOG_PORT": 514, "SYSLOG_PROTOCOL": "udp",
    "SYSLOG_FORMAT": "rfc5424", "SYSLOG_FACILITY": 16, "SYSLOG_VERIFY_TLS": True,
}

_TOML_SECTIONS = {
    "server": "", "security": "", "database": "", "worker": "WORKER_", "agents": "AGENT_", "ansible": "ANSIBLE_",
    "omxvuln": "OMXVULN_", "omxgrc": "OMXGRC_", "ai": "AI_", "rings": "RING_", "nvd": "NVD_", "kev": "KEV_",
    "epss": "EPSS_", "mitre": "MITRE_", "intel": "INTEL_", "smtp": "SMTP_", "syslog": "SYSLOG_", "licensing": "LICENSE_",
}


def default_data_dir() -> Path:
    env = os.environ.get("OMXPATCH_DATA_DIR")
    if env:
        return Path(env)
    if sys.platform.startswith("win"):
        return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "omxpatch"


def _coerce(value, default):
    if isinstance(default, bool):
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on", "sim"}
    if isinstance(default, int):
        return int(value)
    if isinstance(default, float):
        return float(value)
    return value if isinstance(value, str) else str(value)


def _find_config_file(data_dir: Path) -> Path | None:
    candidates = []
    if os.environ.get("OMXPATCH_CONFIG"):
        candidates.append(Path(os.environ["OMXPATCH_CONFIG"]))
    candidates += [Path.cwd() / "omxpatch.toml", data_dir / "omxpatch.toml"]
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).parent / "omxpatch.toml")
    return next((c for c in candidates if c.is_file()), None)


def _load_toml(path: Path) -> dict:
    with path.open("rb") as fh:
        raw = tomllib.load(fh)
    flat: dict[str, object] = {}
    for section, values in raw.items():
        if not isinstance(values, dict):
            flat[section.upper()] = values
            continue
        prefix = _TOML_SECTIONS.get(section, section.upper() + "_")
        for key, val in values.items():
            key = key.upper()
            if section == "database" and key in {"URL", "URI"}:
                flat["DATABASE_URL"] = val
            elif prefix + key in DEFAULTS:
                flat[prefix + key] = val
            elif key in DEFAULTS:
                flat[key] = val
            else:
                flat[prefix + key] = val
    return flat


def _secret_key(data_dir: Path) -> str:
    path = data_dir / "secret.key"
    if path.is_file():
        return path.read_text().strip()
    key = secrets.token_urlsafe(48)
    path.write_text(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def _find_ansible_dir() -> Path:
    """Playbooks: junto ao código-fonte, no pacote PyInstaller, em <prefixo>/share (pip) ou em /opt/omxpatch/ansible."""
    here = Path(__file__).resolve().parent
    candidates = [here.parent / "ansible", Path(getattr(sys, "_MEIPASS", here)) / "ansible", Path(sys.prefix) / "share" / "omxpatch" / "ansible",
                  Path("/usr/local/share/omxpatch/ansible"), Path("/opt/omxpatch/ansible")]
    return next((c for c in candidates if (c / "patch_linux.yml").is_file()), candidates[0])


def load_config(overrides: dict | None = None) -> dict:
    data_dir = default_data_dir()
    cfg: dict[str, object] = dict(DEFAULTS)
    config_file = _find_config_file(data_dir)
    if config_file:
        for k, v in _load_toml(config_file).items():
            if k == "DATA_DIR":
                data_dir = Path(str(v))
            elif k in DEFAULTS:
                cfg[k] = _coerce(v, DEFAULTS[k])
    cfg["OVERRIDES_ERROR"] = ""
    ovr = data_dir / OVERRIDES_NAME                      # alterações feitas na consola (Sistema → Configuração)
    if ovr.is_file():
        try:
            for k, v in _load_toml(ovr).items():
                if k in DEFAULTS:
                    cfg[k] = _coerce(v, DEFAULTS[k])
        except Exception as exc:  # noqa: BLE001 - um ficheiro de alterações inválido nunca impede o arranque
            cfg["OVERRIDES_ERROR"] = f"{ovr.name}: {exc}"
    for key, default in DEFAULTS.items():
        env = os.environ.get(f"OMXPATCH_{key}")
        if env is not None:
            cfg[key] = _coerce(env, default)
    if overrides:
        cfg.update(overrides)
        if "DATA_DIR" in overrides:
            data_dir = Path(overrides["DATA_DIR"])
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "logs").mkdir(exist_ok=True)
    cfg["DATA_DIR"] = str(data_dir)
    cfg["CONFIG_FILE"] = str(config_file) if config_file else ""
    if not cfg["SECRET_KEY"]:
        cfg["SECRET_KEY"] = _secret_key(data_dir)
    if not cfg["DATABASE_URL"]:
        cfg["DATABASE_URL"] = "sqlite:///" + str(data_dir / "omxpatch.db").replace("\\", "/")
    if not cfg["AGENT_PACKAGE_DIR"]:
        cfg["AGENT_PACKAGE_DIR"] = str(data_dir / "packages")
    if not cfg["ANSIBLE_DIR"]:
        cfg["ANSIBLE_DIR"] = str(_find_ansible_dir())
    prefix = str(cfg["URL_PREFIX"] or "").rstrip("/")
    if prefix and not prefix.startswith("/"):
        prefix = "/" + prefix
    cfg["URL_PREFIX"] = prefix
    cfg["SQLALCHEMY_DATABASE_URI"] = cfg["DATABASE_URL"]
    if not cfg["BASE_URL"] and cfg["TLS_ENABLED"]:
        cfg["BASE_URL"] = f"https://{cfg['TLS_HOSTNAME']}" + ("" if int(cfg["PORT"]) == 443 else f":{int(cfg['PORT'])}")
        cfg["BASE_URL_AUTO"] = True
    if not cfg["AGENT_BASE_URL"]:
        scheme = "https" if cfg["TLS_ENABLED"] else "http"
        ip = str(cfg.get("AGENT_SERVER_IP") or "").split(",")[0].strip()
        if str(cfg.get("AGENT_ADDRESS_MODE")) == "ip" and ip:
            addr = f"[{ip}]" if ":" in ip else ip           # IPv6 entre parênteses retos
            cfg["AGENT_BASE_URL"] = f"{scheme}://{addr}:{int(cfg['AGENT_PORT'])}"
        else:
            cfg["AGENT_BASE_URL"] = f"{scheme}://{cfg['AGENT_TLS_HOSTNAME']}:{int(cfg['AGENT_PORT'])}"
        cfg["AGENT_BASE_URL_AUTO"] = True
    cfg["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
    cfg["MAX_CONTENT_LENGTH"] = int(cfg["MAX_UPLOAD_MB"]) * 1024 * 1024
    cfg["SESSION_COOKIE_HTTPONLY"] = True
    cfg["SESSION_COOKIE_SAMESITE"] = "Lax"
    cfg["SESSION_COOKIE_NAME"] = "omxpatch_session"
    cfg["SESSION_COOKIE_PATH"] = prefix or "/"
    cfg["REMEMBER_COOKIE_SECURE"] = cfg["SESSION_COOKIE_SECURE"]
    cfg["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=int(cfg["SESSION_HOURS"]))
    return cfg
