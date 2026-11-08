"""Modelo de dados multitenant do OMXPatch.

Cadeia funcional: Ativo → Exposição → Risco → Mitigação → Patch → Validação → Monitorização contínua.
Todas as entidades de negócio têm ``tenant_id`` e são consultadas através de ``security.scoped()``.
``CveIntel`` é o único catálogo global (inteligência pública partilhada entre organizações).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from flask_login import UserMixin
from sqlalchemy.orm import validates
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db

PASSWORD_HASH_METHOD = "scrypt" if hasattr(hashlib, "scrypt") else "pbkdf2:sha256:600000"

ROLES = {"admin": "Administrador", "user": "Operador", "auditor": "Auditor (só leitura)"}
OS_FAMILIES = {"windows": "Windows", "linux": "Linux", "macos": "macOS"}
ASSET_KINDS = {
    "workstation": "Posto de trabalho", "server": "Servidor", "cloud_vm": "VM cloud", "container": "Contentor",
    "k8s_node": "Nó Kubernetes", "k8s_workload": "Workload Kubernetes", "iot": "IoT", "ot": "OT / ICS",
    "network": "Equipamento de rede", "saas": "Serviço SaaS / Shadow IT", "other": "Outro",
}
ASSET_SOURCES = {
    "agent": "Agente", "agentless": "Sem agente (rede / Ansible)", "ad": "Active Directory", "entra": "Entra ID",
    "vmware": "VMware", "hyperv": "Hyper-V", "aws": "AWS", "azure": "Azure", "gcp": "GCP",
    "omxvuln": "OMXVuln", "import": "Importação", "manual": "Manual",
}
CRITICALITIES = {"critical": "Crítica", "high": "Alta", "medium": "Média", "low": "Baixa"}
CRIT_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

RISK_CATEGORIES = ["low", "medium", "high", "critical", "emergency"]
RISK_LABELS = {"low": "Baixo", "medium": "Médio", "high": "Alto", "critical": "Crítico", "emergency": "Emergência"}
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_LABELS = {"critical": "Crítica", "high": "Alta", "medium": "Média", "low": "Baixa", "info": "Informativa"}

EXPOSURE_STATUSES = {
    "open": "Aberta", "mitigated": "Mitigada (controlo compensatório)", "patching": "Em remediação",
    "remediated": "Remediada (a validar)", "closed": "Fechada (validada)", "accepted": "Risco aceite",
}
OPEN_EXPOSURE = ("open", "mitigated", "patching", "remediated")
EXPLOIT_MATURITY = {"none": "Sem exploit conhecido", "poc": "Prova de conceito", "functional": "Funcional",
                    "weaponized": "Weaponized / em kits"}
MATURITY_RANK = {"none": 0, "poc": 1, "functional": 2, "weaponized": 3}

PATCH_STATUSES = {"identified": "Identificado", "downloaded": "Em repositório", "approved": "Aprovado",
                  "rejected": "Rejeitado", "superseded": "Substituído"}
INSTALLER_TYPES = {"wua": "Windows Update / WSUS (KB)", "msi": "MSI", "msp": "Patch MSI (.msp)", "exe": "EXE (silencioso)",
                   "msu": "MSU (wusa)", "cab": "CAB (DISM)", "choco": "Chocolatey", "office_c2r": "Office Click-to-Run", "winget": "winget",
                   "apt": "apt", "dnf": "dnf/yum", "zypper": "zypper", "brew": "Homebrew", "pkg": "macOS .pkg",
                   "softwareupdate": "macOS softwareupdate", "ansible": "Playbook Ansible"}

CAMPAIGN_STATUSES = {"draft": "Rascunho", "scheduled": "Agendada", "running": "Em execução", "paused": "Em pausa",
                     "completed": "Concluída", "cancelled": "Cancelada", "failed": "Falhou"}
TASK_TYPES = {"update_scan": "Descobrir atualizações", "practice_sim": "Simulação de boa prática", "practice_apply": "Aplicar boa prática", "practice_rollback": "Reverter boa prática",
              "simulate": "Simulação prévia", "inventory": "Inventário", "patch": "Aplicar patch", "validate": "Validar", "bas": "Simulação (BAS)",
              "control": "Controlo compensatório", "rollback": "Reverter patch", "wake": "Wake-on-LAN"}
TASK_STATUSES = {"pending": "Pendente", "waiting_window": "À espera da janela", "waking": "Wake-on-LAN",
                 "queued": "Em fila", "sent": "Enviada ao agente", "running": "Em execução",
                 "succeeded": "Concluída", "failed": "Falhou", "rolled_back": "Revertida",
                 "skipped": "Ignorada", "cancelled": "Cancelada"}
TASK_FINAL = ("succeeded", "failed", "rolled_back", "skipped", "cancelled")

RINGS = {0: "Ring 0 — Laboratório", 1: "Ring 1 — TI", 2: "Ring 2 — Power Users",
         3: "Ring 3 — Unidades de negócio", 4: "Ring 4 — Produção global"}

CONTROL_CATEGORIES = {"firewall": "Firewall", "edr": "EDR", "siem": "SIEM", "iam": "IAM", "waf": "WAF"}
CONTROL_ACTIONS = {
    "block_ioc": ("firewall", "Bloquear IOC"), "block_port": ("firewall", "Bloquear porta"),
    "block_country": ("firewall", "Bloquear país"),
    "edr_detection": ("edr", "Criar deteção"), "edr_block": ("edr", "Criar bloqueio"),
    "siem_rule": ("siem", "Nova regra"), "siem_correlation": ("siem", "Nova correlação"),
    "disable_account": ("iam", "Desativar conta"), "force_mfa": ("iam", "Forçar MFA"),
    "virtual_patch": ("waf", "Virtual patch"),
    "isolate_host": ("isolation", "Isolar o ativo da rede (mantém a consola)"),
}
CONTROL_STATUSES = {"proposed": "Proposto", "approved": "Aprovado", "applied": "Aplicado", "verified": "Verificado",
                    "failed": "Falhou", "reverted": "Revertido", "rejected": "Rejeitado"}

SIGNAL_KINDS = {
    "vuln": "Vulnerabilidade reportada", "active_exploit": "Exploração ativa observada",
    "fw_blocked": "Firewall bloqueia", "fw_allowed": "Firewall não bloqueia",
    "edr_detected": "EDR deteta", "edr_missed": "EDR não deteta",
    "waf_protected": "WAF com virtual patch", "ioc": "IOC observado",
}
SIMULATIONS = {"ransomware": "Ransomware", "lateral_movement": "Movimento lateral",
               "credential_theft": "Roubo de credenciais", "exploit_chain": "Cadeia de exploração"}
AUTONOMOUS_MODES = {"off": "Desligado", "advise": "Aconselhar (propõe, humano aprova)",
                    "auto": "Autónomo (até ao Ring 4, com validação)"}
AUTONOMOUS_STAGES = ["discovery", "assessment", "mapping", "patch_search", "test", "rings", "validation",
                     "closure", "cmdb", "report", "done"]
AUTONOMOUS_STAGE_LABELS = {
    "discovery": "Descoberta automática", "assessment": "Avaliação de risco", "mapping": "Mapeamento dos ativos",
    "patch_search": "Procura de patch", "test": "Teste automático (Ring 0)", "rings": "Ring deployment",
    "validation": "Validação", "closure": "Fecho automático", "cmdb": "Atualização da CMDB",
    "report": "Reporte executivo", "done": "Concluído",
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def jloads(text, default=None):
    try:
        return json.loads(text) if text else (default if default is not None else {})
    except ValueError:
        return default if default is not None else {}


class TimestampMixin:
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class AppMeta(db.Model):
    __tablename__ = "app_meta"
    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.Text, default="")


class Tenant(TimestampMixin, db.Model):
    __tablename__ = "tenants"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(64), unique=True, nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
    legal_name = db.Column(db.String(255), default="")
    nis2_entity_type = db.Column(db.String(16), default="important")
    sector = db.Column(db.String(120), default="")
    country = db.Column(db.String(2), default="PT")
    security_officer = db.Column(db.String(200), default="")
    security_officer_email = db.Column(db.String(255), default="")
    # SLA de remediação por categoria de risco (dias)
    sla_emergency = db.Column(db.Integer, default=1)
    sla_critical = db.Column(db.Integer, default=7)
    sla_high = db.Column(db.Integer, default=30)
    sla_medium = db.Column(db.Integer, default=90)
    sla_low = db.Column(db.Integer, default=180)
    notify_emails = db.Column(db.Text, default="")
    webhook_url = db.Column(db.String(500), default="")
    require_mfa = db.Column(db.Boolean, default=False)
    # Módulo 15 — remediação autónoma
    autonomous_mode = db.Column(db.String(8), default="off")
    autonomous_min_score = db.Column(db.Integer, default=50)     # só CVE com risco >= este valor
    autonomous_kev_only = db.Column(db.Boolean, default=False)
    # Região geográfica por omissão dos ativos descobertos
    default_country = db.Column(db.String(2), default="PT")
    # Identidade visual (branding.py), como no OMXVuln
    logo_file = db.Column(db.String(120), default="")
    brand_header = db.Column(db.String(7), default="")
    brand_primary = db.Column(db.String(7), default="")
    brand_accent = db.Column(db.String(7), default="")
    brand_version = db.Column(db.Integer, default=0)
    license_expires_on = db.Column(db.Date, nullable=True)
    license_ref = db.Column(db.String(120), default="")

    def sla_days(self, category: str) -> int | None:
        return {"emergency": self.sla_emergency, "critical": self.sla_critical, "high": self.sla_high,
                "medium": self.sla_medium, "low": self.sla_low}.get(category)

    def lines(self, field: str) -> list[str]:
        return [x.strip() for x in (getattr(self, field) or "").splitlines() if x.strip() and not x.strip().startswith("#")]


PRIMARY_ADMIN_EMAIL = "admin@omxpatch.local"


class PrimaryAdminError(ValueError):
    pass


class User(UserMixin, TimestampMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=True, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(200), default="")
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(16), default="user", nullable=False)
    is_superadmin = db.Column(db.Boolean, default=False, nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    mfa_secret = db.Column(db.String(64), default="")
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    mfa_method = db.Column(db.String(16), default="totp")
    mfa_last_counter = db.Column(db.Integer, nullable=True)
    mfa_recovery_codes = db.Column(db.Text, default="")
    failed_logins = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)
    session_version = db.Column(db.Integer, default=1, nullable=False)
    is_primary = db.Column(db.Boolean, default=False, nullable=False)
    tenant = db.relationship("Tenant")

    @validates("enabled", "is_superadmin")
    def _protect_primary(self, key, value):
        if self.is_primary and not value:
            raise PrimaryAdminError("O super-administrador inicial não pode ser desativado nem perder o perfil "
                                    "de super-administrador.")
        return value

    @property
    def is_active(self) -> bool:
        if not self.enabled:
            return False
        if self.is_superadmin:
            return True
        from .licensing import is_suspended
        return self.tenant is not None and self.tenant.active and not is_suspended(self.tenant)

    def get_id(self) -> str:
        return f"{self.id}:{self.session_version}"

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password, method=PASSWORD_HASH_METHOD)

    def check_password(self, password: str) -> bool:
        if self.password_hash.startswith("scrypt:") and not hasattr(hashlib, "scrypt"):
            raise RuntimeError("Password criada com scrypt, que não existe neste Python (LibreSSL). Reponha a password.")
        return check_password_hash(self.password_hash, password)

    def has_role(self, *roles: str) -> bool:
        return self.is_superadmin or self.role in roles

    @property
    def can_write(self) -> bool:
        return self.has_role("admin", "user")

    @property
    def can_manage(self) -> bool:
        return self.has_role("admin")


class ApiToken(TimestampMixin, db.Model):
    __tablename__ = "api_tokens"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    prefix = db.Column(db.String(12), nullable=False)
    last_used = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    user = db.relationship("User")


class AuditLog(db.Model):
    __tablename__ = "audit_log"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(64), nullable=False)
    detail = db.Column(db.Text, default="")
    ip = db.Column(db.String(64), default="")
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    user = db.relationship("User")


# --------------------------------------------------------------------------- Módulo 1 — ativos


class Asset(TimestampMixin, db.Model):
    """Registo único da CMDB integrada: hardware, software, utilizador, criticidade, geolocalização, owner."""
    __tablename__ = "assets"
    __table_args__ = (db.UniqueConstraint("tenant_id", "uid", name="uq_asset_uid"),)
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    uid = db.Column(db.String(190), nullable=False)             # identificador estável (hostname, instance-id, MAC…)
    name = db.Column(db.String(255), nullable=False)
    fqdn = db.Column(db.String(255), default="")
    ip = db.Column(db.String(64), default="", index=True)
    mac = db.Column(db.String(32), default="")                  # Wake-on-LAN
    kind = db.Column(db.String(16), default="workstation")
    source = db.Column(db.String(16), default="manual")
    managed = db.Column(db.Boolean, default=False, nullable=False)       # False = ativo descoberto sem gestão (Shadow IT)
    shadow_it = db.Column(db.Boolean, default=False, nullable=False)
    os_family = db.Column(db.String(16), default="")
    os_name = db.Column(db.String(120), default="")
    os_version = db.Column(db.String(120), default="")
    hardware = db.Column(db.Text, default="{}")                 # JSON: cpu, ram_gb, disk_gb, vendor, model, serial
    primary_user = db.Column(db.String(255), default="")
    owner = db.Column(db.String(255), default="")
    department = db.Column(db.String(120), default="")
    criticality = db.Column(db.String(16), default="medium")
    business_value = db.Column(db.Integer, default=50)          # 0-100
    cost_per_hour = db.Column(db.Float, nullable=True)          # custo de indisponibilidade por hora (moeda); vazio = por criticidade
    internet_exposed = db.Column(db.String(8), default="auto")  # auto | yes | no
    country = db.Column(db.String(2), default="")
    city = db.Column(db.String(120), default="")
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    cloud_provider = db.Column(db.String(16), default="")
    cloud_id = db.Column(db.String(255), default="")
    cluster = db.Column(db.String(255), default="")
    tags = db.Column(db.String(500), default="")
    open_ports = db.Column(db.String(500), default="")          # "22,443,8443"
    ring = db.Column(db.Integer, default=4, nullable=False)     # anel de teste (0-4)
    connection = db.Column(db.String(8), default="agent")       # agent | ansible
    ansible_user = db.Column(db.String(120), default="")
    ansible_port = db.Column(db.Integer, default=0)
    maintenance_group = db.Column(db.String(120), default="")
    cmdb_ref = db.Column(db.String(190), default="")            # ID na CMDB externa (ServiceNow, etc.)
    cmdb_synced_at = db.Column(db.DateTime, nullable=True)
    first_seen = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_boot = db.Column(db.DateTime, nullable=True)
    reboot_pending = db.Column(db.Boolean, default=False, nullable=False)
    software = db.relationship("AssetSoftware", backref="asset", cascade="all, delete-orphan", lazy="dynamic")

    @property
    def hw(self) -> dict:
        return jloads(self.hardware)

    @property
    def tag_list(self) -> list[str]:
        return [t.strip() for t in (self.tags or "").split(",") if t.strip()]

    @property
    def ports(self) -> list[int]:
        out = []
        for p in (self.open_ports or "").replace(" ", "").split(","):
            if p.isdigit():
                out.append(int(p))
        return out


class AssetSoftware(db.Model):
    __tablename__ = "asset_software"
    __table_args__ = (db.UniqueConstraint("asset_id", "name", "version", name="uq_asset_sw"),)
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    vendor = db.Column(db.String(200), default="")
    version = db.Column(db.String(120), default="")
    cpe = db.Column(db.String(300), default="")
    source = db.Column(db.String(32), default="agent")
    installed_at = db.Column(db.DateTime, nullable=True)
    last_seen = db.Column(db.DateTime, default=utcnow, nullable=False)


class CmdbChange(db.Model):
    __tablename__ = "cmdb_changes"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    field = db.Column(db.String(64), nullable=False)
    old = db.Column(db.Text, default="")
    new = db.Column(db.Text, default="")
    source = db.Column(db.String(32), default="")
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class EnrollmentToken(TimestampMixin, db.Model):
    """Token de registo de agentes (Windows / Linux / macOS). Distribuído pelos playbooks Ansible."""
    __tablename__ = "enrollment_tokens"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    prefix = db.Column(db.String(12), nullable=False)
    ring = db.Column(db.Integer, default=4)
    max_uses = db.Column(db.Integer, default=0)                 # 0 = ilimitado
    uses = db.Column(db.Integer, default=0)
    expires_at = db.Column(db.DateTime, nullable=True)
    revoked = db.Column(db.Boolean, default=False, nullable=False)


class Agent(TimestampMixin, db.Model):
    __tablename__ = "agents"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=True, index=True)
    key_hash = db.Column(db.String(64), unique=True, nullable=False)
    key_prefix = db.Column(db.String(12), nullable=False)
    hostname = db.Column(db.String(255), default="")
    machine_id = db.Column(db.String(190), default="", index=True)   # um equipamento só reporta a uma organização
    os_family = db.Column(db.String(16), default="")
    version = db.Column(db.String(32), default="")
    ip = db.Column(db.String(64), default="")
    last_seen = db.Column(db.DateTime, nullable=True)
    revoked = db.Column(db.Boolean, default=False, nullable=False)
    asset = db.relationship("Asset", backref=db.backref("agent", uselist=False))


# --------------------------------------------------------------------------- Módulo 2 — inteligência


class CveIntel(db.Model):
    """Catálogo global de CVE: NVD, MITRE, CISA KEV, EPSS, feeds de ameaças e avisos de fabricantes."""
    __tablename__ = "cve_intel"
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(24), unique=True, nullable=False, index=True)
    title = db.Column(db.String(500), default="")
    description = db.Column(db.Text, default="")
    cvss = db.Column(db.Float, nullable=True)
    cvss_vector = db.Column(db.String(200), default="")
    cwe = db.Column(db.String(200), default="")
    published = db.Column(db.DateTime, nullable=True)
    kev = db.Column(db.Boolean, default=False, nullable=False)
    kev_added = db.Column(db.DateTime, nullable=True)
    kev_due = db.Column(db.DateTime, nullable=True)
    ransomware = db.Column(db.Boolean, default=False, nullable=False)
    epss = db.Column(db.Float, nullable=True)                   # 0..1
    epss_percentile = db.Column(db.Float, nullable=True)
    exploit_maturity = db.Column(db.String(12), default="none")
    exploit_refs = db.Column(db.Text, default="")
    malware = db.Column(db.Text, default="")                    # famílias separadas por vírgula
    affected = db.Column(db.Text, default="[]")                 # JSON [{vendor, product, version_start, version_end, fixed}]
    advisories = db.Column(db.Text, default="[]")               # JSON [{vendor, url, fixed_version, kb}]
    sources = db.Column(db.String(200), default="")
    updated_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    @property
    def severity(self) -> str:
        s = self.cvss or 0
        return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low" if s > 0 else "info"

    @property
    def affected_list(self) -> list[dict]:
        return jloads(self.affected, [])

    @property
    def advisory_list(self) -> list[dict]:
        return jloads(self.advisories, [])

    @property
    def malware_list(self) -> list[str]:
        return [m.strip() for m in (self.malware or "").split(",") if m.strip()]


# --------------------------------------------------------------------------- Módulos 3 e 4 — exposição e risco


class Exposure(TimestampMixin, db.Model):
    """Ativo × CVE correlacionado, com risco dinâmico e veredicto multi-vendor."""
    __tablename__ = "exposures"
    __table_args__ = (db.UniqueConstraint("tenant_id", "asset_id", "cve_id", "software_name", name="uq_exposure"),)
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    cve_id = db.Column(db.String(24), nullable=False, index=True)
    software_name = db.Column(db.String(255), default="")
    installed_version = db.Column(db.String(120), default="")
    fixed_version = db.Column(db.String(120), default="")
    port = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(12), default="open", nullable=False, index=True)
    source = db.Column(db.String(16), default="correlation")     # correlation | omxvuln | signal
    omxvuln_finding_id = db.Column(db.Integer, nullable=True)
    patch_id = db.Column(db.Integer, db.ForeignKey("patches.id"), nullable=True)
    patch_available = db.Column(db.Boolean, default=False, nullable=False)
    exploitability = db.Column(db.String(12), default="unknown", nullable=False)   # confirmed | likely | unlikely | unreachable | unknown
    exposure_sim = db.Column(db.Text, default="{}")                 # simulação de exposição (passos do caminho de ataque)
    sim_at = db.Column(db.DateTime, nullable=True)
    expected_loss = db.Column(db.Float, default=0.0, nullable=False)  # perda esperada (moeda) = P(exploração) × impacto
    risk_score = db.Column(db.Integer, default=0, nullable=False, index=True)
    risk_category = db.Column(db.String(12), default="low", nullable=False)
    residual_score = db.Column(db.Integer, default=0, nullable=False)     # após controlos compensatórios
    factors = db.Column(db.Text, default="[]")
    verdict = db.Column(db.Text, default="{}")
    detected_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=utcnow, nullable=False)
    patched_at = db.Column(db.DateTime, nullable=True)
    closed_at = db.Column(db.DateTime, nullable=True)
    due_date = db.Column(db.DateTime, nullable=True)
    asset = db.relationship("Asset", backref=db.backref("exposures", lazy="dynamic"))
    patch = db.relationship("Patch")

    @property
    def sim_data(self) -> dict:
        return jloads(self.exposure_sim, {})

    @property
    def factor_list(self) -> list[dict]:
        return jloads(self.factors, [])

    @property
    def verdict_data(self) -> dict:
        return jloads(self.verdict, {})

    @property
    def is_open(self) -> bool:
        return self.status in OPEN_EXPOSURE


class Signal(TimestampMixin, db.Model):
    """Telemetria de outras plataformas de segurança (EDR, firewall, scanners, CSPM, SIEM…)."""
    __tablename__ = "signals"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    source = db.Column(db.String(32), nullable=False)             # defender, crowdstrike, paloalto, tenable…
    kind = db.Column(db.String(24), nullable=False, index=True)
    cve_id = db.Column(db.String(24), default="", index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=True, index=True)
    asset_ref = db.Column(db.String(255), default="")             # nome/IP quando o ativo ainda não existe
    value = db.Column(db.String(500), default="")                 # porta, IOC, regra, etc.
    observed_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    confidence = db.Column(db.Integer, default=80)
    raw = db.Column(db.Text, default="")


# --------------------------------------------------------------------------- Módulos 5, 6 e 7 — patches


class Patch(TimestampMixin, db.Model):
    """Repositório de patches identificados (e, quando possível, descarregados) por organização."""
    __tablename__ = "patches"
    __table_args__ = (db.UniqueConstraint("tenant_id", "patch_uid", name="uq_patch_uid"),)
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    patch_uid = db.Column(db.String(190), nullable=False)        # KB5031234, apt:openssl, brew:openssl@3 …
    title = db.Column(db.String(500), default="")
    vendor = db.Column(db.String(200), default="")
    product = db.Column(db.String(255), default="")
    os_family = db.Column(db.String(16), default="")             # vazio: qualquer
    installer = db.Column(db.String(16), default="wua")
    package_name = db.Column(db.String(255), default="")
    version_fixed = db.Column(db.String(120), default="")
    silent_args = db.Column(db.String(500), default="")
    download_url = db.Column(db.String(1000), default="")
    sha256 = db.Column(db.String(64), default="")
    size_bytes = db.Column(db.BigInteger, default=0)
    local_file = db.Column(db.String(500), default="")
    cves = db.Column(db.Text, default="[]")
    severity = db.Column(db.String(12), default="medium")
    released_at = db.Column(db.DateTime, nullable=True)
    reboot_required = db.Column(db.Boolean, default=False, nullable=False)
    status = db.Column(db.String(12), default="identified", nullable=False)
    source = db.Column(db.String(16), default="vendor")          # vendor | community | omxvuln | manual
    bulletin_url = db.Column(db.String(1000), default="")
    # Patch Intelligence (Módulo 5)
    community_reports = db.Column(db.Integer, default=0)
    community_success_rate = db.Column(db.Float, nullable=True)   # %
    vendor_known_issues = db.Column(db.Text, default="[]")        # JSON [{"title","severity","url"}]
    reported_problems = db.Column(db.Integer, default=0)
    impact = db.Column(db.String(8), default="low")               # low | medium | high (impacto operacional)
    superseded_by = db.Column(db.String(190), default="")
    notes = db.Column(db.Text, default="")

    @property
    def cve_list(self) -> list[str]:
        return jloads(self.cves, [])

    @property
    def known_issues(self) -> list[dict]:
        return jloads(self.vendor_known_issues, [])


class PatchTelemetry(db.Model):
    """Telemetria dos clientes após cada aplicação (sucesso, crash, experiência do utilizador)."""
    __tablename__ = "patch_telemetry"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    patch_id = db.Column(db.Integer, db.ForeignKey("patches.id"), nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=True)
    task_id = db.Column(db.Integer, nullable=True)
    ring = db.Column(db.Integer, default=4)
    result = db.Column(db.String(12), default="success")          # success | failed | rolled_back
    crashed = db.Column(db.Boolean, default=False, nullable=False)
    ux_score = db.Column(db.Integer, nullable=True)               # 0-100
    duration_s = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)


class MaintenanceWindow(TimestampMixin, db.Model):
    __tablename__ = "maintenance_windows"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    weekdays = db.Column(db.String(20), default="0,1,2,3,4,5,6")  # 0 = segunda
    start_time = db.Column(db.String(5), default="22:00")
    duration_minutes = db.Column(db.Integer, default=240)
    timezone = db.Column(db.String(64), default="")                # vazio: hora do servidor
    rings = db.Column(db.String(20), default="")                   # vazio: todos
    group = db.Column(db.String(120), default="")                  # Asset.maintenance_group; vazio: todos
    allow_emergency = db.Column(db.Boolean, default=True, nullable=False)   # P: Emergência ignora a janela
    enabled = db.Column(db.Boolean, default=True, nullable=False)


class Campaign(TimestampMixin, db.Model):
    __tablename__ = "campaigns"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    patch_id = db.Column(db.Integer, db.ForeignKey("patches.id"), nullable=False)
    status = db.Column(db.String(12), default="draft", nullable=False, index=True)
    origin = db.Column(db.String(12), default="manual")           # manual | autonomous
    run_id = db.Column(db.Integer, nullable=True)
    scope = db.Column(db.Text, default="{}")                      # JSON {asset_ids, tags, os_family, cve_id}
    use_rings = db.Column(db.Boolean, default=True, nullable=False)
    current_ring = db.Column(db.Integer, default=0)
    ring_state = db.Column(db.Text, default="{}")                 # JSON {ring: {state, since, metrics}}
    auto_promote = db.Column(db.Boolean, default=True, nullable=False)
    start_at = db.Column(db.DateTime, nullable=True)
    respect_windows = db.Column(db.Boolean, default=True, nullable=False)
    use_wol = db.Column(db.Boolean, default=False, nullable=False)
    bandwidth_kbps = db.Column(db.Integer, default=0)
    reboot_policy = db.Column(db.String(10), default="if_needed")  # none | if_needed | force
    emergency = db.Column(db.Boolean, default=False, nullable=False)
    require_preflight = db.Column(db.Boolean, default=False, nullable=False)   # só instala após simulação prévia sem bloqueios
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)
    patch = db.relationship("Patch")

    @property
    def scope_data(self) -> dict:
        return jloads(self.scope, {})

    @property
    def rings_state(self) -> dict:
        return jloads(self.ring_state, {})


class Task(TimestampMixin, db.Model):
    """Trabalho para um ativo: executado pelo agente (pull) ou por Ansible (sem agente)."""
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    type = db.Column(db.String(12), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey("campaigns.id"), nullable=True, index=True)
    patch_id = db.Column(db.Integer, db.ForeignKey("patches.id"), nullable=True)
    exposure_id = db.Column(db.Integer, nullable=True)
    ring = db.Column(db.Integer, default=4)
    mode = db.Column(db.String(8), default="agent")               # agent | ansible
    status = db.Column(db.String(16), default="pending", nullable=False, index=True)
    payload = db.Column(db.Text, default="{}")
    result = db.Column(db.Text, default="{}")
    output = db.Column(db.Text, default="")
    attempts = db.Column(db.Integer, default=0)
    not_before = db.Column(db.DateTime, nullable=True)
    sent_at = db.Column(db.DateTime, nullable=True)
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)
    asset = db.relationship("Asset")
    campaign = db.relationship("Campaign", backref=db.backref("tasks", lazy="dynamic"))
    patch = db.relationship("Patch")

    @property
    def payload_data(self) -> dict:
        return jloads(self.payload, {})

    @property
    def result_data(self) -> dict:
        return jloads(self.result, {})


PLAN_STATUSES = {"draft": "Rascunho", "simulating": "A simular", "simulated": "Simulado — a aguardar OK", "executing": "Em execução",
                 "completed": "Concluído", "cancelled": "Cancelado"}
ITEM_STATUSES = {"draft": "Por simular", "simulating": "A simular", "simulated": "Simulado", "approved": "Aprovado (OK)", "queued": "Em fila",
                 "running": "Em execução", "succeeded": "Concluído", "failed": "Falhou", "rolled_back": "Revertido", "skipped": "Ignorado",
                 "reverted": "Revertido pelo utilizador"}
ITEM_FINAL = ("succeeded", "failed", "rolled_back", "skipped", "reverted")

PREFLIGHT_OUTCOMES = {"pending": "A simular", "ready": "Pronto", "warning": "Pronto, com avisos", "blocked": "Bloqueado",
                      "noop": "Nada a instalar", "error": "Erro na simulação"}


class Preflight(TimestampMixin, db.Model):
    """Simulação prévia de um patch num ativo: o que aconteceria se fosse instalado agora (sem instalar)."""
    __tablename__ = "preflights"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    patch_id = db.Column(db.Integer, db.ForeignKey("patches.id"), nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    campaign_id = db.Column(db.Integer, nullable=True, index=True)
    task_id = db.Column(db.Integer, nullable=True)
    outcome = db.Column(db.String(10), default="pending", nullable=False, index=True)
    checks = db.Column(db.Text, default="[]")
    predicted = db.Column(db.Text, default="{}")
    finished_at = db.Column(db.DateTime, nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    patch = db.relationship("Patch")
    asset = db.relationship("Asset")

    @property
    def check_list(self) -> list[dict]:
        return jloads(self.checks, [])

    @property
    def predicted_data(self) -> dict:
        return jloads(self.predicted, {})


class OperationPlan(TimestampMixin, db.Model):
    """Plano de operações em massa — por atualização (um patch/prática em vários ativos) ou por ativo (várias operações num ativo).
    Fluxo obrigatório: simular → rever ações e resultados → **OK explícito** → executar."""
    __tablename__ = "operation_plans"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    mode = db.Column(db.String(10), default="by_patch")           # by_patch | by_asset
    status = db.Column(db.String(12), default="draft", nullable=False, index=True)
    reboot_policy = db.Column(db.String(10), default="if_needed")
    respect_windows = db.Column(db.Boolean, default=True, nullable=False)
    start_at = db.Column(db.DateTime, nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    executed_at = db.Column(db.DateTime, nullable=True)
    # governação ITSM: pedido de mudança (change) associado
    change_ref = db.Column(db.String(64), default="")               # p.ex. CHG0030012
    change_id = db.Column(db.String(64), default="")                # sys_id / chave no ITSM
    change_url = db.Column(db.String(500), default="")
    change_state = db.Column(db.String(24), default="")             # none | requested | approved | rejected | implemented | closed | cancelled
    change_detail = db.Column(db.String(300), default="")
    change_checked_at = db.Column(db.DateTime, nullable=True)
    items = db.relationship("PlanItem", backref="plan", cascade="all, delete-orphan", lazy="dynamic")

    # atributos usados por deploy.patch_payload (compatível com Campaign)
    bandwidth_kbps = 0
    emergency = False


class PlanItem(db.Model):
    """Uma operação (patch ou boa prática) num ativo, com a sua simulação, o OK do utilizador e o resultado."""
    __tablename__ = "plan_items"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    plan_id = db.Column(db.Integer, db.ForeignKey("operation_plans.id"), nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    kind = db.Column(db.String(10), nullable=False)               # patch | practice
    patch_id = db.Column(db.Integer, db.ForeignKey("patches.id"), nullable=True)
    practice = db.Column(db.String(32), default="")
    params = db.Column(db.Text, default="{}")
    status = db.Column(db.String(12), default="draft", nullable=False, index=True)
    sim_outcome = db.Column(db.String(10), default="none")        # none | pending | ready | warning | blocked | noop | error
    sim_checks = db.Column(db.Text, default="[]")
    sim_actions = db.Column(db.Text, default="[]")
    sim_predicted = db.Column(db.Text, default="{}")
    sim_at = db.Column(db.DateTime, nullable=True)
    sim_task_id = db.Column(db.Integer, nullable=True)
    preflight_id = db.Column(db.Integer, nullable=True)
    approved_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    accepted_warnings = db.Column(db.Boolean, default=False, nullable=False)
    task_id = db.Column(db.Integer, nullable=True)
    result = db.Column(db.Text, default="{}")
    output = db.Column(db.Text, default="")
    finished_at = db.Column(db.DateTime, nullable=True)
    asset = db.relationship("Asset")
    patch = db.relationship("Patch")
    approved_by = db.relationship("User", foreign_keys=[approved_by_id])

    @property
    def params_data(self) -> dict:
        return jloads(self.params, {})

    @property
    def check_list(self) -> list[dict]:
        return jloads(self.sim_checks, [])

    @property
    def action_list(self) -> list[dict]:
        return jloads(self.sim_actions, [])

    @property
    def predicted_data(self) -> dict:
        return jloads(self.sim_predicted, {})

    @property
    def result_data(self) -> dict:
        return jloads(self.result, {})

    @property
    def label(self) -> str:
        if self.kind == "patch":
            return self.patch.patch_uid if self.patch else "patch"
        from .engine.practices import PRACTICES
        return PRACTICES.get(self.practice, {}).get("label", self.practice)


class RingPolicy(db.Model):
    """Critérios de promoção entre anéis (taxa de sucesso, crash rate, experiência do utilizador, telemetria)."""
    __tablename__ = "ring_policies"
    __table_args__ = (db.UniqueConstraint("tenant_id", "ring", name="uq_ring_policy"),)
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    ring = db.Column(db.Integer, nullable=False)
    min_success = db.Column(db.Float, default=95.0)
    max_crash = db.Column(db.Float, default=1.0)
    min_ux = db.Column(db.Float, default=80.0)
    min_devices = db.Column(db.Integer, default=1)
    soak_hours = db.Column(db.Integer, default=24)
    auto_promote = db.Column(db.Boolean, default=True, nullable=False)


# --------------------------------------------------------------------------- Módulos 8–10, 14, 15


class ControlAction(TimestampMixin, db.Model):
    """Controlo compensatório quando não existe patch (firewall, EDR, SIEM, IAM, WAF)."""
    __tablename__ = "control_actions"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    cve_id = db.Column(db.String(24), default="", index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=True, index=True)
    exposure_id = db.Column(db.Integer, db.ForeignKey("exposures.id"), nullable=True, index=True)
    category = db.Column(db.String(10), nullable=False)
    action = db.Column(db.String(20), nullable=False)
    params = db.Column(db.Text, default="{}")
    artifact = db.Column(db.Text, default="")                    # regra gerada (iptables, KQL, WAF rule…)
    risk_reduction = db.Column(db.Integer, default=0)
    status = db.Column(db.String(10), default="proposed", nullable=False)
    via = db.Column(db.String(32), default="")                   # ansible | connector:<kind> | manual
    detail = db.Column(db.Text, default="")
    change_ref = db.Column(db.String(64), default="")            # governação ITSM (só se a gestão de changes estiver ativa)
    change_id = db.Column(db.String(64), default="")
    change_url = db.Column(db.String(500), default="")
    change_state = db.Column(db.String(24), default="")
    expires_when_patched = db.Column(db.Boolean, default=True, nullable=False)
    applied_at = db.Column(db.DateTime, nullable=True)
    verified_at = db.Column(db.DateTime, nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    asset = db.relationship("Asset")
    exposure = db.relationship("Exposure")

    @property
    def params_data(self) -> dict:
        return jloads(self.params, {})


class AiPlan(TimestampMixin, db.Model):
    __tablename__ = "ai_plans"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=True)
    question = db.Column(db.String(500), default="")
    target_score = db.Column(db.Integer, default=20)
    before_score = db.Column(db.Integer, default=0)
    after_score = db.Column(db.Integer, default=0)
    plan = db.Column(db.Text, default="[]")
    narrative = db.Column(db.Text, default="")
    status = db.Column(db.String(10), default="proposed")        # proposed | applied
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    asset = db.relationship("Asset")

    @property
    def steps(self) -> list[dict]:
        return jloads(self.plan, [])


class Validation(TimestampMixin, db.Model):
    """Closed-loop: patch instalado, serviço reiniciado, CVE desapareceu, exposição eliminada, compliance."""
    __tablename__ = "validations"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    exposure_id = db.Column(db.Integer, db.ForeignKey("exposures.id"), nullable=True, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    cve_id = db.Column(db.String(24), default="")
    task_id = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(10), default="pending")         # pending | passed | failed | partial
    checks = db.Column(db.Text, default="{}")
    attempts = db.Column(db.Integer, default=0)
    asset = db.relationship("Asset")

    @property
    def check_data(self) -> dict:
        return jloads(self.checks, {})


class Simulation(TimestampMixin, db.Model):
    """Simulação de ataque seguro (BAS): valida se a remediação realmente bloqueia o ataque."""
    __tablename__ = "simulations"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    scenario = db.Column(db.String(24), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    cve_id = db.Column(db.String(24), default="")
    exposure_id = db.Column(db.Integer, nullable=True)
    phase = db.Column(db.String(10), default="baseline")         # baseline | after_fix
    baseline_id = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(10), default="queued")
    outcome = db.Column(db.String(12), default="")               # blocked | partial | not_blocked | error
    steps = db.Column(db.Text, default="[]")
    task_id = db.Column(db.Integer, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)
    asset = db.relationship("Asset")

    @property
    def step_list(self) -> list[dict]:
        return jloads(self.steps, [])


class AutonomousRun(TimestampMixin, db.Model):
    """Fluxo do Módulo 15 para um novo CVE: máquina de estados avançada pelo worker."""
    __tablename__ = "autonomous_runs"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    cve_id = db.Column(db.String(24), nullable=False, index=True)
    mode = db.Column(db.String(8), default="advise")
    stage = db.Column(db.String(16), default="discovery")
    status = db.Column(db.String(12), default="running")         # running | waiting | approval | completed | failed | stopped
    log = db.Column(db.Text, default="")
    data = db.Column(db.Text, default="{}")                      # JSON {asset_ids, patch_id, campaign_id, ...}
    report = db.Column(db.Text, default="{}")
    finished_at = db.Column(db.DateTime, nullable=True)

    @property
    def data_dict(self) -> dict:
        return jloads(self.data, {})

    @property
    def report_data(self) -> dict:
        return jloads(self.report, {})


class Connector(TimestampMixin, db.Model):
    """Integração por organização (SIEM, SOAR, ITSM, EDR, cloud, CMDB, scanners) com segredos cifrados."""
    __tablename__ = "connectors"
    __table_args__ = (db.UniqueConstraint("tenant_id", "kind", name="uq_connector_kind"),)
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    kind = db.Column(db.String(32), nullable=False)
    base_url = db.Column(db.String(500), default="")
    username = db.Column(db.String(255), default="")
    secret = db.Column(db.Text, default="")
    options = db.Column(db.Text, default="{}")
    verify_tls = db.Column(db.Boolean, default=True, nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    last_sync_at = db.Column(db.DateTime, nullable=True)
    last_ok = db.Column(db.Boolean, nullable=True)
    last_detail = db.Column(db.Text, default="")

    @property
    def opts(self) -> dict:
        return jloads(self.options, {})


class NotificationLog(db.Model):
    __tablename__ = "notification_log"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=True, index=True)
    channel = db.Column(db.String(16), default="")
    subject = db.Column(db.String(300), default="")
    ok = db.Column(db.Boolean, default=True)
    detail = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


# --------------------------------------------------------------------------- descoberta de atualizações instaláveis

UPDATE_STATUSES = {"discovered": "Descoberta", "queued": "Na fila de transferência", "downloading": "A transferir", "downloaded": "No repositório do servidor",
                   "failed": "Transferência falhada", "not_downloadable": "Sem transferência (usa a origem do SO)", "installed": "Instalada", "superseded": "Substituída"}


class AvailableUpdate(TimestampMixin, db.Model):
    """Atualização **instalável** num ativo, descoberta pelo agente (apt, dnf, zypper, Windows Update, winget, Chocolatey, softwareupdate, brew)
    e enviada à consola. Liga ao ``Patch`` do repositório (partilhado entre ativos) onde o ficheiro é descarregado proativamente."""
    __tablename__ = "available_updates"
    __table_args__ = (db.UniqueConstraint("tenant_id", "asset_id", "source", "uid", name="uq_available_update"),)
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    source = db.Column(db.String(16), nullable=False)
    uid = db.Column(db.String(190), nullable=False)
    name = db.Column(db.String(255), default="")
    title = db.Column(db.String(500), default="")
    current_version = db.Column(db.String(120), default="")
    new_version = db.Column(db.String(120), default="")
    kb = db.Column(db.String(32), default="")
    severity = db.Column(db.String(12), default="medium")
    category = db.Column(db.String(16), default="update")          # security | update | application
    cves = db.Column(db.Text, default="[]")
    size_bytes = db.Column(db.BigInteger, default=0)
    reboot = db.Column(db.Boolean, default=False, nullable=False)
    installer = db.Column(db.String(16), default="")
    package = db.Column(db.String(255), default="")
    origin = db.Column(db.String(200), default="")
    download_url = db.Column(db.String(1000), default="")
    sha256 = db.Column(db.String(64), default="")
    silent_args = db.Column(db.String(500), default="")
    status = db.Column(db.String(16), default="discovered", nullable=False, index=True)
    detail = db.Column(db.String(500), default="")                  # motivo (falha, sem transferência…)
    attempts = db.Column(db.Integer, default=0, nullable=False)
    last_attempt_at = db.Column(db.DateTime, nullable=True)
    patch_id = db.Column(db.Integer, db.ForeignKey("patches.id"), nullable=True, index=True)
    first_seen = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=utcnow, nullable=False)
    resolved_at = db.Column(db.DateTime, nullable=True)
    asset = db.relationship("Asset", backref=db.backref("updates", lazy="dynamic"))
    patch = db.relationship("Patch")

    @property
    def cve_list(self) -> list[str]:
        return jloads(self.cves, [])

    @property
    def pending(self) -> bool:
        return self.status not in ("installed", "superseded")


class UpdateScan(db.Model):
    """Registo de cada descoberta recebida de um agente (prova de que a informação chegou à consola)."""
    __tablename__ = "update_scans"
    __table_args__ = (db.UniqueConstraint("asset_id", "scan_id", name="uq_update_scan"),)
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    agent_id = db.Column(db.Integer, db.ForeignKey("agents.id"), nullable=True)
    scan_id = db.Column(db.String(64), nullable=False)
    scanned_at = db.Column(db.DateTime, nullable=True)               # no agente
    received_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    total = db.Column(db.Integer, default=0)
    new = db.Column(db.Integer, default=0)
    resolved = db.Column(db.Integer, default=0)
    sources = db.Column(db.Text, default="{}")
    asset = db.relationship("Asset")

    @property
    def source_data(self) -> dict:
        return jloads(self.sources, {})


# --------------------------------------------------------------------------- linhas de base (gold images)


class BaselineItem(TimestampMixin, db.Model):
    """Requisito da linha de base de um grupo de ativos (SO/etiqueta): patch mínimo ou boa prática. Alimentado automaticamente pelas
    remediações bem-sucedidas e exportável para as imagens padrão (Ansible, shell, Packer, JSON)."""
    __tablename__ = "baseline_items"
    __table_args__ = (db.UniqueConstraint("tenant_id", "scope", "kind", "name", name="uq_baseline_item"),)
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, index=True)
    scope = db.Column(db.String(120), default="linux", nullable=False)       # os_family (linux|windows|macos) ou «os_family:etiqueta»
    kind = db.Column(db.String(10), nullable=False)                          # patch | practice
    name = db.Column(db.String(255), nullable=False)                         # pacote / KB / id da boa prática
    installer = db.Column(db.String(16), default="")
    min_version = db.Column(db.String(120), default="")
    params = db.Column(db.Text, default="{}")
    source_plan_id = db.Column(db.Integer, nullable=True)
    cves = db.Column(db.Text, default="[]")
    note = db.Column(db.String(300), default="")
    active = db.Column(db.Boolean, default=True, nullable=False)

    @property
    def params_data(self) -> dict:
        return jloads(self.params, {})

    @property
    def cve_list(self) -> list[str]:
        return jloads(self.cves, [])
