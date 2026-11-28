"""Motor Ansible sem agente: atualiza o sistema operativo e todo o software (Windows, Linux, macOS), os componentes CyberArk (Vault, CPM, PSM,
PSMP) e avalia atualizações em equipamentos de rede/firewalls (Check Point, FortiGate, Palo Alto, Cisco, Juniper, Arista).

Fluxo (igual ao dos planos): **avaliar** (só leitura) → **OK explícito do administrador** → **aplicar**. Aplicar exige uma avaliação bem-sucedida
das últimas 24 h para cada ativo; no CyberArk exige ainda o pacote do fabricante (com SHA-256), o comando de atualização e uma confirmação escrita.
Os componentes CyberArk respeitam a ordem Vault → CPM → PSM → PSMP: cada etapa só arranca se a anterior tiver terminado com sucesso."""
from __future__ import annotations

import json
import re
from datetime import timedelta

from ..extensions import db
from ..models import Asset, Task, Tenant, utcnow

OPERATIONS = {
    "os": {"label": "Sistema operativo (Windows Update / apt / dnf / zypper / softwareupdate)", "task": "os_update", "scope": "os", "kinds": ("windows", "linux", "macos")},
    "software": {"label": "Software e aplicações (winget, Chocolatey, snap, flatpak, Homebrew, Mac App Store)", "task": "sw_update", "scope": "software", "kinds": ("windows", "linux", "macos")},
    "all": {"label": "Tudo: sistema operativo + software", "task": "os_update", "scope": "all", "kinds": ("windows", "linux", "macos")},
    "cyberark": {"label": "CyberArk: Vault, CPM, PSM, PSMP", "task": "cyb_upgrade", "scope": "", "kinds": ("cyberark",)},
    "agent_install": {"label": "Instalar o agente OMXPatch (por SSH/WMI, sem agente prévio)", "task": "agent_inst", "scope": "", "kinds": ("windows", "linux", "macos")},
    "network": {"label": "Avaliar atualizações de switches, routers e firewalls (somente leitura)", "task": "net_assess", "scope": "", "kinds": ("network",)},
}
PLAYBOOKS = {("os_update", "windows"): "update_windows.yml", ("os_update", "linux"): "update_linux.yml", ("os_update", "macos"): "update_macos.yml",
             ("sw_update", "windows"): "update_windows.yml", ("sw_update", "linux"): "update_linux.yml", ("sw_update", "macos"): "update_macos.yml",
             ("cyb_upgrade", "any"): "cyberark_upgrade.yml", ("net_assess", "any"): "net_assess.yml"}
TASK_TYPES = ("os_update", "sw_update", "cyb_upgrade", "net_assess", "agent_inst")
CYBERARK_ORDER = ("vault", "cpm", "psm", "psmp")
APPLY_FRESHNESS = timedelta(hours=24)
CONFIRM_WORD = "ATUALIZAR"
NET_OS = {"cisco_ios": "cisco.ios.ios", "cisco_nxos": "cisco.nxos.nxos", "junos": "junipernetworks.junos.junos", "eos": "arista.eos.eos"}


class EngineError(ValueError):
    pass


NET_GUESS = (("fortios", r"forti(gate|os)"), ("panos", r"pan-?os|palo ?alto"), ("checkpoint", r"check ?point|gaia"), ("cisco_nxos", r"nx-?os|nexus"),
             ("cisco_ios", r"cisco|ios[- ]?xe?"), ("junos", r"junos|juniper"), ("eos", r"arista|\beos\b"))


def guess_platform(asset: Asset) -> str:
    """Plataforma de rede provável de um ativo sem «plataforma» definida (pelo tipo, nome e sistema)."""
    text = " ".join([asset.name or "", asset.os_name or "", asset.os_version or "", asset.tags or ""]).lower()
    for plat, pat in NET_GUESS:
        if re.search(pat, text):
            return plat
    return ""


def eligible(asset: Asset, op: str) -> bool:
    kinds = OPERATIONS[op]["kinds"]
    if "network" in kinds:
        return bool(asset.platform or guess_platform(asset))
    if "cyberark" in kinds:
        return bool(asset.cyberark_role)
    return asset.os_family in kinds and not asset.platform and not asset.cyberark_role and (op != "agent_install" or agent_for(asset) is None)


# --------------------------------------------------------------------------- inventário (com credenciais cifradas → ficheiro temporário 0600)


WINRM_TRANSPORTS = ("ntlm", "basic", "credssp", "kerberos", "ssl")


WINDOWS_TRANSPORTS = ("wmi", "winrm", "ssh")
TRANSPORTS = {"": "Automático (Linux/macOS: SSH · Windows: WMI)", "ssh": "SSH", "wmi": "WMI/DCOM + SMB (Windows, sem agente)", "winrm": "WinRM (Windows)",
              "agent": "Através do agente OMXPatch (procuração)"}


def windows_transport(opts: dict, explicit: str = "") -> str:
    """Ligação sem agente ao Windows: o que o ativo indica; senão o da credencial; senão o global (WMI por omissão)."""
    from flask import current_app
    if explicit in WINDOWS_TRANSPORTS:
        return explicit
    if opts.get("_kind") == "ssh_key":
        return "ssh"
    if opts.get("windows_connection") in WINDOWS_TRANSPORTS:
        return opts["windows_connection"]
    default = str(current_app.config.get("ANSIBLE_WINDOWS_TRANSPORT", "wmi"))
    return default if default in WINDOWS_TRANSPORTS else "wmi"


def _winrm_vars(opts: dict, kind: str = "", transport: str = "") -> dict:
    """Variáveis de ligação ao Windows SEM agente. WMI/DCOM + SMB (omissão): nada a instalar nem ativar no Windows além da firewall e de uma conta
    de administrador. WinRM (NTLM sobre HTTPS) e SSH (OpenSSH Server) continuam disponíveis."""
    transport = transport or windows_transport(opts | {"_kind": kind})
    if transport == "wmi":
        return {"ansible_connection": "omx_wmi", "ansible_shell_type": "powershell"}
    if transport == "ssh" or kind == "ssh_key":
        return {"ansible_connection": "ssh", "ansible_shell_type": "powershell"}
    t = opts.get("winrm_transport") if opts.get("winrm_transport") in WINRM_TRANSPORTS else "ntlm"
    return {"ansible_connection": "winrm", "ansible_winrm_transport": t, "ansible_winrm_scheme": "https",
            "ansible_winrm_server_cert_validation": "ignore" if opts.get("validate_certs") is False else "validate"}


def connection_problems(asset: Asset, transport: str | None = None) -> list[str]:
    """O que falta para o Ansible conseguir ligar-se ao ativo (evita erros crípticos como «auth method ssl requires a username»)."""
    if (transport if transport is not None else asset.ansible_transport) == "agent" and not asset.platform:
        ok, why = agent_usable(asset)
        return [] if ok else [why]
    from ..connectors import store
    from ..models import AnsibleCredential
    cred = db.session.get(AnsibleCredential, asset.credential_id) if asset.credential_id else None
    user = asset.ansible_user or (cred.username if cred else "")
    sec = {}
    if cred is not None and cred.tenant_id == asset.tenant_id:
        try:
            sec = store.decrypt_json(cred.secret)
        except Exception:  # noqa: BLE001 - chave de cifra alterada: o erro aparece ao executar
            sec = {}
    out = []
    if asset.platform in ("fortios", "panos"):
        if not sec.get("api_token"):
            out.append("falta uma credencial do tipo «Token / chave de API» (utilizador de API só de leitura)")
        return out
    if not user:
        out.append("falta o utilizador (campo «Utilizador Ansible» do ativo ou o utilizador da credencial)")
    is_windows = asset.os_family == "windows" or (asset.cyberark_role and asset.cyberark_role != "psmp")
    if is_windows:
        opts = dict(sec.get("opts") or {})
        opts["_kind"] = cred.kind if cred is not None else ""
        tr = windows_transport(opts, transport if transport is not None else asset.ansible_transport or "")
        if tr in ("wmi", "winrm") and not sec.get("password"):
            out.append(f"o Windows por {'WMI' if tr == 'wmi' else 'WinRM'} precisa de uma credencial com palavra-passe (conta de administrador)")
        elif tr == "ssh" and not sec.get("password") and not sec.get("ssh_key"):
            out.append("o Windows por SSH precisa de palavra-passe ou chave SSH")
    return out


_HINTS = (
    (r"(?i)impacket|falta a biblioteca", "Falta a biblioteca do WMI no servidor: sudo /opt/omxpatch/venv/bin/omxpatch ansible-doctor --fix"),
    (r"(?i)tcp 135|dcom|rpc_s_access_denied|sem ligação a .* confirme", "WMI/DCOM sem acesso: abra TCP 135, 445 e as portas RPC dinâmicas (49152–65535) no Windows («Windows Management Instrumentation» e «Partilha de Ficheiros e Impressoras»), "
     "use uma conta de administrador e, para conta local, LocalAccountTokenFilterPolicy=1. Teste em Motor Ansible → «Testar ligação»."),
    (r"requires a username", "Falta o utilizador de ligação: associe ao ativo uma credencial com utilizador (e palavra-passe no Windows) ou preencha «Utilizador Ansible»."),
    (r"(?i)401|unauthorized|credentials were rejected|authentication failed|invalid credentials|logon failure",
     "Utilizador ou palavra-passe recusados. No Windows confirme também o transporte WinRM da credencial (NTLM por omissão) e que o utilizador pertence a «Administrators»."),
    (r"(?i)certificate verify failed|ssl: .*certificate|CERTIFICATE_VERIFY_FAILED|hostname .* doesn't match",
     "Certificado do WinRM não confiável (autoassinado ou nome diferente). Instale a CA no servidor OMXPatch ou, em laboratório, desmarque «Validar certificado» na credencial."),
    (r"(?i)connection refused|timed out|timeout|no route to host|name or service not known|nodename nor servname|temporary failure in name resolution|unreachable",
     "Sem ligação ao equipamento: confirme o nome/IP, a porta (WinRM HTTPS 5986; SSH 22), a firewall e, no Windows, que o WinRM está ativo (Enable-PSRemoting -Force e um listener HTTPS)."),
    (r"(?i)permission denied \(publickey|no authentication methods available|host key verification failed",
     "SSH recusado: a chave/palavra-passe não serve ou a chave do equipamento não é confiável. Com «Ansible aceita a chave SSH na 1.ª ligação» (Sistema → Configuração) a chave é aceite e registada na 1.ª ligação; se o equipamento mudou de chave, apague a linha em <dados>/ansible/known_hosts."),
    (r"(?i)a password is required|sudo: .*password", "O utilizador precisa de sudo sem palavra-passe, ou marque na credencial «usar a palavra-passe também para sudo»."),
    (r"(?i)couldn't resolve module/action|collection .* not found", "Faltam coleções Ansible no servidor: sudo /opt/omxpatch/venv/bin/omxpatch ansible-doctor --fix"),
)


def explain(output: str) -> list[str]:
    """Explicações em português para os erros mais comuns do Ansible (mostradas no detalhe do trabalho)."""
    out = []
    for pat, text in _HINTS:
        if re.search(pat, output or "") and text not in out:
            out.append(text)
    return out


def agent_for(asset: Asset):
    """Agente ativo do ativo (None se não houver)."""
    from ..models import Agent
    return Agent.query.filter_by(asset_id=asset.id, revoked=False).first() if asset.id else None


def agent_usable(asset: Asset) -> tuple[bool, str]:
    """O agente do ativo pode servir de procuração? (consola ativa, agente recente e com a permissão local ``allow-exec``)"""
    from datetime import timedelta
    from flask import current_app
    if not current_app.config.get("AGENT_EXEC_ENABLED"):
        return False, "a execução através do agente está desativada na consola (Sistema → Configuração → AGENT_EXEC_ENABLED)"
    ag = agent_for(asset)
    if ag is None:
        return False, "o ativo não tem agente OMXPatch"
    if not ag.last_seen or utcnow() - ag.last_seen > timedelta(minutes=int(current_app.config["AGENT_OFFLINE_MINUTES"])):
        return False, "o agente está offline"
    if not ag.status.get("exec_allowed"):
        return False, "o agente não permite execução remota: no equipamento execute «omxpatch-agent config allow-exec on» (administrador local)"
    return True, ""


def _agent_vars(a: Asset) -> dict:
    """Ligação pela procuração do agente: sem credenciais, sem portas de entrada; PowerShell em Windows, shell POSIX nos restantes."""
    win = a.os_family == "windows" or (a.cyberark_role and a.cyberark_role != "psmp")
    return {"ansible_connection": "omx_agent", "ansible_shell_type": "powershell" if win else "sh", "omx_asset_id": a.id, "ansible_become": False}


def _ssh_args(opts: dict) -> str:
    """Argumentos SSH: ficheiro known_hosts na pasta de trabalho do serviço (a «home» do utilizador do serviço é só de leitura) e, por omissão,
    aceitação da chave do equipamento na 1.ª ligação (``accept-new``: se mudar depois, a ligação é recusada)."""
    from flask import current_app
    from . import ansible_runner
    kh = ansible_runner.ansible_home() / "known_hosts"
    accept = opts.get("ssh_accept_new")
    if accept is None:
        accept = bool(current_app.config.get("ANSIBLE_SSH_ACCEPT_NEW", True))
    return f"-o UserKnownHostsFile={kh}" + (" -o StrictHostKeyChecking=accept-new" if accept else "")


def build_inventory(assets: list[Asset], transports: dict | None = None) -> dict:
    from ..connectors import store
    from ..models import AnsibleCredential
    hosts: dict[str, dict] = {}
    groups: dict[str, list[str]] = {}

    def add(group: str, key: str) -> None:
        groups.setdefault(group, []).append(key)
    creds = {}
    for a in assets:
        key = f"asset{a.id}"
        v: dict = {"ansible_host": a.fqdn or a.ip or a.name, "omx_asset_id": a.id}
        explicit = (transports or {}).get(a.id) or a.ansible_transport or ""
        via_agent = explicit == "agent" and not a.platform                                                  # equipamentos de rede não têm agente
        if via_agent:
            v.update(_agent_vars(a))
        if a.ansible_user and not via_agent:
            v["ansible_user"] = a.ansible_user
        if a.ansible_port:
            v["ansible_port"] = a.ansible_port
        c = None
        winrm_opts: dict = {}
        if a.credential_id and not via_agent:                   # pela procuração do agente não são precisas credenciais de ligação
            c = creds.get(a.credential_id) or db.session.get(AnsibleCredential, a.credential_id)
            if c is None or c.tenant_id != a.tenant_id:
                raise EngineError(f"Credencial inválida no ativo {a.name}")
            creds[a.credential_id] = c
            sec = store.decrypt_json(c.secret)
            if c.username and not a.ansible_user:
                v["ansible_user"] = c.username
            winrm_opts = dict(sec.get("opts") or {})
            winrm_opts["_kind"] = c.kind
            if c.kind == "password" and sec.get("password"):
                v["ansible_password"] = sec["password"]
                if c.become_password:
                    v["ansible_become_password"] = sec["password"]
            elif c.kind == "ssh_key" and sec.get("ssh_key"):
                v["__ssh_key__"] = sec["ssh_key"]
                if sec.get("passphrase"):
                    v["ansible_ssh_private_key_passphrase"] = sec["passphrase"]
            elif c.kind == "api_token" and sec.get("api_token"):
                v["omx_api_token"] = sec["api_token"]
        if a.platform:
            if a.platform in NET_OS:
                v.update({"ansible_connection": "ansible.netcommon.network_cli", "ansible_network_os": NET_OS[a.platform]})
                if a.platform == "cisco_ios" and v.get("ansible_become_password"):
                    v.update({"ansible_become": True, "ansible_become_method": "enable"})
            elif a.platform in ("fortios", "panos"):
                v["ansible_connection"] = "local"
            v["omx_validate_certs"] = winrm_opts.get("validate_certs", True) is not False
            v["omx_fw_opts"] = {k: winrm_opts[k] for k in ("group_block", "group_isolate", "vsys", "cp_package", "cp_targets", "cp_domain", "tag_block", "tag_isolate") if winrm_opts.get(k)}
            add(f"net_{a.platform}", key)
        elif a.cyberark_role:
            v["omx_component"] = a.cyberark_role
            if a.cyberark_role != "psmp":
                if not via_agent:
                    v.update(_winrm_vars(winrm_opts, winrm_opts.get('_kind', ''), windows_transport(winrm_opts, explicit)))
                add("windows", key)
            else:
                add("linux", key)
            add(f"cyberark_{a.cyberark_role}", key)
        elif a.os_family:
            if a.os_family == "windows" and not via_agent:
                v.update(_winrm_vars(winrm_opts, winrm_opts.get('_kind', ''), windows_transport(winrm_opts, explicit)))
            add(a.os_family, key)
        if v.get("ansible_connection") == "omx_wmi" and winrm_opts.get("domain"):
            v["omx_domain"] = winrm_opts["domain"]
        if v.get("ansible_connection") == "omx_wmi":
            v.pop("ansible_port", None)                                    # a porta do ativo é do SSH/WinRM; o WMI usa 135/445
        if not via_agent and v.get("ansible_connection") in (None, "ssh", "ansible.netcommon.network_cli"):
            v["ansible_ssh_common_args"] = _ssh_args(winrm_opts)
            if v.get("ansible_connection") == "ansible.netcommon.network_cli":
                v["ansible_host_key_auto_add"] = bool(winrm_opts.get("ssh_accept_new", True))           # network_cli (paramiko)
        hosts[key] = v
    inv: dict = {"all": {"hosts": hosts}}
    for g, members in groups.items():
        inv[g] = {"hosts": {m: {} for m in members}}
    return inv


# --------------------------------------------------------------------------- criação de trabalhos


def _assets(tenant: Tenant, ids: list[int], op: str) -> list[Asset]:
    rows = Asset.query.filter(Asset.tenant_id == tenant.id, Asset.id.in_(ids or [0])).all()
    bad = [a.name for a in rows if (a.connection != "ansible" and a.ansible_transport != "agent") or not eligible(a, op)]
    if not rows:
        raise EngineError("Selecione pelo menos um ativo.")
    if bad:
        raise EngineError("Ativos não elegíveis para esta operação (têm de usar «Sem agente (Ansible)» e a plataforma/componente certos): " + ", ".join(bad[:5]))
    return rows


def _fresh_assessment(asset: Asset, op: str, now=None) -> Task | None:
    cfg = OPERATIONS[op]
    now = now or utcnow()
    for t in Task.query.filter(Task.tenant_id == asset.tenant_id, Task.asset_id == asset.id, Task.type == cfg["task"], Task.status == "succeeded",
                               Task.finished_at > now - APPLY_FRESHNESS).order_by(Task.id.desc()):
        p = t.payload_data
        if p.get("mode") == "assess" and p.get("op") == op:
            return t
    return None


def _payload(op: str, mode: str, options: dict, user) -> dict:
    cfg = OPERATIONS[op]
    p: dict = {"op": op, "mode": mode, "requested_by": getattr(user, "email", "") or "consola"}
    if cfg["scope"]:
        p["omx_scope"] = cfg["scope"]
        p["reboot_policy"] = options.get("reboot_policy") if options.get("reboot_policy") in ("never", "if_needed", "force") else "if_needed"
        p["security_only"] = bool(options.get("security_only"))
    return p


def create_job(tenant: Tenant, user, op: str, asset_ids: list[int], mode: str, options: dict | None = None) -> list[Task]:
    """Cria uma tarefa por ativo (avaliar ou aplicar). ``apply`` exige avaliação recente, OK explícito e, no CyberArk, o pacote do fabricante."""
    options = options or {}
    if op not in OPERATIONS:
        raise EngineError("Operação desconhecida")
    if mode not in ("assess", "apply") or (op == "network" and mode != "assess"):
        raise EngineError("Modo inválido (os equipamentos de rede só admitem avaliação)")
    assets = _assets(tenant, asset_ids, op)
    if op in ("os", "software", "all"):
        netlike = [a for a in assets if a.kind == "network" or guess_platform(a)]
        if netlike:
            from ..models import NET_PLATFORMS
            raise EngineError("Estes ativos parecem equipamentos de rede/firewall, não servidores: " + ", ".join(f"{a.name}" + (f" ({NET_PLATFORMS[guess_platform(a)]})" if guess_platform(a) else "") for a in netlike[:5])
                              + ". Defina a «Plataforma de rede / firewall» no ativo e use a operação «Avaliar atualizações de switches, routers e firewalls».")
    if op == "network":
        for a in assets:
            if not a.platform and (g := guess_platform(a)):
                a.platform = g                                           # primeira avaliação: assume a plataforma provável
    transports: dict[int, str] = {}
    problems = []
    for a in assets:
        p = connection_problems(a)
        if p and op != "agent_install" and not a.ansible_transport and not a.platform and _fallback_on() and agent_usable(a)[0]:
            transports[a.id] = "agent"                          # sem credenciais/ligação direta, mas há agente que o permite: usa-o como procuração
        elif p:
            problems.append(f"{a.name}: {'; '.join(p)}")
    if problems:
        raise EngineError("Não é possível ligar a: " + " | ".join(problems[:5]) + ". Defina a credencial no ativo (Ativos → editar → «Credencial Ansible») e crie-a em Motor Ansible → Credenciais.")
    base = _payload(op, mode, options, user)
    if op == "agent_install":
        mode = "apply"                                              # não há «avaliação»: a instalação é pedida explicitamente pelo administrador
        base["mode"] = "apply"
    elif mode == "apply":
        if not options.get("confirm_ok"):
            raise EngineError("Aplicar exige o OK explícito do administrador.")
        missing = [a.name for a in assets if _fresh_assessment(a, op) is None]
        if missing:
            raise EngineError("Faça primeiro a avaliação (últimas 24 h) destes ativos: " + ", ".join(missing[:5]))
    if op == "cyberark":
        base.update(_cyberark_options(options, mode))
        assets = sorted(assets, key=lambda a: CYBERARK_ORDER.index(a.cyberark_role))
    tasks: list[Task] = []
    prev_stage: list[Task] = []             # etapa anterior (mesmo componente) de que esta depende
    cur_stage: list[Task] = []
    stage_role = None
    for a in assets:
        p = dict(base)
        status = "queued"
        if op == "cyberark" and mode == "apply":
            if a.cyberark_role != stage_role:               # mudou de componente: a etapa que acabou passa a ser a «anterior»
                prev_stage, cur_stage, stage_role = cur_stage, [], a.cyberark_role
            if prev_stage:
                p["after"] = [t.id for t in prev_stage]
                status = "waiting_dep"
        if a.id in transports:
            p["transport"] = "agent"
        t = Task(tenant_id=tenant.id, type=OPERATIONS[op]["task"], asset_id=a.id, ring=a.ring, mode="ansible", status=status, payload=json.dumps(p))
        db.session.add(t)
        db.session.flush()
        tasks.append(t)
        cur_stage.append(t)
    return tasks


def _cyberark_options(o: dict, mode: str) -> dict:
    out = {"cyberark_target_version": str(o.get("target_version") or "")[:40], "cyberark_media_sha256": str(o.get("media_sha256") or "").strip().lower(),
           "cyberark_media_src": str(o.get("media_src") or "")[:500], "cyberark_upgrade_cmd": str(o.get("upgrade_cmd") or "")[:2000],
           "cyberark_post_cmd": str(o.get("post_cmd") or "")[:2000]}
    if mode == "apply":
        if str(o.get("confirm_word") or "") != CONFIRM_WORD:
            raise EngineError(f"No CyberArk escreva «{CONFIRM_WORD}» para confirmar.")
        if not re.fullmatch(r"[0-9a-f]{64}", out["cyberark_media_sha256"]):
            raise EngineError("Indique o SHA-256 (64 hex) do pacote do fabricante.")
        if not out["cyberark_media_src"].startswith("/") or ".." in out["cyberark_media_src"]:
            raise EngineError("Indique o caminho absoluto do pacote no controlador (ex.: /var/lib/omxpatch/cyberark/CPM-v14.zip).")
        if not out["cyberark_target_version"]:
            raise EngineError("Indique a versão alvo.")
    return out


def release_stages(tenant: Tenant) -> int:
    """Liberta as etapas à espera da anterior (ordem CyberArk); cancela as que dependem de uma etapa falhada."""
    n = 0
    for t in Task.query.filter_by(tenant_id=tenant.id, status="waiting_dep"):
        deps = Task.query.filter(Task.id.in_(t.payload_data.get("after") or [0])).all()
        if any(d.status in ("failed", "cancelled", "rolled_back") for d in deps):
            t.status, t.finished_at = "cancelled", utcnow()
            t.output = "Cancelada: uma etapa anterior (ordem Vault → CPM → PSM → PSMP) falhou."
            n += 1
        elif deps and all(d.status == "succeeded" for d in deps):
            t.status = "queued"
            n += 1
    return n


# --------------------------------------------------------------------------- execução e resultados


def playbook_for(task: Task) -> str | None:
    return PLAYBOOKS.get((task.type, task.asset.os_family)) or PLAYBOOKS.get((task.type, "any"))


def _fallback_on() -> bool:
    from flask import current_app
    return bool(current_app.config.get("AGENT_EXEC_FALLBACK", True)) and bool(current_app.config.get("AGENT_EXEC_ENABLED"))


def _run_once(task: Task, pb: str, transport: str | None) -> dict:
    from . import ansible_runner
    p = dict(task.payload_data)
    extra = {k: v for k, v in p.items() if k not in ("op", "requested_by", "after", "transport")}
    extra["omx_mode"] = p.get("mode", "assess")
    extra["task_id"] = task.id
    inv = build_inventory([task.asset], {task.asset_id: transport} if transport else None)
    return ansible_runner.run_playbook(pb, inv, extra, limit=f"asset{task.asset_id}", timeout_minutes=240 if task.type == "cyb_upgrade" else None)


def run_task(task: Task) -> dict:
    if task.type == "agent_inst":
        from . import agent_deploy
        return agent_deploy.run(task)
    pb = playbook_for(task)
    if pb is None:
        return {"status": "failed", "output": f"Sem playbook para {task.type}/{task.asset.os_family or '?'}"}
    transport = task.payload_data.get("transport") or task.asset.ansible_transport or None
    res = _run_once(task, pb, transport)
    note = ""
    if res["rc"] != 0 and transport != "agent" and not task.asset.platform and "UNREACHABLE" in (res["output"] or "") and _fallback_on() and agent_usable(task.asset)[0]:
        first = res["output"]
        res = _run_once(task, pb, "agent")                       # «caso não seja possível a operação sem agente»: repete através do agente
        note = "[Ligação direta impossível — repetido através do agente OMXPatch (procuração)]\n--- tentativa direta ---\n" + _scrub(first)[-3000:] + "\n--- através do agente ---\n"
    data = res["result"] or {}
    status = data.get("status") or ("succeeded" if res["rc"] == 0 else "failed")
    if res["rc"] != 0:
        status = "failed"
    for k in ("raw_winget", "raw_choco"):
        if isinstance(data.get(k), str):
            data[k] = data[k][:200000]
    return {**data, "status": status, "exit_code": res["rc"], "output": note + _scrub(res["output"]), "via_agent": bool(note) or transport == "agent"}


def housekeeping(tenant: Tenant) -> int:
    """Limpa as tarefas de execução remota antigas (podem conter comandos/saídas com segredos) e os ficheiros temporários."""
    import time
    from datetime import timedelta
    from pathlib import Path
    from flask import current_app
    n = 0
    for t in Task.query.filter(Task.tenant_id == tenant.id, Task.type == "exec", Task.created_at < utcnow() - timedelta(hours=1)):
        if t.payload != '{"limpo": true}' and '"limpo"' not in (t.payload or ""):
            t.payload, t.result, t.output = '{"limpo": true}', "{}", ""
            n += 1
    d = Path(current_app.config["DATA_DIR"]) / "ansible-blobs"
    if d.is_dir():
        for f in d.iterdir():
            if f.is_file() and time.time() - f.stat().st_mtime > 24 * 3600:
                f.unlink(missing_ok=True)
    return n


def _scrub(text: str) -> str:
    """Remove segredos que o Ansible possa ecoar (palavras-passe, tokens)."""
    return re.sub(r"(?i)(password|passphrase|token|api[_-]?key|secret)(\"?\s*[:=]\s*\"?)[^\s\",}]+", r"\1\2[removido]", text or "")


_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


def on_result(task: Task, report: dict) -> None:
    """Chamado quando uma tarefa do motor termina: grava avaliações de rede e converte pendências em «Atualizações disponíveis»."""
    if task.type == "net_assess":
        from . import netassess
        netassess.process(task, report)
        return
    p = task.payload_data
    if task.type in ("os_update", "sw_update") and p.get("mode") == "assess" and report.get("status") == "succeeded":
        from . import updates
        items = []
        pending = list(report.get("pending") or [])
        if task.asset.os_family == "windows":                 # winget/choco: o playbook devolve o texto; as colunas lêem-se com os mesmos analisadores do agente
            from omxpatch_agent.updates import windows as winp
            pending += [{"name": u["name"] or u["id"], "package": u["id"], "current_version": u["current"], "new_version": u["new"], "source": "winget"}
                        for u in winp.parse_winget_upgrade(str(report.get("raw_winget") or ""))[:200]]
            pending += [{"name": u["name"], "current_version": u["current"], "new_version": u["new"], "source": "choco"}
                        for u in winp.parse_choco_outdated(str(report.get("raw_choco") or ""))[:200]]
        for it in pending[:updates.MAX_ITEMS]:
            if not isinstance(it, dict) or not it.get("name"):
                continue
            src = str(it.get("source") or "ansible")[:16]
            items.append({"source": src, "uid": str(it.get("kb") or it["name"])[:190], "name": it.get("name"), "title": it.get("name"),
                          "current_version": it.get("current_version", ""), "new_version": it.get("new_version", ""), "kb": it.get("kb", ""),
                          "severity": _SEV.get(str(it.get("severity") or ("high" if it.get("security") else "medium")), "medium"),
                          "category": "security" if it.get("security") or it.get("severity") in ("critical", "high") else "update",
                          "reboot": bool(it.get("reboot")), "installer": "ansible", "package": it.get("package") or it.get("name"), "origin": "Motor Ansible"})
        scan = {"scan_id": f"ansible-{task.id}", "scanned_at": __import__("time").time(), "updates": items, "sources": {s: {"ok": True, "count": sum(1 for i in items if i["source"] == s)}
                                                                                                      for s in {i["source"] for i in items}}}
        tenant = db.session.get(Tenant, task.tenant_id)
        try:
            updates.ingest(tenant, None, task.asset, scan)
        except updates.ScanError:
            pass
