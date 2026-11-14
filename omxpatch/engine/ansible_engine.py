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
    "network": {"label": "Avaliar atualizações de switches, routers e firewalls (somente leitura)", "task": "net_assess", "scope": "", "kinds": ("network",)},
}
PLAYBOOKS = {("os_update", "windows"): "update_windows.yml", ("os_update", "linux"): "update_linux.yml", ("os_update", "macos"): "update_macos.yml",
             ("sw_update", "windows"): "update_windows.yml", ("sw_update", "linux"): "update_linux.yml", ("sw_update", "macos"): "update_macos.yml",
             ("cyb_upgrade", "any"): "cyberark_upgrade.yml", ("net_assess", "any"): "net_assess.yml"}
TASK_TYPES = ("os_update", "sw_update", "cyb_upgrade", "net_assess")
CYBERARK_ORDER = ("vault", "cpm", "psm", "psmp")
APPLY_FRESHNESS = timedelta(hours=24)
CONFIRM_WORD = "ATUALIZAR"
NET_OS = {"cisco_ios": "cisco.ios.ios", "cisco_nxos": "cisco.nxos.nxos", "junos": "junipernetworks.junos.junos", "eos": "arista.eos.eos"}


class EngineError(ValueError):
    pass


def eligible(asset: Asset, op: str) -> bool:
    kinds = OPERATIONS[op]["kinds"]
    if "network" in kinds:
        return bool(asset.platform)
    if "cyberark" in kinds:
        return bool(asset.cyberark_role)
    return asset.os_family in kinds and not asset.platform and not asset.cyberark_role


# --------------------------------------------------------------------------- inventário (com credenciais cifradas → ficheiro temporário 0600)


def build_inventory(assets: list[Asset]) -> dict:
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
        if a.ansible_user:
            v["ansible_user"] = a.ansible_user
        if a.ansible_port:
            v["ansible_port"] = a.ansible_port
        c = None
        if a.credential_id:
            c = creds.get(a.credential_id) or db.session.get(AnsibleCredential, a.credential_id)
            if c is None or c.tenant_id != a.tenant_id:
                raise EngineError(f"Credencial inválida no ativo {a.name}")
            creds[a.credential_id] = c
            sec = store.decrypt_json(c.secret)
            if c.username and not a.ansible_user:
                v["ansible_user"] = c.username
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
            v["omx_validate_certs"] = True
            add(f"net_{a.platform}", key)
        elif a.cyberark_role:
            v["omx_component"] = a.cyberark_role
            if a.cyberark_role != "psmp":
                v.update({"ansible_connection": "winrm", "ansible_winrm_server_cert_validation": "validate"})
                add("windows", key)
            else:
                add("linux", key)
            add(f"cyberark_{a.cyberark_role}", key)
        elif a.os_family:
            if a.os_family == "windows":
                v.update({"ansible_connection": "winrm", "ansible_winrm_server_cert_validation": "validate"})
            add(a.os_family, key)
        hosts[key] = v
    inv: dict = {"all": {"hosts": hosts}}
    for g, members in groups.items():
        inv[g] = {"hosts": {m: {} for m in members}}
    return inv


# --------------------------------------------------------------------------- criação de trabalhos


def _assets(tenant: Tenant, ids: list[int], op: str) -> list[Asset]:
    rows = Asset.query.filter(Asset.tenant_id == tenant.id, Asset.id.in_(ids or [0])).all()
    bad = [a.name for a in rows if a.connection != "ansible" or not eligible(a, op)]
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
    base = _payload(op, mode, options, user)
    if mode == "apply":
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


def run_task(task: Task) -> dict:
    from . import ansible_runner
    pb = playbook_for(task)
    if pb is None:
        return {"status": "failed", "output": f"Sem playbook para {task.type}/{task.asset.os_family or '?'}"}
    p = dict(task.payload_data)
    extra = {k: v for k, v in p.items() if k not in ("op", "requested_by", "after")}
    extra["omx_mode"] = p.get("mode", "assess")
    extra["task_id"] = task.id
    res = ansible_runner.run_playbook(pb, build_inventory([task.asset]), extra, limit=f"asset{task.asset_id}", timeout_minutes=240 if task.type == "cyb_upgrade" else None)
    data = res["result"] or {}
    status = data.get("status") or ("succeeded" if res["rc"] == 0 else "failed")
    if res["rc"] != 0:
        status = "failed"
    for k in ("raw_winget", "raw_choco"):
        if isinstance(data.get(k), str):
            data[k] = data[k][:200000]
    return {**data, "status": status, "exit_code": res["rc"], "output": _scrub(res["output"])}


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
