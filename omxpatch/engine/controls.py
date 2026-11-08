"""Módulo 8 — Compensating Controls (quando não existe patch, ou enquanto o patch não é aplicado).

Ações por categoria: Firewall (bloquear IOC / porta / país) · EDR (criar deteção / bloqueio) · SIEM (nova regra /
correlação) · IAM (desativar conta / forçar MFA) · WAF (virtual patch).

Fluxo: **proposto → aprovado (humano) → aplicado → verificado**; o controlo é revertido quando a exposição é
fechada pelo patch (``retire_for``). Cada proposta traz o *artefacto* pronto a usar (regra de firewall, KQL, SPL,
Sigma, ModSecurity, PowerShell/Graph) e a redução de risco prevista (``risk.CONTROL_EFFECT``).
Hosts: firewall local por agente (tarefa *control*) ou Ansible; restantes categorias por conector configurado.
"""
from __future__ import annotations

import json
import re

from ..extensions import db
from ..models import (CONTROL_ACTIONS, Asset, ControlAction, CveIntel, Exposure, Signal, Task, Tenant, jloads, utcnow)
from . import risk

WEB_HINT = re.compile(r"apache|nginx|iis|tomcat|httpd|wordpress|jboss|weblogic|struts|joomla|drupal|confluence|jenkins|"
                      r"grafana|spring|php", re.I)
REMOTE_HINT = re.compile(r"vpn|rdp|remote desktop|citrix|openssh|ssh|anydesk|teamviewer|globalprotect|fortigate|pulse", re.I)
CWE_WAF = {
    "CWE-22": ('@rx (?:\\.\\./|\\.\\.\\\\|%2e%2e%2f)', "Path traversal"),
    "CWE-78": ('@rx (?:;|\\||`|\\$\\()\\s*(?:cat|id|whoami|curl|wget|bash|sh|powershell)\\b', "Command injection"),
    "CWE-77": ('@rx (?:;|\\||`|\\$\\()\\s*(?:cat|id|whoami|curl|wget|bash|sh)\\b', "Command injection"),
    "CWE-89": ('@rx (?i:union\\s+select|or\\s+1=1|sleep\\(\\d+\\)|benchmark\\()', "SQL injection"),
    "CWE-79": ('@rx (?i:<script|javascript:|onerror\\s*=)', "XSS"),
    "CWE-502": ('@rx (?i:rO0AB|aced0005|java\\.lang\\.Runtime|ysoserial)', "Desserialização insegura"),
    "CWE-918": ('@rx (?i:169\\.254\\.169\\.254|metadata\\.google\\.internal|file://|gopher://)', "SSRF"),
    "CWE-917": ('@rx (?i:\\$\\{(?:jndi|env|sys|lower|upper)[:}])', "Injeção de expressões (ex.: Log4Shell)"),
}


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", text)[:40].strip("-")


def rule_name(cve_id: str, action: str, port: int | str = "") -> str:
    return f"OMXPatch-{cve_id}-{action}{('-' + str(port)) if port else ''}"


# --------------------------------------------------------------------------- artefactos


def artifact(action: str, cve_id: str, asset: Asset | None, params: dict, cve: CveIntel | None = None) -> str:
    if action == "isolate_host":
        return ("# Isolamento preventivo (o agente mantém só a ligação à consola; validade máx. %s min; desfaz-se se a consola ficar inacessível)\n"
                "# Linux (nftables): política drop em input/output com exceção para loopback, ligações estabelecidas e a consola\n"
                "# Windows: Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Block + regras Allow para a consola\n"
                "# macOS (pf): block drop quick all, exceto loopback e a consola\n") % params.get("ttl_minutes", 120)
    name = rule_name(cve_id, action, params.get("port", ""))
    port, proto = params.get("port"), (params.get("proto") or "tcp").lower()
    host = asset.name if asset else "<ativo>"
    if action == "block_port":
        return (f"# Linux (nftables)\nnft add rule inet filter input {proto} dport {port} drop comment \"{name}\"\n"
                f"# Linux (ufw)\nufw deny in proto {proto} to any port {port} comment '{name}'\n"
                f"# Windows\nnetsh advfirewall firewall add rule name=\"{name}\" dir=in action=block protocol={proto.upper()} localport={port}\n"
                f"# macOS (pf)\necho 'block in proto {proto} from any to any port {port}' | pfctl -a omxpatch -f -\n")
    if action == "block_ioc":
        ioc = params.get("ioc", "<ioc>")
        return (f"# IOC {ioc}\niptables -A OUTPUT -d {ioc} -j DROP -m comment --comment \"{name}\"\n"
                f"New-NetFirewallRule -DisplayName \"{name}\" -Direction Outbound -RemoteAddress {ioc} -Action Block\n"
                f"# NGFW: criar objeto de endereço/domínio '{ioc}' e regra de negação (origem: {host})\n")
    if action == "block_country":
        cc = params.get("country", "??")
        return (f"# NGFW (Palo Alto / Fortinet / Check Point): regra de negação por geolocalização\n"
                f"country = {cc}; destino = {host}; serviço = {params.get('port', 'qualquer')}; nome = {name}\n")
    if action == "edr_detection":
        proc = params.get("process", "*")
        return (f"title: {name} — comportamento pós-exploração ({cve_id})\nstatus: experimental\n"
                "logsource: {category: process_creation}\ndetection:\n  selection:\n"
                f"    ParentImage|endswith: '{proc}'\n    Image|endswith: ['\\\\cmd.exe', '\\\\powershell.exe', '/bin/sh', '/bin/bash']\n"
                "  condition: selection\nlevel: high\n")
    if action == "edr_block":
        return (f"# Regra de bloqueio EDR ({name})\nAlvo: processo-filho de shell lançado por '{params.get('process', '*')}' em {host}\n"
                "Defender XDR: Indicator/ASR 'Block process creations from PSExec/WMI' + custom detection com ação de isolamento\n"
                "SentinelOne: Restriction/Deep Visibility rule; CrowdStrike: Custom IOA (Process Creation) em modo Prevent\n")
    if action == "siem_rule":
        port_f = f" and DestinationPort == {port}" if port else ""
        return (f"// Microsoft Sentinel (KQL) — {cve_id}\nCommonSecurityLog | where Message has \"{cve_id}\" or DeviceCustomString1 has \"{cve_id}\"\n"
                f"| where DeviceName == \"{host}\"{port_f}\n\n"
                f"# Splunk (SPL)\nindex=* (\"{cve_id}\" OR signature=\"*{cve_id}*\") host=\"{host}\" | stats count by src, dest, signature\n\n"
                f"# Elastic (EQL)\nany where event.original : \"*{cve_id}*\" and host.name == \"{host}\"\n")
    if action == "siem_correlation":
        return (f"// Correlação {name}\nlet vuln = \"{host}\";\n"
                f"SecurityAlert | where Entities has vuln and (AlertName has \"exploit\" or Description has \"{cve_id}\")\n"
                f"| join kind=inner (SecurityEvent | where Computer == vuln and EventID in (4688, 4624)) on $left.SystemAlertId == $right.Computer\n"
                "// Corrobora alerta de exploração com criação de processos / logons no ativo vulnerável\n")
    if action == "disable_account":
        acc = params.get("account", "<conta>")
        return (f"Disable-ADAccount -Identity '{acc}'\n# Entra ID (Graph): PATCH /users/{acc} {{\"accountEnabled\": false}}\n")
    if action == "force_mfa":
        return ("# Entra ID: política de Acesso Condicional — exigir MFA para a aplicação/grupo afetados\n"
                f"# Âmbito: {params.get('scope', host)} · motivo: {cve_id}\n"
                "# AD FS/VPN: ativar segundo fator no perfil de ligação\n")
    if action == "virtual_patch":
        rules = []
        cwes = [c.strip() for c in (cve.cwe if cve else "").split(",") if c.strip()]
        for i, cwe in enumerate(cwes):
            if cwe in CWE_WAF:
                pattern, label = CWE_WAF[cwe]
                rules.append(f"SecRule REQUEST_URI|ARGS|REQUEST_HEADERS|REQUEST_BODY \"{pattern}\" "
                             f"\"id:{9100000 + (abs(hash(cve_id)) % 9000) * 10 + i},phase:2,deny,status:403,log,"
                             f"msg:'{name} virtual patch ({label})',tag:'{cve_id}'\"")
        if not rules:
            rules.append(f"# Sem padrão genérico para {cve_id} ({cve.cwe if cve else 'CWE n/d'}): "
                         "importar a assinatura do fabricante do WAF e ativá-la em modo bloqueio")
        return "\n".join(["# ModSecurity / OWASP CRS (equivalente noutros WAF)"] + rules) + "\n"
    return ""


# --------------------------------------------------------------------------- propostas


def _exists(tenant_id: int, cve_id: str, asset_id: int | None, action: str, params: dict) -> bool:
    return any(c.params_data.get("port") == params.get("port") and c.params_data.get("ioc") == params.get("ioc")
               for c in ControlAction.query.filter(ControlAction.tenant_id == tenant_id, ControlAction.cve_id == cve_id,
                                                   ControlAction.asset_id == asset_id, ControlAction.action == action,
                                                   ControlAction.status.notin_(("rejected", "reverted"))))


def make(tenant: Tenant, ex: Exposure | None, action: str, params: dict, cve_id: str = "", asset: Asset | None = None,
         user=None) -> ControlAction:
    if action not in CONTROL_ACTIONS:
        raise ValueError("Ação desconhecida")
    cve_id = cve_id or (ex.cve_id if ex else "")
    asset = asset or (ex.asset if ex else None)
    cve = CveIntel.query.filter_by(cve_id=cve_id).first() if cve_id else None
    cat = CONTROL_ACTIONS[action][0]
    c = ControlAction(tenant_id=tenant.id, cve_id=cve_id, asset_id=asset.id if asset else None,
                      exposure_id=ex.id if ex else None, category=cat, action=action, params=json.dumps(params),
                      artifact=artifact(action, cve_id, asset, params, cve), status="proposed",
                      created_by_id=getattr(user, "id", None))
    if ex is not None:
        base = ex.risk_score
        eff = risk.CONTROL_EFFECT.get(action, {})
        pts = {f["key"]: f["points"] for f in ex.factor_list}
        c.risk_reduction = int(round(sum(pts.get(k, 0) * (1 - m) for k, m in eff.items()))) if pts else 0
        c.risk_reduction = min(c.risk_reduction, base)
    db.session.add(c)
    return c


def suggest_specs(ex: Exposure, cve: CveIntel | None = None) -> list[tuple[str, dict]]:
    """Controlos aplicáveis a uma exposição (sem tocar na base de dados): [(ação, parâmetros)]."""
    cve = cve or CveIntel.query.filter_by(cve_id=ex.cve_id).first()
    asset = ex.asset
    out: list[tuple[str, dict]] = []
    ports = [ex.port] if ex.port else (asset.ports if (cve and cve.kev) or ex.risk_category in ("critical", "emergency") else [])
    watch = [p for p in ports if p and p not in (22, 3389)] or ([ex.port] if ex.port else [])
    for p in watch[:2]:
        out.append(("block_port", {"port": int(p), "proto": "tcp", "direction": "in"}))
    process = re.sub(r"\s+", "", ex.software_name.split(" ")[0]) if ex.software_name else "*"
    if (cve and (cve.kev or cve.exploit_maturity in ("functional", "weaponized"))) or ex.risk_category in ("critical", "emergency"):
        out.append(("edr_detection", {"process": process}))
        out.append(("siem_rule", {"port": ex.port} if ex.port else {}))
    if cve and (cve.ransomware or ex.risk_category == "emergency"):
        out.append(("edr_block", {"process": process}))
    if WEB_HINT.search(ex.software_name or "") or any((c in CWE_WAF) for c in (cve.cwe.split(",") if cve else [])):
        out.append(("virtual_patch", {"software": ex.software_name}))
    if REMOTE_HINT.search(ex.software_name or "") and cve and cve.kev:
        out.append(("force_mfa", {"scope": ex.software_name}))
    for s in Signal.query.filter_by(tenant_id=ex.tenant_id, kind="ioc", cve_id=ex.cve_id).limit(5):
        out.append(("block_ioc", {"ioc": s.value}))
    return out


def propose_for(tenant: Tenant, ex: Exposure) -> list[ControlAction]:
    """Cria propostas (sem duplicar as existentes)."""
    out: list[ControlAction] = []
    for action, params in suggest_specs(ex):
        if not _exists(tenant.id, ex.cve_id, ex.asset_id, action, params):
            out.append(make(tenant, ex, action, params))
    return out


# --------------------------------------------------------------------------- ciclo de vida


def approve(c: ControlAction, user=None) -> ControlAction:
    if c.status != "proposed":
        raise ValueError("Só controlos propostos podem ser aprovados")
    c.status = "approved"
    return c


def reject(c: ControlAction) -> ControlAction:
    c.status = "rejected"
    return c


MANAGEMENT_PORTS = {22: "SSH", 3389: "RDP", 5985: "WinRM", 5986: "WinRM (TLS)", 445: "SMB"}


def apply(c: ControlAction, tenant: Tenant) -> ControlAction:
    """Aplica um controlo aprovado: agente/Ansible no host (firewall) ou conector (EDR/SIEM/IAM/WAF/NGFW)."""
    if c.status not in ("approved", "failed"):
        raise ValueError("Aprove o controlo antes de o aplicar")
    from . import itsm
    allowed, why = itsm.gate_control(c, tenant)
    if not allowed:
        raise ValueError(why)
    port = c.params_data.get("port")
    if c.action == "block_port" and port in MANAGEMENT_PORTS and not c.params_data.get("allow_management_port"):
        raise ValueError(f"A porta {port} ({MANAGEMENT_PORTS[port]}) é de gestão: bloqueá-la pode cortar o acesso ao ativo. "
                         "Use uma regra de rede com origens restritas ou confirme com allow_management_port.")
    asset = c.asset
    if c.action == "isolate_host":
        if asset is None or asset.agent is None:
            raise ValueError("O isolamento exige um agente instalado no ativo (é o agente que mantém só a ligação à consola)")
        ttl = max(5, min(int(c.params_data.get("ttl_minutes") or 120), 1440))
        t = Task(tenant_id=tenant.id, type="control", asset_id=asset.id, exposure_id=c.exposure_id, mode="agent", status="queued",
                 payload=json.dumps({"control_id": c.id, "op": "isolate", "ttl_minutes": ttl, "keep_ssh_from": c.params_data.get("keep_ssh_from") or []}))
        db.session.add(t)
        c.via, c.detail = "agent", f"Isolamento pedido (máx. {ttl} min; só a consola fica acessível)"
        return c
    local_fw = c.action in ("block_port", "block_ioc") and asset is not None
    if local_fw:
        op = {"op": "firewall_block_port" if c.action == "block_port" else "firewall_block_ioc",
              "name": rule_name(c.cve_id, c.action, c.params_data.get("port", "")), **c.params_data}
        mode = "ansible" if (asset.connection == "ansible" and asset.agent is None) else "agent"
        t = Task(tenant_id=tenant.id, type="control", asset_id=asset.id, exposure_id=c.exposure_id, mode=mode,
                 status="queued", payload=json.dumps({"control_id": c.id, **op}))
        db.session.add(t)
        c.via = "ansible" if mode == "ansible" else "agent"
        c.detail = "Tarefa de firewall criada"
        return c
    from ..connectors import outbound
    ok, detail = outbound.apply_control(tenant, c)
    c.via, c.detail = (f"connector:{detail.split(':', 1)[0]}" if ok else "manual"), detail
    if ok:
        c.status, c.applied_at = "applied", utcnow()
    else:
        c.detail = detail + " — aplique o artefacto manualmente e marque como aplicado."
    return c


def propose_isolation(tenant: Tenant, asset: Asset, ttl_minutes: int = 120, keep_ssh_from: list | None = None, ex: Exposure | None = None, user=None) -> ControlAction:
    """Propõe o isolamento preventivo do ativo (fica «proposto»: exige aprovação como qualquer controlo)."""
    return make(tenant, ex, "isolate_host", {"ttl_minutes": max(5, min(int(ttl_minutes), 1440)), "keep_ssh_from": list(keep_ssh_from or [])}, cve_id=ex.cve_id if ex else "", asset=asset)


def release_isolation(c: ControlAction, tenant: Tenant) -> Task:
    """Pede ao agente que liberte o isolamento (a consola continua acessível durante todo o isolamento)."""
    if c.action != "isolate_host" or c.asset is None:
        raise ValueError("Não é um controlo de isolamento")
    t = Task(tenant_id=tenant.id, type="control", asset_id=c.asset_id, exposure_id=c.exposure_id, mode="agent", status="queued",
             payload=json.dumps({"control_id": c.id, "revert": True, "op": "isolate_release"}))
    db.session.add(t)
    c.detail = "Libertação do isolamento pedida"
    return t


def mark_applied(c: ControlAction, verified: bool = False) -> ControlAction:
    c.status = "verified" if verified else "applied"
    c.applied_at = c.applied_at or utcnow()
    if verified:
        c.verified_at = utcnow()
    return c


def on_report(task: Task, report: dict) -> None:
    c = db.session.get(ControlAction, task.payload_data.get("control_id") or 0)
    if c is None:
        return
    if task.payload_data.get("revert"):
        c.status = "reverted" if report.get("status") == "succeeded" else c.status
        return
    if report.get("status") == "succeeded":
        c.status, c.applied_at = "applied", utcnow()
        if report.get("verified"):
            c.status, c.verified_at = "verified", utcnow()
        c.detail = (report.get("detail") or "Aplicado")[:500]
        if c.exposure_id:
            from . import correlate
            ex = db.session.get(Exposure, c.exposure_id)
            if ex:
                correlate.refresh(ex)
    else:
        c.status, c.detail = "failed", (report.get("output") or "Falhou")[-500:]


def retire_for(ex: Exposure) -> int:
    """Exposição fechada pelo patch: reverte os controlos temporários do par ativo/CVE."""
    n = 0
    for c in ControlAction.query.filter(ControlAction.tenant_id == ex.tenant_id, ControlAction.cve_id == ex.cve_id,
                                        ControlAction.asset_id == ex.asset_id, ControlAction.expires_when_patched.is_(True),
                                        ControlAction.status.in_(("applied", "verified", "approved", "proposed"))):
        if c.status in ("proposed", "approved"):
            c.status = "rejected"
            c.detail = "Dispensado: patch aplicado antes do controlo."
        elif c.action in ("block_port", "block_ioc") and c.via in ("agent", "ansible"):
            mode = "ansible" if c.via == "ansible" else "agent"
            db.session.add(Task(tenant_id=c.tenant_id, type="control", asset_id=ex.asset_id, mode=mode, status="queued",
                                payload=json.dumps({"control_id": c.id, "revert": True, "op": "firewall_remove",
                                                    "name": rule_name(c.cve_id, c.action, c.params_data.get("port", ""))})))
            c.detail = "Reversão pedida (patch aplicado)"
        else:
            c.status, c.detail = "reverted", "Patch aplicado: remova o controlo temporário no sistema de destino."
        n += 1
    return n


def summary(tenant_id: int) -> dict:
    q = ControlAction.query.filter_by(tenant_id=tenant_id)
    return {s: q.filter_by(status=s).count() for s in ("proposed", "approved", "applied", "verified", "failed")}


__all__ = ["jloads"]
