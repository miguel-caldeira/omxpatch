"""Simulação prévia (pré-voo) de patches: «o que aconteceria se o instalasse agora?» — sem instalar.

Fluxo: ``start`` cria o registo e uma tarefa *simulate* para o agente (que faz as verificações e o *dry-run* e descarrega o
instalador para o *staging*); ``on_report`` classifica o resultado:

* **blocked**  — alguma verificação *block* (sem privilégios, disco insuficiente, instalador/origem indisponível, assinatura inválida…);
* **warning**  — só avisos (reinício pendente, aplicação em utilização, assinatura ausente…): pode avançar;
* **noop**     — já está aplicado / não é aplicável: nada a instalar;
* **ready**    — tudo ok.

As campanhas com ``require_preflight`` só libertam a instalação dos ativos *ready*/*warning*; os *blocked* e *noop* ficam
ignorados com o motivo, e a decisão fica visível por ativo."""
from __future__ import annotations

import json
from datetime import timedelta

from ..extensions import db
from ..models import Asset, Campaign, Patch, Preflight, Task, Tenant, utcnow
from . import deploy, patches, sources

MAX_AGE = timedelta(hours=24)


def server_checks(tenant: Tenant, patch: Patch, asset: Asset) -> list[dict]:
    """Verificações que o servidor faz sozinho (também valem para ativos sem agente)."""
    out: list[dict] = []
    ok, why = sources.check(asset, patch.installer)
    out.append({"id": "source", "label": "Origem de atualização suportada", "status": "ok" if ok and not why else "info" if ok else "block",
                "detail": why or INSTALLER_LABEL(patch.installer)})
    if patch.installer in sources.FILE_INSTALLERS:
        has = patches.local_path(patch, tenant) is not None
        out.append({"id": "repository_file", "label": "Instalador no repositório", "status": "ok" if has else "block",
                    "detail": f"SHA-256 {patch.sha256[:16]}…" if has else "Carregue o instalador no repositório (com SHA-256)"})
        if patch.installer == "exe" and not patch.silent_args:
            out.append({"id": "silent_args", "label": "Argumentos silenciosos", "status": "warn",
                        "detail": "Sem silent_args: será usado /S, que nem todos os instaladores aceitam"})
    intel = patches.intelligence(patch)
    out.append({"id": "patch_intelligence", "label": "Patch Intelligence", "status": {"go": "ok", "caution": "warn", "hold": "block"}[intel["level"]],
                "detail": " ".join(intel["reasons"])[:300]})
    if patch.status != "approved":
        out.append({"id": "approval", "label": "Patch aprovado", "status": "warn", "detail": "Ainda não aprovado (a simulação é permitida; a instalação exige aprovação)"})
    online = deploy.is_online(asset)
    out.append({"id": "online", "label": "Agente contactável", "status": "ok" if online else "warn",
                "detail": "" if online else "Agente sem contacto recente: a simulação executa-se quando voltar a ligar"})
    if asset.agent is None and asset.connection != "ansible":
        out.append({"id": "agent", "label": "Agente instalado", "status": "block", "detail": "Sem agente nem ligação Ansible: não é possível simular"})
    return out


def INSTALLER_LABEL(installer: str) -> str:
    from ..models import INSTALLER_TYPES
    return INSTALLER_TYPES.get(installer, installer)


def classify(checks: list[dict], predicted: dict) -> str:
    if any(c["status"] == "block" for c in checks):
        return "blocked"
    if predicted.get("noop"):
        return "noop"
    if any(c["status"] == "warn" for c in checks):
        return "warning"
    return "ready"


def start(tenant: Tenant, patch: Patch, asset: Asset, user=None, campaign: Campaign | None = None) -> Preflight:
    """Cria a simulação e a tarefa do agente. Sem agente ou bloqueada pelo servidor: conclui já com as verificações do servidor."""
    pf = Preflight(tenant_id=tenant.id, patch_id=patch.id, asset_id=asset.id, campaign_id=campaign.id if campaign else None,
                   created_by_id=getattr(user, "id", None))
    db.session.add(pf)
    db.session.flush()
    srv = server_checks(tenant, patch, asset)
    blocked = [c for c in srv if c["status"] == "block"]
    if blocked or asset.agent is None:
        extra = [] if blocked else [{"id": "limited", "label": "Simulação limitada", "status": "warn",
                                     "detail": "Ativo sem agente (Ansible): só foram feitas as verificações do servidor"}]
        pf.checks = json.dumps(srv + extra, ensure_ascii=False)
        pf.outcome, pf.finished_at = classify(srv + extra, {}), utcnow()
        return pf
    payload = deploy.patch_payload(campaign or _no_campaign(), patch, asset)
    payload["preflight_id"] = pf.id
    t = Task(tenant_id=tenant.id, type="simulate", asset_id=asset.id, patch_id=patch.id, campaign_id=campaign.id if campaign else None,
             ring=asset.ring, mode="agent", status="queued", payload=json.dumps(payload))
    db.session.add(t)
    db.session.flush()
    pf.task_id = t.id
    pf.checks = json.dumps(srv, ensure_ascii=False)       # as do servidor ficam já visíveis; o agente acrescenta as suas
    return pf


class _no_campaign:                      # valores por omissão quando se simula fora de uma campanha
    reboot_policy, bandwidth_kbps, emergency = "if_needed", 0, False


def on_report(task: Task, report: dict) -> None:
    pf = db.session.get(Preflight, task.payload_data.get("preflight_id") or 0)
    if pf is None:
        return
    agent_checks = report.get("checks") or []
    predicted = report.get("predicted") or {}
    if report.get("status") == "failed" and not agent_checks:
        agent_checks = [{"id": "agent", "label": "Execução da simulação", "status": "block", "detail": (report.get("output") or "falhou")[-300:]}]
    checks = [c for c in pf.check_list if c["id"] not in {x["id"] for x in agent_checks}] + agent_checks
    pf.checks, pf.predicted = json.dumps(checks, ensure_ascii=False), json.dumps(predicted)
    pf.outcome = "error" if (report.get("status") == "failed" and not report.get("checks")) else classify(checks, predicted)
    pf.finished_at = utcnow()


def latest(patch_id: int, asset_id: int, max_age: timedelta = MAX_AGE) -> Preflight | None:
    pf = Preflight.query.filter_by(patch_id=patch_id, asset_id=asset_id).order_by(Preflight.id.desc()).first()
    if pf is None:
        return None
    return pf if (pf.outcome == "pending" or utcnow() - pf.created_at <= max_age) else None


def simulate_scope(tenant: Tenant, patch: Patch, scope: dict, user=None, campaign: Campaign | None = None) -> list[Preflight]:
    """Simula o patch em todos os ativos do âmbito (os mesmos que uma campanha usaria)."""
    out = []
    for a in deploy.resolve_scope(tenant, scope, patch):
        out.append(start(tenant, patch, a, user, campaign))
    return out


def gate(c: Campaign, tenant: Tenant, t: Task) -> str:
    """Decisão para uma tarefa de patch de uma campanha com ``require_preflight``:
    ``go`` (liberta), ``wait`` (simulação em curso) ou ``skip`` (bloqueada / nada a instalar; ``t.output`` explica)."""
    if not c.require_preflight or t.type != "patch":
        return "go"
    pf = latest(t.patch_id, t.asset_id)
    if pf is None:
        start(tenant, t.patch, t.asset, campaign=c)
        t.output = "A aguardar a simulação prévia"
        return "wait"
    if pf.outcome == "pending":
        return "wait"
    if pf.outcome in ("ready", "warning"):
        return "go"
    why = next((f"{x['label']}: {x['detail']}" for x in pf.check_list if x["status"] == "block"), "")
    t.output = ("Já aplicado / não aplicável (simulação prévia)." if pf.outcome == "noop" else f"Bloqueado pela simulação prévia. {why}").strip()[:500]
    return "skip"


def summary(campaign_id: int) -> dict:
    q = Preflight.query.filter_by(campaign_id=campaign_id)
    return {o: q.filter_by(outcome=o).count() for o in ("pending", "ready", "warning", "blocked", "noop", "error")}
