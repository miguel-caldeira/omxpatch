"""Planos de operações em massa: **simular → rever → OK → executar**, por atualização ou por ativo.

* *Por atualização*: um patch (ou uma boa prática) em vários ativos. *Por ativo*: várias operações (patches e boas práticas) num ativo.
  O plano é a mesma estrutura — um conjunto de itens (operação × ativo) — vista agrupada por operação ou por ativo.
* Cada item é **simulado** (patches: simulação prévia; boas práticas: plano de alterações com *diff* e verificações) e mostra as ações e
  os resultados previstos.
* Só depois do **OK explícito** do utilizador (por item ou em bloco; os avisos têm de ser aceites) é que o item pode ser executado.
  A aprovação caduca com a simulação (24 h) e os itens bloqueados, já conformes ou com erro nunca são executáveis.
* A execução cria as tarefas do agente respeitando janelas de manutenção e hora de início; as boas práticas aplicam-se com teste,
  verificação e **reversão automática**, e podem ser revertidas depois."""
from __future__ import annotations

import json
from datetime import datetime, timedelta

from ..extensions import db
from ..models import (ITEM_FINAL, Asset, OperationPlan, Patch, PlanItem, Preflight, Task, Tenant, jloads, utcnow)
from . import deploy, practices as pr, preflight, sources

MAX_AGE = timedelta(hours=24)


class PlanError(ValueError):
    pass


def _set_sim(item: PlanItem, outcome: str, checks: list, actions: list, predicted: dict, when=None) -> None:
    item.sim_outcome = outcome
    item.sim_checks = json.dumps(checks, ensure_ascii=False)
    item.sim_actions = json.dumps(actions, ensure_ascii=False)
    item.sim_predicted = json.dumps(predicted, ensure_ascii=False)
    item.sim_at = when or utcnow()
    item.status = "simulated"
    item.approved_at = item.approved_by_id = None
    item.accepted_warnings = False


def _blocked(item: PlanItem, why: str, cid: str = "applicability") -> None:
    _set_sim(item, "blocked", [{"id": cid, "label": "Aplicabilidade", "status": "block", "detail": why}], [], {})


def create(tenant: Tenant, name: str, mode: str, asset_ids: list[int], patch_ids: list[int], practice_specs: list[dict], user=None,
           reboot_policy: str = "if_needed", respect_windows: bool = True, start_at: datetime | None = None,
           pairs: list[tuple[int, int]] | None = None) -> OperationPlan:
    """``pairs`` = [(ativo, patch)]: itens exatos (em vez do produto cartesiano ativos × patches), p.ex. as atualizações descobertas por ativo."""
    if pairs:
        patch_ids = sorted({p for _a, p in pairs} | set(patch_ids or []))
        asset_ids = sorted({a for a, _p in pairs} | set(asset_ids or []))
    if not asset_ids or not (patch_ids or practice_specs):
        raise PlanError("Escolha pelo menos um ativo e uma operação (patch ou boa prática).")
    for spec in practice_specs:
        if spec.get("id") not in pr.PRACTICES:
            raise PlanError(f"Boa prática desconhecida: {spec.get('id')}")
    assets = Asset.query.filter(Asset.tenant_id == tenant.id, Asset.id.in_(asset_ids)).order_by(Asset.name).all()
    patches_ = Patch.query.filter(Patch.tenant_id == tenant.id, Patch.id.in_(patch_ids or [0])).all()
    if not assets:
        raise PlanError("Nenhum dos ativos indicados pertence a esta organização.")
    plan = OperationPlan(tenant_id=tenant.id, name=name[:200] or "Plano", mode=mode if mode in ("by_patch", "by_asset") else "by_patch",
                         reboot_policy=reboot_policy if reboot_policy in ("none", "if_needed", "force") else "if_needed",
                         respect_windows=respect_windows, start_at=start_at, created_by_id=getattr(user, "id", None))
    db.session.add(plan)
    db.session.flush()
    wanted = set(pairs) if pairs else None
    for a in assets:
        for p in patches_:
            if wanted is not None and (a.id, p.id) not in wanted:
                continue
            it = PlanItem(tenant_id=tenant.id, plan_id=plan.id, asset_id=a.id, kind="patch", patch_id=p.id)
            db.session.add(it)
            ok, why = sources.check(a, p.installer)
            if a.os_family and p.os_family and a.os_family != p.os_family:
                ok, why = False, f"O patch é para {p.os_family} e o ativo é {a.os_family}"
            if not ok:
                _blocked(it, why, "source")
        for spec in practice_specs:
            pid = spec.get("id")
            if pid not in pr.PRACTICES:
                raise PlanError(f"Boa prática desconhecida: {pid}")
            it = PlanItem(tenant_id=tenant.id, plan_id=plan.id, asset_id=a.id, kind="practice", practice=pid,
                          params=json.dumps(pr.clean_params(pid, spec.get("params") or {})))
            db.session.add(it)
            ok, why = pr.applicable(a, pid)
            if not ok:
                _blocked(it, why)
    db.session.flush()
    refresh_plan(plan)
    return plan


# --------------------------------------------------------------------------- simulação


def simulate(plan: OperationPlan, tenant: Tenant, user=None, only: list[int] | None = None) -> int:
    """Pede a simulação de todos os itens por simular (ou desatualizados). Devolve quantos ficaram em curso."""
    n = 0
    now = utcnow()
    for it in plan.items:
        if only is not None and it.id not in only:
            continue
        if it.status in ITEM_FINAL or it.status in ("queued", "running"):
            continue
        if it.sim_outcome == "blocked" and it.status == "simulated" and it.sim_at and now - it.sim_at < MAX_AGE and not only:
            continue                                                    # bloqueio de aplicabilidade já conhecido
        it.status, it.sim_outcome = "simulating", "pending"
        it.approved_at = it.approved_by_id = None
        if it.kind == "patch":
            pf = preflight.start(tenant, it.patch, it.asset, user)
            it.preflight_id = pf.id
            if pf.outcome != "pending":
                sync_patch_item(it, pf)
        else:
            if it.asset.agent is None:
                _blocked(it, "Sem agente instalado: não é possível simular nem aplicar boas práticas", "agent")
            else:
                t = Task(tenant_id=tenant.id, type="practice_sim", asset_id=it.asset_id, ring=it.asset.ring, mode="agent", status="queued",
                         payload=json.dumps({"item_id": it.id, "practice": it.practice, "params": it.params_data}))
                db.session.add(t)
                db.session.flush()
                it.sim_task_id = t.id
        n += 1
    refresh_plan(plan)
    return n


def sync_patch_item(it: PlanItem, pf: Preflight) -> None:
    pr_ = pf.predicted_data
    p = it.patch
    action = {"target": it.asset.name, "kind": "instalar patch", "server": "",
              "summary": f"{p.patch_uid} ({p.title or p.product or p.installer}): {pr_.get('version_before') or '?'} → {pr_.get('version_after') or '?'}"
                         + (f" · {pr_['download_mb']} MB" if pr_.get("download_mb") else "") + (" · reinício previsto" if pr_.get("reboot") else ""),
              "diff": "", "reversible": False}
    _set_sim(it, pf.outcome, pf.check_list, [action] if pf.outcome not in ("blocked", "error") else [], pr_, pf.finished_at)


def on_preflight_done(pf: Preflight) -> None:
    for it in PlanItem.query.filter_by(preflight_id=pf.id, status="simulating"):
        sync_patch_item(it, pf)
        refresh_plan(it.plan)


def on_sim_report(task: Task, report: dict) -> None:
    it = db.session.get(PlanItem, task.payload_data.get("item_id") or 0)
    if it is None or it.sim_task_id != task.id:
        return
    checks, actions, predicted = report.get("checks") or [], report.get("actions") or [], report.get("predicted") or {}
    if report.get("status") == "failed" and not checks:
        checks = [{"id": "agent", "label": "Execução da simulação", "status": "block", "detail": (report.get("output") or "falhou")[-300:]}]
        outcome = "error"
    else:
        outcome = preflight.classify(checks, predicted)
    _set_sim(it, outcome, checks, actions, predicted)
    refresh_plan(it.plan)


# --------------------------------------------------------------------------- OK do utilizador


def eligible(it: PlanItem, now=None) -> tuple[bool, str]:
    now = now or utcnow()
    if it.status != "simulated":
        return False, "ainda não foi simulado" if it.status in ("draft", "simulating") else f"estado «{it.status}»"
    if it.sim_outcome in ("blocked", "error"):
        return False, "a simulação bloqueou este item" if it.sim_outcome == "blocked" else "erro na simulação"
    if it.sim_outcome == "noop":
        return False, "nada a aplicar (já em conformidade / já instalado)"
    if it.sim_outcome == "pending" or not it.sim_at:
        return False, "simulação em curso"
    if now - it.sim_at > MAX_AGE:
        return False, "a simulação tem mais de 24 h: simule de novo"
    return True, ""


def approve(plan: OperationPlan, item_ids: list[int] | None, user, accept_warnings: bool = False, all_ok: bool = False) -> dict:
    """OK do utilizador. Devolve {approved: n, refused: [(item, motivo)]}. ``all_ok`` aprova os itens «pronto» (e «avisos» se aceites)."""
    approved, refused = 0, []
    for it in plan.items:
        if all_ok:
            if it.sim_outcome not in ("ready", "warning") or it.status != "simulated":
                continue
        elif item_ids is None or it.id not in item_ids:
            continue
        ok, why = eligible(it)
        if ok and it.sim_outcome == "warning" and not accept_warnings:
            ok, why = False, "tem avisos: confirme que os aceita"
        if not ok:
            refused.append((it, why))
            continue
        it.status, it.approved_by_id, it.approved_at, it.accepted_warnings = "approved", getattr(user, "id", None), utcnow(), accept_warnings and it.sim_outcome == "warning"
        approved += 1
    refresh_plan(plan)
    return {"approved": approved, "refused": refused}


def revoke(plan: OperationPlan, item_ids: list[int]) -> int:
    n = 0
    for it in plan.items:
        if it.id in item_ids and it.status == "approved":
            it.status, it.approved_at, it.approved_by_id = "simulated", None, None
            n += 1
    refresh_plan(plan)
    return n


# --------------------------------------------------------------------------- execução


def execute(plan: OperationPlan, tenant: Tenant, user=None, now=None) -> dict:
    """Cria as tarefas dos itens aprovados (e só desses). Itens cuja simulação caducou voltam a «simulado»."""
    now = now or utcnow()
    done, skipped = 0, []
    for it in plan.items:
        if it.status != "approved":
            continue
        if not it.sim_at or now - it.sim_at > MAX_AGE:
            it.status, it.approved_at, it.approved_by_id = "simulated", None, None
            skipped.append((it, "a simulação caducou: simule e aprove de novo"))
            continue
        if it.kind == "patch" and it.patch.status != "approved":
            it.status, it.output = "failed", "O patch não está aprovado no repositório."
            it.finished_at = now
            skipped.append((it, it.output))
            continue
        mode = "ansible" if (it.asset.connection == "ansible" and it.asset.agent is None) else "agent"
        if it.kind == "patch":
            payload = deploy.patch_payload(plan, it.patch, it.asset)
            payload["reboot_policy"] = plan.reboot_policy
            ttype, patch_id = "patch", it.patch_id
        else:
            if it.asset.agent is None:
                it.status, it.output, it.finished_at = "failed", "Sem agente: não é possível aplicar boas práticas.", now
                skipped.append((it, it.output))
                continue
            payload = {"item_id": it.id, "practice": it.practice, "params": it.params_data, "reboot_policy": plan.reboot_policy}
            ttype, patch_id, mode = "practice_apply", None, "agent"
        payload["plan_item_id"] = it.id
        t = Task(tenant_id=tenant.id, type=ttype, asset_id=it.asset_id, patch_id=patch_id, ring=it.asset.ring, mode=mode, status="pending",
                 not_before=plan.start_at, payload=json.dumps(payload))
        db.session.add(t)
        db.session.flush()
        it.task_id, it.status = t.id, "queued"
        done += 1
    if done:
        plan.status, plan.executed_at = "executing", plan.executed_at or now
    refresh_plan(plan)
    return {"queued": done, "skipped": skipped}


def release(tenant: Tenant, now: datetime) -> int:
    """Liberta as tarefas pendentes de planos (hora de início e janelas de manutenção)."""
    n = 0
    for t in Task.query.filter(Task.tenant_id == tenant.id, Task.status == "pending", Task.campaign_id.is_(None),
                               Task.type.in_(("patch", "practice_apply"))):
        pid = t.payload_data.get("plan_item_id")
        if not pid:
            continue
        it = db.session.get(PlanItem, pid)
        if it is None or t.not_before and t.not_before > now:
            continue
        if it.plan.respect_windows:
            ok, why = deploy.window_allows(tenant.id, t.asset, now)
            if not ok:
                t.output = why
                continue
        t.status = "queued"
        n += 1
    return n


def on_task_started(task: Task) -> None:
    it = _item_of(task)
    if it is not None and it.status == "queued":
        it.status = "running"


def _item_of(task: Task) -> PlanItem | None:
    pid = task.payload_data.get("plan_item_id") or (task.payload_data.get("item_id") if task.type in ("practice_apply", "practice_rollback") else None)
    it = db.session.get(PlanItem, pid) if pid else None
    return it if it is not None and it.tenant_id == task.tenant_id else None


def on_task_done(task: Task, report: dict) -> None:
    if task.type not in ("patch", "practice_apply", "practice_rollback"):
        return
    it = _item_of(task)
    if it is None:
        return
    if task.type == "practice_rollback":
        if task.status == "succeeded":
            it.status, it.output, it.finished_at = "reverted", report.get("output", "Revertido"), utcnow()
        else:
            it.output = "Falha ao reverter: " + str(report.get("output", ""))[-300:]
        refresh_plan(it.plan)
        return
    if it.task_id != task.id or task.status not in ("succeeded", "failed", "rolled_back"):
        return                                                            # tentativa repetida ou ainda em curso
    it.status = "succeeded" if task.status == "succeeded" else ("rolled_back" if report.get("rolled_back") else "failed")
    it.result = json.dumps({k: v for k, v in report.items() if k not in ("software", "hotfixes")}, default=str)[:60000]
    it.output = str(report.get("output", ""))[-4000:]
    it.finished_at = utcnow()
    refresh_plan(it.plan)


def revert(it: PlanItem, tenant: Tenant) -> Task:
    if it.kind != "practice" or it.status != "succeeded":
        raise PlanError("Só boas práticas concluídas podem ser revertidas.")
    t = Task(tenant_id=tenant.id, type="practice_rollback", asset_id=it.asset_id, ring=it.asset.ring, mode="agent", status="queued",
             payload=json.dumps({"item_id": it.id, "practice": it.practice, "params": it.params_data}))
    db.session.add(t)
    db.session.flush()
    return t


def cancel(plan: OperationPlan) -> int:
    n = 0
    for it in plan.items:
        if it.status in ("draft", "simulating", "simulated", "approved"):
            it.status, it.output, n = "skipped", "Plano cancelado", n + 1
    for it in plan.items:
        if it.status == "queued" and it.task_id:
            t = db.session.get(Task, it.task_id)
            if t and t.status in ("pending", "queued"):
                t.status, it.status, it.output, n = "cancelled", "skipped", "Plano cancelado", n + 1
    plan.status = "cancelled"
    return n


# --------------------------------------------------------------------------- estado do plano


def counts(plan: OperationPlan) -> dict:
    c: dict[str, int] = {}
    for it in plan.items:
        c[it.status] = c.get(it.status, 0) + 1
    return c


def refresh_plan(plan: OperationPlan) -> str:
    if plan.status == "cancelled":
        return plan.status
    items = list(plan.items)
    st = {i.status for i in items}
    if items and st <= set(ITEM_FINAL):
        plan.status = "completed"
    elif st & {"queued", "running"} or (plan.executed_at and st - set(ITEM_FINAL)):
        plan.status = "executing"
    elif "simulating" in st:
        plan.status = "simulating"
    elif st == {"draft"}:
        plan.status = "draft"
    else:
        plan.status = "simulated"
    return plan.status


def summary(plan: OperationPlan) -> dict:
    sim = {}
    for it in plan.items:
        sim[it.sim_outcome] = sim.get(it.sim_outcome, 0) + 1
    return {"status": counts(plan), "simulation": sim, "total": len(list(plan.items))}


__all__ = ["jloads"]
