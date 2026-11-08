"""Governação ITSM: pedidos de mudança (*change*) no ServiceNow, Jira ou Freshservice para as alterações/remediações do ativo.

**Desativado por omissão.** Sem a opção ``change_management = true`` na integração (e sem integração ITSM), **nada muda**: todo o ciclo
de aprovação (simular → OK → executar) é feito diretamente pela solução. Quando ativado:

1. o utilizador pede a *change* a partir do plano (ou do controlo) — a solução cria o pedido no ITSM com as ações simuladas;
2. a execução fica **bloqueada** até o ITSM aprovar (ServiceNow: ``approval = approved`` e estado Scheduled/Implement; Jira/Freshservice:
   estados configurados). O OK na solução continua a ser exigido;
3. no fim, o resultado (sucesso / falha / reversão) é escrito na *change* (notas de fecho ou comentário).

O estado é consultado a pedido e pelo worker. Falhas de comunicação com o ITSM nunca aprovam: mantêm o bloqueio."""
from __future__ import annotations

import logging

import requests

from ..connectors.http import request
from ..connectors.store import ConnectorError, of_group
from ..models import ControlAction, OperationPlan, Tenant, utcnow

log = logging.getLogger("omxpatch.itsm")
TRUE = ("1", "true", "yes", "sim", "on")


class ChangeError(RuntimeError):
    pass


def connector(tenant: Tenant):
    """Integração ITSM com a gestão de changes **ativada** (opção ``change_management``); senão None (= aprovação só na solução)."""
    for c in of_group(tenant.id, "itsm"):
        if c.enabled and str(c.opts.get("change_management", "false")).lower() in TRUE:
            return c
    return None


def enabled(tenant: Tenant) -> bool:
    return connector(tenant) is not None


def _split(csv: str) -> list[str]:
    return [x.strip().lower() for x in str(csv or "").split(",") if x.strip()]


# --------------------------------------------------------------------------- criar / ler / fechar (por plataforma)


def create(c, title: str, description: str, urgency: str = "medium") -> dict:
    """Cria o pedido de mudança. Devolve {ref, id, url}."""
    o = c.opts
    base = c.base_url.rstrip("/")
    if c.kind == "servicenow":
        body = {"short_description": title[:160], "description": description[:30000], "type": o.get("change_type") or "normal",
                "risk": {"high": "2", "medium": "3", "low": "4"}.get(urgency, "3"), "impact": {"high": "1", "medium": "2", "low": "3"}.get(urgency, "2"),
                "category": "Software"}
        if o.get("assignment_group"):
            body["assignment_group"] = o["assignment_group"]
        r = request(c, "POST", "/api/now/table/change_request", json_body=body, extra_headers={"Accept": "application/json"})
        r.raise_for_status()
        res = r.json().get("result", {})
        return {"ref": res.get("number", ""), "id": res.get("sys_id", ""), "url": f"{base}/nav_to.do?uri=change_request.do?sys_id={res.get('sys_id', '')}"}
    if c.kind == "jira":
        r = request(c, "POST", "/rest/api/3/issue", json_body={"fields": {
            "project": {"key": o.get("project") or "SEC"}, "summary": title[:250], "issuetype": {"name": o.get("change_issue_type") or "Change"},
            "description": {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [{"type": "text", "text": description[:30000]}]}]}}})
        r.raise_for_status()
        key = r.json().get("key", "")
        return {"ref": key, "id": key, "url": f"{base}/browse/{key}"}
    if c.kind == "freshservice":
        r = request(c, "POST", "/api/v2/changes", json_body={"subject": title[:250], "description": description, "email": o.get("requester_email") or "secops@localhost",
                                                              "priority": {"high": 3, "medium": 2, "low": 1}.get(urgency, 2), "status": 1, "change_type": 2, "impact": 2,
                                                              "risk": 2, "planned_start_date": utcnow().isoformat() + "Z", "planned_end_date": utcnow().isoformat() + "Z"})
        r.raise_for_status()
        cid = str(r.json().get("change", {}).get("id", ""))
        return {"ref": f"CHG-{cid}", "id": cid, "url": f"{base}/a/changes/{cid}"}
    raise ChangeError(f"ITSM sem suporte a changes: {c.kind}")


def read_state(c, change_id: str) -> tuple[str, str]:
    """(estado normalizado, detalhe). Estados: requested | approved | rejected | closed | cancelled."""
    o = c.opts
    if c.kind == "servicenow":
        r = request(c, "GET", f"/api/now/table/change_request/{change_id}", params={"sysparm_fields": "number,state,approval,phase,close_code"}, extra_headers={"Accept": "application/json"})
        r.raise_for_status()
        res = r.json().get("result", {})
        state, appr = str(res.get("state", "")).lower(), str(res.get("approval", "")).lower()
        if state in ("3", "closed", "complete"):
            return "closed", f"fechada ({res.get('close_code', '')})"
        if state in ("4", "canceled", "cancelled"):
            return "cancelled", "cancelada no ITSM"
        if appr == "rejected":
            return "rejected", "rejeitada no ITSM"
        if appr == "approved" and (state in _split(o.get("approved_states") or "-2,-1,scheduled,implement") or not state):
            return "approved", f"aprovada (estado {state or '?'})"
        return "requested", f"a aguardar aprovação (aprovação: {appr or '?'}, estado: {state or '?'})"
    if c.kind == "jira":
        r = request(c, "GET", f"/rest/api/3/issue/{change_id}", params={"fields": "status"})
        r.raise_for_status()
        name = str(r.json().get("fields", {}).get("status", {}).get("name", "")).lower()
        if name in _split(o.get("rejected_statuses") or "Rejected,Declined,Cancelled,Canceled"):
            return "rejected", f"estado «{name}»"
        if name in ("done", "closed", "resolved"):
            return "closed", f"estado «{name}»"
        if name in _split(o.get("approved_statuses") or "Approved,Scheduled,Implementing,In Progress"):
            return "approved", f"estado «{name}»"
        return "requested", f"estado «{name}»"
    if c.kind == "freshservice":
        r = request(c, "GET", f"/api/v2/changes/{change_id}")
        r.raise_for_status()
        sid = str(r.json().get("change", {}).get("status", ""))
        if sid in _split(o.get("rejected_status_ids") or "6,7"):
            return "rejected", f"estado {sid}"
        if sid in _split(o.get("approved_status_ids") or "4,5"):
            return "approved", f"estado {sid}"
        return "requested", f"estado {sid}"
    raise ChangeError(f"ITSM sem suporte a changes: {c.kind}")


def write_result(c, change_id: str, ok: bool, notes: str) -> None:
    """Regista o resultado na change: ServiceNow → Review com código/notas de fecho; Jira/Freshservice → comentário/nota."""
    if c.kind == "servicenow":
        r = request(c, "PATCH", f"/api/now/table/change_request/{change_id}",
                    json_body={"state": "0", "close_code": "successful" if ok else "unsuccessful", "close_notes": notes[:4000]}, extra_headers={"Accept": "application/json"})
        r.raise_for_status()
    elif c.kind == "jira":
        r = request(c, "POST", f"/rest/api/3/issue/{change_id}/comment", json_body={"body": {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [
            {"type": "text", "text": ("[OMXPatch] " + notes)[:30000]}]}]}})
        r.raise_for_status()
    elif c.kind == "freshservice":
        r = request(c, "POST", f"/api/v2/changes/{change_id}/notes", json_body={"body": ("[OMXPatch] " + notes)[:30000]})
        r.raise_for_status()


# --------------------------------------------------------------------------- descrições


def plan_description(plan: OperationPlan) -> str:
    lines = [f"Plano de operações #{plan.id}: {plan.name}", f"Modo: {plan.mode} · reinício: {plan.reboot_policy}", "", "Alterações simuladas (nada foi aplicado):"]
    for it in plan.items:
        acts = "; ".join(a.get("summary", "") for a in it.action_list[:2]) or it.label
        lines.append(f"- {it.asset.name}: {it.label} — simulação {it.sim_outcome or 'pendente'} — {acts}"[:300])
    lines += ["", "Aprovação direta na solução OMXPatch: o utilizador dá o OK após rever as ações; a execução só arranca com esta change aprovada."]
    return "\n".join(lines)


# --------------------------------------------------------------------------- planos


def request_change_for_plan(plan: OperationPlan, tenant: Tenant, user=None) -> dict:
    c = connector(tenant)
    if c is None:
        raise ChangeError("A gestão de changes no ITSM não está ativada (aprovação feita diretamente na solução)")
    if plan.change_state in ("requested", "approved"):
        return {"ref": plan.change_ref, "state": plan.change_state, "duplicate": True}
    urgency = "high" if any(i.patch and i.patch.severity in ("critical", "high") for i in plan.items if i.kind == "patch") else "medium"
    try:
        res = create(c, f"OMXPatch #{plan.id}: {plan.name}", plan_description(plan), urgency)
    except (requests.RequestException, ConnectorError, ValueError) as exc:
        raise ChangeError(f"Não foi possível criar a change no ITSM: {exc}") from exc
    plan.change_ref, plan.change_id, plan.change_url, plan.change_state = res["ref"], res["id"], res["url"], "requested"
    plan.change_detail, plan.change_checked_at = "pedida", utcnow()
    return {"ref": res["ref"], "state": "requested", "url": res["url"]}


def refresh_plan(plan: OperationPlan, tenant: Tenant) -> str:
    c = connector(tenant)
    if c is None or not plan.change_id or plan.change_state in ("closed", "cancelled", "rejected"):
        return plan.change_state
    try:
        state, detail = read_state(c, plan.change_id)
    except (requests.RequestException, ConnectorError, ValueError, ChangeError) as exc:
        plan.change_detail, plan.change_checked_at = f"ITSM inacessível: {str(exc)[:150]}", utcnow()
        return plan.change_state                                  # nunca aprova por falha de comunicação
    if plan.change_state != "implemented" or state in ("rejected", "cancelled", "closed"):
        plan.change_state = state
    plan.change_detail, plan.change_checked_at = detail, utcnow()
    return plan.change_state


def gate(plan: OperationPlan, tenant: Tenant) -> tuple[bool, str]:
    """(pode executar, motivo). Sem gestão de changes ativada: sempre pode (aprovação só na solução)."""
    if not enabled(tenant):
        return True, ""
    if not plan.change_ref:
        return False, "A gestão de changes está ativa: peça a change no ITSM antes de executar"
    state = refresh_plan(plan, tenant) if plan.change_state == "requested" else plan.change_state
    if state in ("approved", "implemented"):
        return True, ""
    return False, f"Change {plan.change_ref} {plan.change_detail or 'a aguardar aprovação'} (estado: {state})"


def close_plan(plan: OperationPlan, tenant: Tenant) -> bool:
    """Escreve o resultado do plano na change (uma só vez)."""
    c = connector(tenant)
    if c is None or not plan.change_id or plan.change_state in ("closed", "cancelled", "rejected", "implemented"):
        return False
    items = list(plan.items)
    ok_n = sum(1 for i in items if i.status == "succeeded")
    bad = [i for i in items if i.status in ("failed", "rolled_back")]
    notes = f"OMXPatch: {ok_n}/{len(items)} operações concluídas com sucesso." + "".join(f"\n- {i.asset.name} / {i.label}: {i.status}" for i in bad[:20])
    try:
        write_result(c, plan.change_id, not bad and ok_n > 0, notes)
    except (requests.RequestException, ConnectorError, ValueError) as exc:
        plan.change_detail = f"Resultado por escrever no ITSM: {str(exc)[:120]}"
        return False
    plan.change_state, plan.change_detail = "implemented", "resultado registado na change"
    return True


# --------------------------------------------------------------------------- controlos (isolamento, firewall…)


def request_change_for_control(ctl: ControlAction, tenant: Tenant) -> dict:
    c = connector(tenant)
    if c is None:
        raise ChangeError("A gestão de changes no ITSM não está ativada")
    if ctl.change_state in ("requested", "approved"):
        return {"ref": ctl.change_ref, "state": ctl.change_state, "duplicate": True}
    desc = f"Controlo compensatório: {ctl.action} em {ctl.asset.name if ctl.asset else 'n/d'} ({ctl.cve_id or 'sem CVE'})\n{ctl.detail or ''}\n\nArtefacto:\n{(ctl.artifact or '')[:2000]}"
    try:
        res = create(c, f"OMXPatch controlo {ctl.action}: {ctl.asset.name if ctl.asset else ''}", desc, "high")
    except (requests.RequestException, ConnectorError, ValueError) as exc:
        raise ChangeError(f"Não foi possível criar a change no ITSM: {exc}") from exc
    ctl.change_ref, ctl.change_id, ctl.change_url, ctl.change_state = res["ref"], res["id"], res["url"], "requested"
    return res


def gate_control(ctl: ControlAction, tenant: Tenant) -> tuple[bool, str]:
    c = connector(tenant)
    if c is None:
        return True, ""
    if not ctl.change_ref:
        return False, "A gestão de changes está ativa: peça a change no ITSM antes de aplicar o controlo"
    if ctl.change_state == "requested":
        try:
            state, _d = read_state(c, ctl.change_id)
            ctl.change_state = state
        except (requests.RequestException, ConnectorError, ValueError, ChangeError):
            return False, "ITSM inacessível: o controlo continua bloqueado"
    return (True, "") if ctl.change_state in ("approved", "implemented") else (False, f"Change {ctl.change_ref} ainda não aprovada ({ctl.change_state})")


def tick(tenant: Tenant) -> int:
    """Worker: atualiza o estado das changes pedidas (e fecha as dos planos concluídos)."""
    if not enabled(tenant):
        return 0
    n = 0
    for plan in OperationPlan.query.filter(OperationPlan.tenant_id == tenant.id, OperationPlan.change_state.in_(("requested", "approved"))):
        before = plan.change_state
        refresh_plan(plan, tenant)
        if plan.status == "completed":
            close_plan(plan, tenant)
        n += 1 if plan.change_state != before else 0
    return n
