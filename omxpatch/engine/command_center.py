"""Centro de comando: consolida num só ecrã o estado completo da solução (frota, exposição, remediação, planos, boas práticas,
conformidade, integrações e saúde) e as ações rápidas para **simular** e **remediar**.

Nenhuma ação rápida executa alterações: cria um plano de operações e pede a simulação; a aplicação continua a exigir o OK explícito
do utilizador (ver ``engine/plans``)."""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from .. import licensing
from ..extensions import db
from ..models import (Agent, Asset, AuditLog, Campaign, ControlAction, CveIntel, Exposure, OperationPlan, Patch, PlanItem, Task, Tenant,
                      Validation, utcnow)
from . import compliance, executive, plans as plans_mod

ACTIVE_ITEM = ("draft", "simulating", "simulated", "approved", "queued", "running")
OPEN = ("open", "mitigated", "patching")
CAT_ORDER = {"emergency": 5, "critical": 4, "high": 3, "medium": 2, "low": 1}


def _fleet(tenant: Tenant, assets: list) -> dict:
    import omxpatch_agent
    now = utcnow()
    offline = timedelta(minutes=int(__import__("flask").current_app.config["AGENT_OFFLINE_MINUTES"]))
    agents = Agent.query.filter_by(tenant_id=tenant.id, revoked=False).all()
    online = [a for a in agents if a.last_seen and now - a.last_seen < offline]
    by_os: dict[str, dict] = {}
    for a in assets:
        o = by_os.setdefault(a.os_family or "outro", {"agent": 0, "ansible": 0, "none": 0})
        o["agent" if a.agent is not None else ("ansible" if a.connection == "ansible" else "none")] += 1
    legacy = sum(1 for a in assets if (a.hw.get("agent_runtime") or {}).get("level") == "legacy")
    return {"agents": len(agents), "online": len(online), "offline": len(agents) - len(online), "by_os": by_os, "unmanaged": sum(1 for a in assets if not a.managed),
            "legacy_python": legacy, "outdated": sum(1 for a in agents if a.version and a.version != omxpatch_agent.__version__),
            "no_agent": sum(1 for a in assets if a.agent is None and a.os_family in ("windows", "linux", "macos") and a.managed is False)}


def _priority(tenant: Tenant, limit: int = 8) -> tuple[list, list]:
    """Remediação prioritária por patch (com patch disponível) e CVE sem patch (a mitigar)."""
    exps = Exposure.query.filter(Exposure.tenant_id == tenant.id, Exposure.status.in_(OPEN)).all()
    kev_ids = {c.cve_id for c in CveIntel.query.filter(CveIntel.kev.is_(True), CveIntel.cve_id.in_({e.cve_id for e in exps} or {"-"}))}
    active = {}
    for it in PlanItem.query.filter(PlanItem.tenant_id == tenant.id, PlanItem.kind == "patch", PlanItem.status.in_(ACTIVE_ITEM)):
        active.setdefault(it.patch_id, {}).setdefault(it.status, 0)
        active[it.patch_id][it.status] += 1
    by_patch: dict[int, dict] = {}
    nopatch: dict[str, dict] = {}
    for e in exps:
        if e.patch_id and e.patch is not None:
            g = by_patch.setdefault(e.patch_id, {"patch": e.patch, "assets": set(), "cves": set(), "risk": 0.0, "cat": "low", "kev": 0})
        else:
            g = nopatch.setdefault(e.cve_id, {"cve": e.cve_id, "assets": set(), "risk": 0.0, "cat": "low", "kev": 0})
        g["assets"].add(e.asset_id)
        if "cves" in g:
            g["cves"].add(e.cve_id)
        g["risk"] = max(g["risk"], e.risk_score or 0)
        if CAT_ORDER.get(e.risk_category, 0) > CAT_ORDER[g["cat"]]:
            g["cat"] = e.risk_category
        g["kev"] += 1 if e.cve_id in kev_ids else 0
    rows = []
    for pid, g in sorted(by_patch.items(), key=lambda kv: (-kv[1]["risk"], kv[0]))[:limit]:
        p: Patch = g["patch"]
        rows.append({"id": pid, "uid": p.patch_uid, "title": p.title or p.product or p.patch_uid, "status": p.status, "assets": len(g["assets"]), "cves": len(g["cves"]),
                     "risk": round(g["risk"]), "cat": g["cat"], "kev": g["kev"], "plan_state": active.get(pid, {})})
    nrows = [{"cve": g["cve"], "assets": len(g["assets"]), "risk": round(g["risk"]), "cat": g["cat"], "kev": g["kev"]}
             for g in sorted(nopatch.values(), key=lambda g: (-g["risk"], g["cve"]))[:5]]
    return rows, nrows


def _plans(tenant: Tenant) -> dict:
    now = utcnow()
    items = PlanItem.query.filter_by(tenant_id=tenant.id).all()
    awaiting = [i for i in items if i.status == "simulated" and i.sim_outcome in ("ready", "warning") and i.sim_at and now - i.sim_at <= plans_mod.MAX_AGE]
    by_status: dict[str, int] = {}
    for i in items:
        by_status[i.status] = by_status.get(i.status, 0) + 1
    awaiting_by_plan: dict[int, int] = {}
    for i in awaiting:
        awaiting_by_plan[i.plan_id] = awaiting_by_plan.get(i.plan_id, 0) + 1
    plan_rows = []
    for pid, n in sorted(awaiting_by_plan.items(), key=lambda kv: -kv[1])[:5]:
        p = db.session.get(OperationPlan, pid)
        plan_rows.append({"id": pid, "name": p.name, "awaiting": n, "warnings": sum(1 for i in awaiting if i.plan_id == pid and i.sim_outcome == "warning")})
    recent_fail = [i for i in items if i.status in ("failed", "rolled_back") and i.finished_at and now - i.finished_at < timedelta(days=7)]
    return {"by_status": by_status, "awaiting": len(awaiting), "awaiting_plans": plan_rows, "failed_recent": len(recent_fail),
            "blocked": sum(1 for i in items if i.sim_outcome == "blocked" and i.status == "simulated"),
            "stale": sum(1 for i in items if i.status == "simulated" and i.sim_at and now - i.sim_at > plans_mod.MAX_AGE),
            "executing": sum(1 for p in OperationPlan.query.filter_by(tenant_id=tenant.id, status="executing"))}


def _practices(tenant: Tenant, assets: list) -> dict:
    web = [a for a in assets if a.hw.get("webservers")]
    done = {}
    for it in PlanItem.query.filter_by(tenant_id=tenant.id, kind="practice", status="succeeded"):
        done.setdefault(it.practice, set()).add(it.asset_id)
    servers: dict[str, int] = {}
    for a in web:
        for w in a.hw["webservers"]:
            servers[w.get("type", "?")] = servers.get(w.get("type", "?"), 0) + 1
    from . import practices as pr
    rows = [{"id": k, "label": v["label"], "done": len(done.get(k, set()) & {a.id for a in web}), "total": len(web),
             "todo_ids": [a.id for a in web if a.id not in done.get(k, set())]} for k, v in pr.PRACTICES.items()]
    return {"webservers": len(web), "servers": servers, "rows": rows}


def _campaigns(tenant: Tenant) -> list:
    out = []
    for c in Campaign.query.filter(Campaign.tenant_id == tenant.id, Campaign.status.in_(("running", "scheduled", "paused"))).order_by(Campaign.id.desc()).limit(5):
        tasks = Task.query.filter_by(campaign_id=c.id).all()
        done = sum(1 for t in tasks if t.status in ("succeeded", "failed", "rolled_back", "cancelled"))
        ok = sum(1 for t in tasks if t.status == "succeeded")
        out.append({"id": c.id, "name": c.name, "status": c.status, "ring": c.current_ring, "total": len(tasks), "done": done, "ok": ok,
                    "pct": round(100 * done / len(tasks)) if tasks else 0})
    return out


def _funnel(tenant: Tenant, k: dict, plan_status: dict) -> list:
    approved_patches = Patch.query.filter_by(tenant_id=tenant.id, status="approved").count()
    return [("Exposições abertas", k["open_exposures"]), ("Com patch disponível", k["patchable_open"]), ("Patches aprovados", approved_patches),
            ("Simulados (prontos)", plan_status.get("simulated", 0)), ("Com OK", plan_status.get("approved", 0)),
            ("Em execução", plan_status.get("queued", 0) + plan_status.get("running", 0)), ("Concluídos", plan_status.get("succeeded", 0))]


def _compliance(tenant: Tenant) -> list:
    out = []
    for key, fw in compliance.build(tenant)["frameworks"].items():
        reqs = fw["requirements"]
        c = sum(1 for r in reqs if r["status"] == "compliant")
        p = sum(1 for r in reqs if r["status"] == "partial")
        out.append({"key": key, "name": fw["name"].split(" (")[0], "ok": c, "partial": p, "gap": len(reqs) - c - p, "total": len(reqs),
                    "pct": round(100 * (c + 0.5 * p) / len(reqs)) if reqs else 0})
    return out


def _health(app, tenant: Tenant, user) -> dict:
    from ..connectors.store import effective
    lic = licensing.status(tenant)
    conns = []
    for kind, label in (("omxvuln", "OMXVuln"), ("omxgrc", "OMXGRC")):
        c = effective(tenant.id, kind)
        conns.append({"label": label, "configured": c is not None, "ok": getattr(c, "last_ok", None), "last": getattr(c, "last_sync_at", None),
                      "detail": (getattr(c, "last_detail", "") or "")[:80]})
    h = {"license": lic, "connectors": conns, "validation_failed": Validation.query.filter_by(tenant_id=tenant.id, status="failed").count(),
         "controls": ControlAction.query.filter(ControlAction.tenant_id == tenant.id, ControlAction.status.in_(("applied", "verified"))).count()}
    if user.is_superadmin:                      # estado do sistema (todas as organizações): só super-administrador
        from . import capacity
        from .. import tls
        snap = capacity.snapshot(app)
        est = capacity.estimate(snap)
        certs = []
        try:
            for prof in ("console", "agent"):
                cert, _k, _m = tls.paths(app.config, prof)
                if cert.is_file():
                    certs.append({"profile": prof, "days": tls.info(cert)["days_left"]})
        except Exception:  # noqa: BLE001
            pass
        from . import backup
        bl = backup.listing(app.config)
        h["system"] = {"utilization": est["utilization"], "capacity": est["capacity_rps"], "max_agents": est["max_agents"], "certs": certs,
                       "last_backup": bl[0]["at"] if bl else None, "db": snap["db"]["engine"], "worker": snap["worker"].get("at", "")[:19]}
    return h


def _actions(tenant: Tenant, k: dict, fleet: dict, pl: dict, prio: list, practices: dict) -> list:
    """Fila de ações recomendadas, por prioridade. Cada uma tem um destino (ver ``web/main.py::command_quick``)."""
    a = []
    if pl["awaiting"]:
        a.append({"level": "info", "text": f"{pl['awaiting']} item(ns) simulados a aguardar o seu OK", "cta": "Rever e aprovar", "kind": "link", "plan_id": pl["awaiting_plans"][0]["id"] if pl["awaiting_plans"] else None})
    kev_patch = [r for r in prio if r["kev"] and not r["plan_state"]]
    if kev_patch:
        a.append({"level": "critical", "text": f"{len(kev_patch)} patch(es) com CVE explorados (KEV) ainda sem simulação", "cta": "Simular o mais urgente", "kind": "patch", "id": kev_patch[0]["id"]})
    elif prio and not prio[0]["plan_state"]:
        a.append({"level": "warning", "text": f"Patch mais urgente ({prio[0]['uid']}) sem simulação", "cta": "Simular", "kind": "patch", "id": prio[0]["id"]})
    if k["sla_breaches"]:
        a.append({"level": "warning", "text": f"{k['sla_breaches']} exposição(ões) fora do SLA", "cta": "Ver", "kind": "url", "url": "main.exposures"})
    tls_row = next((r for r in practices["rows"] if r["id"] == "tls_protocols"), None)
    if tls_row and tls_row["todo_ids"]:
        a.append({"level": "info", "text": f"{len(tls_row['todo_ids'])} servidor(es) web sem a boa prática TLS 1.2/1.3 aplicada", "cta": "Simular TLS 1.2/1.3", "kind": "tls"})
    if pl["failed_recent"]:
        a.append({"level": "warning", "text": f"{pl['failed_recent']} operação(ões) falhadas/revertidas nos últimos 7 dias", "cta": "Ver planos", "kind": "url", "url": "plans.plans_list"})
    if pl["stale"]:
        a.append({"level": "info", "text": f"{pl['stale']} simulação(ões) com mais de 24 h: simule de novo antes de aprovar", "cta": "Ver planos", "kind": "url", "url": "plans.plans_list"})
    if fleet["offline"] and fleet["agents"]:
        a.append({"level": "warning" if fleet["offline"] / fleet["agents"] > .2 else "info", "text": f"{fleet['offline']} agente(s) offline", "cta": "Ver agentes", "kind": "url", "url": "admin.agents"})
    if fleet["legacy_python"]:
        a.append({"level": "info", "text": f"{fleet['legacy_python']} agente(s) com Python antigo (3.8/3.9)", "cta": "Ver agentes", "kind": "url", "url": "admin.agents"})
    if k["validation_failed"]:
        a.append({"level": "warning", "text": f"{k['validation_failed']} validação(ões) falhada(s)", "cta": "Rever", "kind": "url", "url": "secops.validations"})
    order = {"critical": 0, "warning": 1, "info": 2}
    return sorted(a, key=lambda x: order[x["level"]])[:7]


def overview(app, tenant: Tenant, user) -> dict:
    k = executive.kpis(tenant)
    assets = Asset.query.filter_by(tenant_id=tenant.id).all()
    fleet = _fleet(tenant, assets)
    prio, nopatch = _priority(tenant)
    pl = _plans(tenant)
    prac = _practices(tenant, assets)
    recent = AuditLog.query.filter_by(tenant_id=tenant.id).order_by(AuditLog.id.desc()).limit(8).all()
    return {"k": k, "fleet": fleet, "priority": prio, "nopatch": nopatch, "plans": pl, "practices": prac, "campaigns": _campaigns(tenant),
            "funnel": _funnel(tenant, k, pl["by_status"]), "compliance": _compliance(tenant), "health": _health(app, tenant, user),
            "actions": _actions(tenant, k, fleet, pl, prio, prac),
            "activity": [{"at": r.created_at, "action": r.action, "detail": (r.detail or "")[:90], "who": r.user.email if r.user else ""} for r in recent]}
