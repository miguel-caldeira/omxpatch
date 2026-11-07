"""Módulo 15 — Autonomous Remediation (nível máximo de maturidade).

    Novo CVE → Descoberta automática → Avaliação de risco → Mapeamento dos ativos → Procura de patch →
    Teste automático (Ring 0) → Ring deployment → Validação → Fecho automático → Atualização da CMDB →
    Reporte executivo

Máquina de estados persistida em ``AutonomousRun`` e avançada pelo worker (``advance``), porque o ciclo atravessa
horas ou dias (janelas de manutenção, anéis, validações). Modos por organização:

* **aconselhar** — executa descoberta, avaliação, mapeamento e procura de patch, e propõe; um humano aprova
  (patch + campanha) antes de qualquer alteração;
* **autónomo** — aprova patches sem alertas graves da Patch Intelligence, testa no Ring 0, promove pelos anéis,
  valida e fecha sozinho. Patch Intelligence em *hold*, critérios de anel falhados ou validações falhadas
  devolvem sempre o controlo a um humano.
"""
from __future__ import annotations

import json
import logging

from ..extensions import db
from ..models import (AUTONOMOUS_STAGE_LABELS, AUTONOMOUS_STAGES, Asset, AutonomousRun, Campaign, CveIntel, Exposure,
                      Patch, Tenant, jloads, utcnow)
from . import controls, correlate, deploy, executive, intel, patches, rings

log = logging.getLogger("omxpatch.autonomous")
ACTIVE = ("running", "waiting", "approval")


def _log(run: AutonomousRun, msg: str) -> None:
    run.log = ((run.log or "") + f"[{utcnow():%Y-%m-%d %H:%M:%S}] {msg}\n")[-60000:]


def _set(run: AutonomousRun, **kw) -> None:
    d = run.data_dict
    d.update(kw)
    run.data = json.dumps(d)


def trigger(tenant: Tenant, cve_id: str, force: bool = False) -> AutonomousRun | None:
    """Abre um fluxo para o CVE se o modo estiver ativo e o risco justificar."""
    if tenant.autonomous_mode == "off" and not force:
        return None
    if AutonomousRun.query.filter(AutonomousRun.tenant_id == tenant.id, AutonomousRun.cve_id == cve_id,
                                  AutonomousRun.status.in_(ACTIVE)).first():
        return None
    run = AutonomousRun(tenant_id=tenant.id, cve_id=cve_id, mode=tenant.autonomous_mode if tenant.autonomous_mode != "off" else "advise",
                        stage="discovery", status="running")
    db.session.add(run)
    db.session.flush()
    _log(run, f"Novo CVE {cve_id}: fluxo iniciado (modo {run.mode}).")
    return run


def scan_new_cves(tenant: Tenant) -> list[AutonomousRun]:
    """Procura exposições abertas de CVE ainda sem fluxo e que cumprem os limiares da organização."""
    if tenant.autonomous_mode == "off":
        return []
    runs = []
    done = {r.cve_id for r in AutonomousRun.query.filter_by(tenant_id=tenant.id)}
    best: dict[str, int] = {}
    for e in Exposure.query.filter(Exposure.tenant_id == tenant.id, Exposure.status == "open"):
        best[e.cve_id] = max(best.get(e.cve_id, 0), e.risk_score)
    for cve_id, score in sorted(best.items(), key=lambda x: -x[1]):
        if cve_id in done or score < tenant.autonomous_min_score:
            continue
        cve = CveIntel.query.filter_by(cve_id=cve_id).first()
        if tenant.autonomous_kev_only and not (cve and cve.kev):
            continue
        r = trigger(tenant, cve_id)
        if r:
            runs.append(r)
    return runs


def _open_exposures(run: AutonomousRun) -> list[Exposure]:
    return Exposure.query.filter(Exposure.tenant_id == run.tenant_id, Exposure.cve_id == run.cve_id,
                                 Exposure.status.in_(("open", "mitigated", "patching", "remediated"))).all()


def approve(run: AutonomousRun, user=None) -> None:
    """Aprovação humana (modo aconselhar, ou patch em *hold* / anel em pausa)."""
    d = run.data_dict
    d["approved"] = True
    d["approved_by"] = getattr(user, "email", "")
    run.data = json.dumps(d)
    if run.status == "approval":
        run.status = "running"
    _log(run, f"Aprovado por {d['approved_by'] or 'utilizador'}.")


def stop(run: AutonomousRun) -> None:
    run.status, run.finished_at = "stopped", utcnow()
    _log(run, "Fluxo interrompido manualmente.")


def advance(run: AutonomousRun, now=None) -> str:
    """Executa a etapa atual (um passo por chamada). Devolve o estado do fluxo."""
    if run.status not in ("running", "waiting"):
        return run.status
    now = now or utcnow()
    tenant = db.session.get(Tenant, run.tenant_id)
    handler = _STAGES.get(run.stage)
    if handler is None:
        return run.status
    try:
        handler(run, tenant, now)
    except Exception as exc:  # noqa: BLE001 - nunca derruba o worker; o fluxo fica visível como falhado
        log.exception("Fluxo %s: %s", run.id, exc)
        _log(run, f"Erro na etapa {run.stage}: {exc}")
        run.status, run.finished_at = "failed", utcnow()
    return run.status


def _next(run: AutonomousRun, stage: str) -> None:
    run.stage = stage
    run.status = "running"


# ------------------------------------------------------------------ etapas


def _discovery(run, tenant, now):
    intel.enrich([run.cve_id])
    cve = CveIntel.query.filter_by(cve_id=run.cve_id).first()
    n_assets = Asset.query.filter_by(tenant_id=tenant.id, managed=True).count()
    _log(run, f"Descoberta: inteligência do CVE atualizada (CVSS {cve.cvss if cve else 'n/d'}, "
              f"KEV {'sim' if cve and cve.kev else 'não'}); {n_assets} ativos geridos no inventário.")
    _next(run, "assessment")


def _assessment(run, tenant, now):
    correlate.correlate_tenant(tenant)
    exps = _open_exposures(run)
    if not exps:
        _log(run, "Avaliação: nenhum ativo afetado — nada a remediar.")
        run.status, run.finished_at, run.stage = "completed", utcnow(), "done"
        return
    top = max(e.risk_score for e in exps)
    cats = sorted({e.risk_category for e in exps})
    _log(run, f"Avaliação de risco: {len(exps)} exposição(ões); risco máximo {top}/100 ({', '.join(cats)}).")
    if top < tenant.autonomous_min_score and run.mode != "advise":
        _log(run, f"Risco abaixo do limiar ({tenant.autonomous_min_score}): acompanhamento normal pelas políticas de SLA.")
        run.status, run.finished_at, run.stage = "completed", utcnow(), "done"
        return
    _set(run, risk_max=top)
    _next(run, "mapping")


def _mapping(run, tenant, now):
    exps = _open_exposures(run)
    ids = sorted({e.asset_id for e in exps})
    by_os: dict[str, int] = {}
    for a in Asset.query.filter(Asset.id.in_(ids or [0])):
        by_os[a.os_family or "n/d"] = by_os.get(a.os_family or "n/d", 0) + 1
    _set(run, asset_ids=ids)
    _log(run, f"Mapeamento: {len(ids)} ativo(s) afetados ({', '.join(f'{k}: {v}' for k, v in by_os.items())}).")
    _next(run, "patch_search")


def _patch_search(run, tenant, now):
    cve = CveIntel.query.filter_by(cve_id=run.cve_id).first()
    found = patches.identify_for_cve(tenant.id, cve) if cve else []
    exps = _open_exposures(run)
    for e in exps:
        correlate.refresh(e, tenant, cve)
    usable = [p for p in found if p.status != "rejected"]
    if not usable:
        if run.data_dict.get("waiting_for_patch"):
            run.status = "waiting"      # já registado: reavalia em silêncio a cada ciclo
            return
        proposed = sum(len(controls.propose_for(tenant, e)) for e in exps)
        applied = 0
        if run.mode == "auto":
            for c in controls.ControlAction.query.filter_by(tenant_id=tenant.id, cve_id=run.cve_id, status="proposed"):
                controls.approve(c)
                controls.apply(c, tenant)
                applied += 1
        _log(run, f"Procura de patch: sem patch disponível. {proposed} controlo(s) compensatório(s) propostos"
                  f"{f', {applied} aplicados automaticamente' if applied else ''}. A aguardar patch do fabricante.")
        run.status = "waiting"           # revisto em cada ciclo: reavalia quando surgir patch
        _set(run, waiting_for_patch=True)
        return
    # prioriza o patch com melhor recomendação da Patch Intelligence
    order = {"go": 0, "caution": 1, "hold": 2}
    scored = sorted(usable, key=lambda p: (order[patches.intelligence(p)["level"]], -len(p.cve_list)))
    ranked = [p for p in scored if patches.intelligence(p)["level"] != "hold"] or scored
    chosen, seen_keys = [], set()
    for p in ranked:                        # um patch por (SO, produto): o melhor classificado
        key = (p.os_family, (p.product or p.package_name or p.patch_uid).lower())
        if key not in seen_keys:
            seen_keys.add(key)
            chosen.append(p)
    _set(run, patch_ids=[p.id for p in chosen], waiting_for_patch=False)
    levels = ", ".join(f"{p.patch_uid} ({patches.intelligence(p)['level']})" for p in chosen[:4])
    _log(run, f"Procura de patch: {len(usable)} patch(es) identificado(s): {levels}.")
    _next(run, "test")


def _needs_human(run, tenant, patch_list: list[Patch]) -> str | None:
    d = run.data_dict
    if d.get("approved"):
        return None
    if run.mode == "advise":
        return "Modo aconselhar: aprove o plano para iniciar o teste no Ring 0."
    holds = [p.patch_uid for p in patch_list if patches.intelligence(p)["level"] == "hold"]
    if holds:
        return "Patch Intelligence recomenda não aplicar (" + ", ".join(holds) + "): decisão humana necessária."
    return None


def _test(run, tenant, now):
    """Ring 0: cria a campanha (rings automáticos) e espera o resultado do laboratório."""
    d = run.data_dict
    plist = [db.session.get(Patch, i) for i in d.get("patch_ids", [])]
    plist = [p for p in plist if p]
    if not plist:
        _next(run, "patch_search")
        return
    reason = _needs_human(run, tenant, plist)
    if reason:
        run.status = "approval"
        _log(run, reason)
        return
    if not d.get("campaign_ids"):
        rings.ensure_policies(tenant)
        cids = []
        emergency = any(e.risk_category == "emergency" for e in _open_exposures(run))
        for p in plist:
            if p.status != "approved":
                p.status = "approved"
                _log(run, f"Patch {p.patch_uid} aprovado ({'autónomo' if run.mode == 'auto' else d.get('approved_by', 'humano')}).")
            try:
                c = deploy.create_campaign(tenant, p, f"[Autónomo] {run.cve_id} — {p.patch_uid}",
                                           {"cve_id": run.cve_id}, origin="autonomous", run_id=run.id,
                                           emergency=emergency, force=bool(d.get("approved")))
                cids.append(c.id)
            except deploy.PatchBlocked as exc:
                _log(run, f"Campanha não criada para {p.patch_uid}: {exc}")
        if not cids:
            run.status = "approval"
            _log(run, "Nenhuma campanha pôde ser criada: intervenção humana necessária.")
            return
        _set(run, campaign_ids=cids)
        _log(run, f"Teste automático: campanha(s) {cids} criada(s); a executar no Ring 0 (laboratório).")
        return
    camps = [db.session.get(Campaign, i) for i in d["campaign_ids"]]
    camps = [c for c in camps if c]
    if any(c.status == "paused" for c in camps):
        run.status = "approval"
        _log(run, "Campanha em pausa no teste: " + "; ".join(
            r for c in camps for st in c.rings_state.values() for r in st.get("reasons", [])[:2]))
        return
    if all(c.status in ("completed", "cancelled", "failed") or c.current_ring > 0
           or c.rings_state.get("0", {}).get("state") == "done" for c in camps):
        _log(run, "Teste automático concluído: critérios do Ring 0 cumpridos.")
        _next(run, "rings")


def _rings(run, tenant, now):
    camps = [db.session.get(Campaign, i) for i in run.data_dict.get("campaign_ids", [])]
    camps = [c for c in camps if c]
    if any(c.status == "paused" for c in camps):
        run.status = "approval"
        _log(run, "Ring deployment em pausa (critérios de promoção não cumpridos): decisão humana necessária.")
        return
    if all(c.status in ("completed", "cancelled", "failed") for c in camps):
        _log(run, "Ring deployment concluído até à produção global.")
        _next(run, "validation")


def _validation(run, tenant, now):
    pending = [e for e in _open_exposures(run) if e.status == "remediated"]
    if pending:
        run.status = "waiting"
        return
    _log(run, "Validação: ver resultados abaixo (patch instalado, serviço, CVE, exposição, compliance).")
    _next(run, "closure")


def _closure(run, tenant, now):
    exps = Exposure.query.filter_by(tenant_id=tenant.id, cve_id=run.cve_id).all()
    closed = [e for e in exps if e.status == "closed"]
    still = [e for e in exps if e.status in ("open", "mitigated", "patching", "remediated")]
    _set(run, closed=len(closed), still_open=len(still))
    _log(run, f"Fecho automático: {len(closed)} exposição(ões) fechadas e validadas; {len(still)} ainda em aberto.")
    _next(run, "cmdb")


def _cmdb(run, tenant, now):
    from ..connectors import sync
    ids = run.data_dict.get("asset_ids", [])
    n = sync.push_cmdb(tenant, [db.session.get(Asset, i) for i in ids if db.session.get(Asset, i)])
    _log(run, f"CMDB atualizada: {n} registo(s) sincronizados.")
    _next(run, "report")


def _report(run, tenant, now):
    from ..connectors import sync
    k = executive.kpis(tenant)
    d = run.data_dict
    rep = {"cve": run.cve_id, "assets": len(d.get("asset_ids", [])), "closed": d.get("closed", 0),
           "still_open": d.get("still_open", 0), "campaigns": d.get("campaign_ids", []),
           "started_at": run.created_at.isoformat(), "finished_at": utcnow().isoformat(),
           "hours": round((utcnow() - run.created_at).total_seconds() / 3600, 1),
           "kpis": {x: k[x] for x in ("total_assets", "open_exposures", "patch_compliance", "mttp_days", "mttr_days",
                                      "kev_exposures", "sla_breaches")}}
    run.report = json.dumps(rep)
    sync.on_run_completed(tenant, run, rep)
    _log(run, f"Reporte executivo emitido ({rep['closed']} fechadas, {rep['still_open']} em aberto, {rep['hours']} h).")
    run.stage, run.status, run.finished_at = "done", "completed", utcnow()


_STAGES = {"discovery": _discovery, "assessment": _assessment, "mapping": _mapping, "patch_search": _patch_search,
           "test": _test, "rings": _rings, "validation": _validation, "closure": _closure, "cmdb": _cmdb,
           "report": _report}


def reevaluate_waiting(tenant: Tenant) -> int:
    """Fluxos à espera de patch voltam a procurar (novas inteligências/avisos)."""
    n = 0
    for r in AutonomousRun.query.filter_by(tenant_id=tenant.id, status="waiting", stage="patch_search"):
        r.status = "running"
        n += 1
    return n


def stage_index(run: AutonomousRun) -> int:
    return AUTONOMOUS_STAGES.index(run.stage) if run.stage in AUTONOMOUS_STAGES else 0


__all__ = ["AUTONOMOUS_STAGE_LABELS", "jloads"]
