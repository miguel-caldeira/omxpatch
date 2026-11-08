"""Correlação automática: Ativo → Software → Versão → CVE → Exploração ativa → Patch disponível.

Cria/atualiza ``Exposure``, liga cada uma ao melhor patch do repositório, calcula o risco dinâmico e o veredicto
multi-vendor, e fixa o prazo (SLA) pela categoria de risco. Uma exposição de origem *correlation* cujo software
já não é afetado passa a *remediada* e dispara a validação em ciclo fechado (Módulo 10).
"""
from __future__ import annotations

import json
import re
from datetime import timedelta

from ..extensions import db
from ..models import (OPEN_EXPOSURE, Asset, AssetSoftware, ControlAction, CveIntel, Exposure, Signal, Tenant, utcnow)
from . import patches, risk
from .versions import in_range

_STOP = {"for", "the", "and", "inc", "corporation", "corp", "ltd", "llc", "gmbh", "software", "foundation", "project",
         "x64", "x86", "64bit", "32bit", "edition", "version", "update", "runtime", "client", "server", "app"}


def tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", (text or "").lower()) if t and t not in _STOP]


def software_matches(sw: AssetSoftware, entry: dict) -> bool:
    product = tokens((entry.get("product") or "").replace("_", " "))
    if not product:
        return False
    name = tokens(sw.name)
    joined = "".join(name)
    if not (set(product) <= set(name) or "".join(product) in joined):
        return False
    vendor = tokens((entry.get("vendor") or "").replace("_", " "))
    have_vendor = tokens(sw.vendor)
    if vendor and have_vendor and not (set(vendor) & set(have_vendor)) and "".join(vendor) not in joined:
        return False
    return True


def entry_affects(version: str, entry: dict) -> bool:
    return in_range(version, start=entry.get("version_start", ""), start_excl=entry.get("start_excl", ""),
                    end=entry.get("version_end", ""), end_excl=entry.get("end_excl", ""),
                    exact=entry.get("exact", ""))


def _index(cves: list[CveIntel]) -> dict[str, list[tuple[CveIntel, dict]]]:
    idx: dict[str, list[tuple[CveIntel, dict]]] = {}
    for c in cves:
        for e in c.affected_list:
            toks = tokens((e.get("product") or "").replace("_", " "))
            if toks and any(e.get(k) for k in ("version_start", "start_excl", "version_end", "end_excl", "exact")):
                idx.setdefault(max(toks, key=len), []).append((c, e))
    return idx


def candidates(asset: Asset, idx: dict) -> list[tuple[AssetSoftware, CveIntel, dict]]:
    out = []
    for sw in asset.software:
        if not sw.version:
            continue
        keys = set(tokens(sw.name)) | {"".join(tokens(sw.name))}
        for key in keys:
            for cve, entry in idx.get(key, []):
                if software_matches(sw, entry) and entry_affects(sw.version, entry):
                    out.append((sw, cve, entry))
    return out


def os_candidates(asset: Asset, cves: list[CveIntel]) -> list[tuple[CveIntel, dict]]:
    """CVE do SO tratados por KB (Windows): avisos com ``kb`` cujo produto corresponde ao SO e KB em falta."""
    if asset.os_family != "windows":
        return []
    installed = {str(k).upper() for k in asset.hw.get("hotfixes", [])}
    out = []
    for c in cves:
        for adv in c.advisory_list:
            kb = (adv.get("kb") or "").upper()
            if not kb or kb in installed:
                continue
            prod = tokens(adv.get("product", ""))
            if prod and set(prod) <= set(tokens(f"{asset.os_name} {asset.os_version}")):
                out.append((c, adv))
    return out


def _signals(tenant_id: int, asset: Asset, cve_id: str) -> list[Signal]:
    return Signal.query.filter(Signal.tenant_id == tenant_id,
                               db.or_(Signal.cve_id == cve_id, db.and_(Signal.cve_id == "", Signal.asset_id == asset.id))
                               ).all()


def refresh(ex: Exposure, tenant: Tenant | None = None, cve: CveIntel | None = None) -> Exposure:
    """Recalcula patch, veredicto, risco e prazo de uma exposição."""
    tenant = tenant or db.session.get(Tenant, ex.tenant_id)
    cve = cve or CveIntel.query.filter_by(cve_id=ex.cve_id).first()
    asset = ex.asset
    patches.link_exposure(ex, cve)
    signals = _signals(ex.tenant_id, asset, ex.cve_id)
    controls = ControlAction.query.filter(ControlAction.tenant_id == ex.tenant_id, ControlAction.cve_id == ex.cve_id,
                                          db.or_(ControlAction.asset_id == asset.id, ControlAction.asset_id.is_(None))).all()
    verdict = risk.exposure_verdict(ex, cve, asset, signals, controls)
    from . import exposure_sim, priority
    exposure_sim.apply(ex, cve, asset, controls, verdict)            # simulação de exposição (contexto do agente + inteligência), sem tocar no ativo
    priority.apply(ex, cve, asset, controls)                          # perda esperada (probabilidade × impacto)
    observed = verdict["active_exploitation_observed"]
    res = risk.score_exposure(cve, asset, observed, controls, floor=verdict["floor"])
    ex.verdict = json.dumps(verdict, ensure_ascii=False)
    ex.factors = json.dumps(res["factors"], ensure_ascii=False)
    if ex.status in OPEN_EXPOSURE and ex.status != "remediated":
        ex.risk_score, ex.risk_category, ex.residual_score = res["score"], res["category"], res["residual"]
        if ex.status == "open" and any(c.status in risk.EFFECTIVE_STATUS for c in controls):
            ex.status = "mitigated"
        elif ex.status == "mitigated" and not any(c.status in risk.EFFECTIVE_STATUS for c in controls):
            ex.status = "open"
    elif ex.status in ("closed", "accepted"):
        ex.residual_score = 0 if ex.status == "closed" else ex.residual_score
    days = tenant.sla_days(res["category"]) if tenant else None
    if days is not None:
        ex.due_date = ex.detected_at + timedelta(days=days)
    return ex


def _upsert_exposure(tenant: Tenant, asset: Asset, cve: CveIntel, sw_name: str, version: str, fixed: str,
                     source: str = "correlation") -> tuple[Exposure, bool]:
    ex = Exposure.query.filter_by(tenant_id=tenant.id, asset_id=asset.id, cve_id=cve.cve_id,
                                  software_name=sw_name[:255]).first()
    created = ex is None
    if created:
        ex = Exposure(tenant_id=tenant.id, asset_id=asset.id, cve_id=cve.cve_id, software_name=sw_name[:255],
                      installed_version=version[:120], fixed_version=fixed[:120], source=source)
        db.session.add(ex)
        db.session.flush()
    else:
        ex.last_seen = utcnow()
        ex.installed_version = version[:120] or ex.installed_version
        if fixed:
            ex.fixed_version = fixed[:120]
        if ex.status in ("closed", "remediated") and ex.source == "correlation":
            ex.status, ex.closed_at = "open", None          # reapareceu: reabre
            ex.detected_at = utcnow()
    return ex, created


def correlate_asset(tenant: Tenant, asset: Asset, cves: list[CveIntel] | None = None, idx: dict | None = None) -> dict:
    cves = cves if cves is not None else CveIntel.query.all()
    idx = idx if idx is not None else _index(cves)
    found: set[tuple[str, str]] = set()
    new = 0
    for sw, cve, entry in candidates(asset, idx):
        fixed = entry.get("fixed") or entry.get("end_excl") or ""
        ex, created = _upsert_exposure(tenant, asset, cve, sw.name, sw.version, fixed)
        found.add((cve.cve_id, sw.name[:255]))
        new += created
        refresh(ex, tenant, cve)
    for cve, adv in os_candidates(asset, cves):
        label = f"{asset.os_name} {asset.os_version}".strip()[:255] or "Sistema operativo"
        ex, created = _upsert_exposure(tenant, asset, cve, label, asset.os_version, (adv.get("kb") or "").upper())
        found.add((cve.cve_id, label))
        new += created
        refresh(ex, tenant, cve)
    remediated = 0
    for ex in Exposure.query.filter(Exposure.tenant_id == tenant.id, Exposure.asset_id == asset.id,
                                    Exposure.source == "correlation",
                                    Exposure.status.in_(("open", "mitigated", "patching"))):
        if (ex.cve_id, ex.software_name) not in found:
            ex.status, ex.patched_at = "remediated", utcnow()
            remediated += 1
            from . import validation
            validation.schedule(ex, tenant)
    return {"new": new, "remediated": remediated, "found": len(found)}


def correlate_tenant(tenant: Tenant) -> dict:
    cves = CveIntel.query.all()
    idx = _index(cves)
    total = {"assets": 0, "new": 0, "remediated": 0}
    new_ids: list[int] = []
    for asset in Asset.query.filter_by(tenant_id=tenant.id):
        before = {e.id for e in Exposure.query.filter_by(tenant_id=tenant.id, asset_id=asset.id)}
        r = correlate_asset(tenant, asset, cves, idx)
        total["assets"] += 1
        total["new"] += r["new"]
        total["remediated"] += r["remediated"]
        new_ids += [e.id for e in Exposure.query.filter_by(tenant_id=tenant.id, asset_id=asset.id) if e.id not in before]
    db.session.commit()
    total["new_ids"] = new_ids
    return total


def refresh_tenant(tenant: Tenant) -> int:
    """Recalcula risco/veredicto de todas as exposições abertas (novos sinais, controlos, EPSS/KEV atualizados)."""
    n = 0
    for ex in Exposure.query.filter(Exposure.tenant_id == tenant.id, Exposure.status.in_(OPEN_EXPOSURE)):
        refresh(ex, tenant)
        n += 1
    db.session.commit()
    return n
