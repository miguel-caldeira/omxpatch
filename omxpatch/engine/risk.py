"""Módulo 4 — Dynamic Risk Score (0–100) e Módulo 3 — veredicto de exposição multi-vendor.

Pontuação (soma = 100), explicável fator a fator:

=====================  ======  =================================================================
Fator                  Máx.    Origem
=====================  ======  =================================================================
CVSS                   25      CVSS base ×2,5 (sem CVSS: 5,0)
EPSS                   15      <1 % = 2 · <10 % = 6 · <50 % = 11 · ≥50 % = 15
KEV                    15      CISA KEV = 12; +3 se usada em ransomware
Criticidade do ativo   12      crítica 12 · alta 8 · média 4 · baixa 0
Exposição à Internet   10      exposto = 10
Valor de negócio        8      valor de negócio do ativo (0–100) ×0,08
Evidência de exploit   15      exploração observada no ambiente = 15; senão maturidade do exploit
                               (weaponized 10, funcional 7, PoC 4) +3 se associado a malware
=====================  ======  =================================================================

Categorias: Baixo < 25 ≤ Médio < 50 ≤ Alto < 70 ≤ Crítico < 85 ≤ Emergência.

O **risco residual** aplica os controlos compensatórios aplicados/verificados (firewall, EDR, WAF…) aos
fatores que eles realmente atenuam. Remediar (patch) leva o risco a 0.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime

from ..models import ControlAction, CveIntel, jloads

WEIGHTS = {"cvss": 25, "epss": 15, "kev": 15, "criticality": 12, "internet": 10, "business": 8, "evidence": 15}
LABELS = {"cvss": "CVSS", "epss": "EPSS", "kev": "CISA KEV", "criticality": "Criticidade do ativo",
          "internet": "Exposição à Internet", "business": "Valor de negócio", "evidence": "Evidência de exploit"}
CATEGORY_BANDS = [(85, "emergency"), (70, "critical"), (50, "high"), (25, "medium"), (0, "low")]
CRIT_POINTS = {"critical": 12, "high": 8, "medium": 4, "low": 0}
MATURITY_POINTS = {"none": 0, "poc": 4, "functional": 7, "weaponized": 10}

# Efeito (multiplicador dos pontos do fator) de cada controlo compensatório quando aplicado
CONTROL_EFFECT: dict[str, dict[str, float]] = {
    "block_port": {"internet": 0.0, "evidence": 0.4, "epss": 0.6},
    "block_ioc": {"evidence": 0.6},
    "block_country": {"internet": 0.5, "evidence": 0.7},
    "edr_detection": {"evidence": 0.6},
    "edr_block": {"evidence": 0.3, "epss": 0.7},
    "siem_rule": {"evidence": 0.9},
    "siem_correlation": {"evidence": 0.85},
    "disable_account": {"evidence": 0.7},
    "force_mfa": {"evidence": 0.8},
    "virtual_patch": {"cvss": 0.4, "epss": 0.3, "evidence": 0.2, "internet": 0.5},
}
EFFECTIVE_STATUS = ("applied", "verified")


def category_for(score: int) -> str:
    for threshold, cat in CATEGORY_BANDS:
        if score >= threshold:
            return cat
    return "low"


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address((ip or "").strip()).is_global
    except ValueError:
        return False


def internet_exposed(asset) -> bool:
    mode = getattr(asset, "internet_exposed", "auto")
    if mode == "yes":
        return True
    if mode == "no":
        return False
    return is_public_ip(getattr(asset, "ip", "")) or getattr(asset, "kind", "") == "saas"


def factor_points(cve: CveIntel | None, asset, evidence_observed: bool = False) -> dict[str, float]:
    cvss = (cve.cvss if cve and cve.cvss is not None else 5.0)
    epss = cve.epss if cve and cve.epss is not None else None
    if epss is None:
        pts_epss = 2 if not (cve and cve.kev) else 6
    else:
        pts_epss = 2 if epss < 0.01 else 6 if epss < 0.10 else 11 if epss < 0.50 else 15
    kev = 0
    if cve and cve.kev:
        kev = 12 + (3 if cve.ransomware else 0)
    if evidence_observed:
        evidence = 15
    else:
        evidence = MATURITY_POINTS.get(cve.exploit_maturity if cve else "none", 0)
        if cve and cve.malware_list:
            evidence += 3
        evidence = min(evidence, 15)
    return {
        "cvss": min(25.0, cvss * 2.5), "epss": float(pts_epss), "kev": float(kev),
        "criticality": float(CRIT_POINTS.get(getattr(asset, "criticality", "medium"), 4)),
        "internet": 10.0 if internet_exposed(asset) else 0.0,
        "business": max(0, min(100, int(getattr(asset, "business_value", 50) or 0))) * WEIGHTS["business"] / 100,
        "evidence": float(evidence),
    }


def _detail(key: str, cve: CveIntel | None, asset, observed: bool) -> str:
    if key == "cvss":
        return f"CVSS {cve.cvss if cve and cve.cvss is not None else 'n/d (5,0 assumido)'}"
    if key == "epss":
        return f"EPSS {cve.epss * 100:.1f} %" if cve and cve.epss is not None else "EPSS n/d"
    if key == "kev":
        return ("Na lista CISA KEV" + (" · usada em ransomware" if cve.ransomware else "")) if cve and cve.kev else "Fora da lista KEV"
    if key == "criticality":
        return f"Ativo de criticidade {getattr(asset, 'criticality', 'média')}"
    if key == "internet":
        return "Exposto à Internet" if internet_exposed(asset) else "Apenas rede interna"
    if key == "business":
        return f"Valor de negócio {getattr(asset, 'business_value', 50)}/100"
    if observed:
        return "Exploração observada no ambiente"
    mat = cve.exploit_maturity if cve else "none"
    extra = f" · malware: {', '.join(cve.malware_list)}" if cve and cve.malware_list else ""
    return f"Maturidade do exploit: {mat}{extra}"


def apply_controls(points: dict[str, float], controls: list[ControlAction]) -> dict[str, float]:
    out = dict(points)
    for c in controls:
        if c.status not in EFFECTIVE_STATUS:
            continue
        for factor, mult in CONTROL_EFFECT.get(c.action, {}).items():
            out[factor] = out[factor] * mult
    return out


def score_exposure(cve: CveIntel | None, asset, evidence_observed: bool = False,
                   controls: list[ControlAction] | None = None, floor: str | None = None) -> dict:
    """Devolve {score, category, residual, residual_category, factors[]}; ``floor`` impõe uma categoria mínima
    (veredicto multi-vendor de risco crítico)."""
    pts = factor_points(cve, asset, evidence_observed)
    score = int(round(min(100, sum(pts.values()))))
    residual_pts = apply_controls(pts, controls or [])
    residual = int(round(min(100, sum(residual_pts.values()))))
    factors = [{"key": k, "label": LABELS[k], "points": round(pts[k], 1), "residual": round(residual_pts[k], 1),
                "max": WEIGHTS[k], "detail": _detail(k, cve, asset, evidence_observed)} for k in WEIGHTS]
    if floor:
        mins = {"critical": 70, "emergency": 85}
        score = max(score, mins.get(floor, 0))
        residual = max(residual, mins.get(floor, 0)) if not any(c.status in EFFECTIVE_STATUS for c in (controls or [])) \
            else residual
    return {"score": score, "category": category_for(score), "residual": residual,
            "residual_category": category_for(residual), "factors": factors}


def asset_risk(scores: list[int]) -> int:
    """Risco agregado de um ativo (ou grupo): probabilidade combinada — 1 − Π(1 − sᵢ/100)."""
    prod = 1.0
    for s in scores:
        prod *= 1 - max(0, min(100, s)) / 100
    return int(round((1 - prod) * 100))


# --------------------------------------------------------------------------- Módulo 3 — veredicto multi-vendor


def _latest(signals, kinds: tuple[str, ...]):
    rel = [s for s in signals if s.kind in kinds]
    return max(rel, key=lambda s: s.observed_at or datetime.min) if rel else None


def exposure_verdict(exposure, cve: CveIntel | None, asset, signals: list, controls: list[ControlAction]) -> dict:
    """Correlaciona sinais de vários fabricantes e conclui se a exposição é realmente crítica.

    ``signals`` são os sinais do tenant relevantes (mesmo CVE, mesmo ativo ou globais ao CVE).
    Cada conclusão é True / False / None (desconhecido)."""
    active_obs = any(s.kind == "active_exploit" and (s.asset_id in (None, asset.id)) for s in signals)
    active_known = bool(cve and cve.kev)
    fw = _latest([s for s in signals if s.asset_id in (None, asset.id)], ("fw_blocked", "fw_allowed"))
    edr = _latest([s for s in signals if s.asset_id in (None, asset.id)], ("edr_detected", "edr_missed"))
    waf = _latest(signals, ("waf_protected",))
    fw_blocks: bool | None = (fw.kind == "fw_blocked") if fw else None
    edr_detects: bool | None = (edr.kind == "edr_detected") if edr else None
    for c in controls:
        if c.status in EFFECTIVE_STATUS:
            if c.category == "firewall":
                fw_blocks = True
            elif c.category == "edr":
                edr_detects = True
            elif c.category == "waf":
                waf = waf or c
    waf_protected = waf is not None
    patch_available = bool(exposure.patch_available)
    vulnerable = exposure.status in ("open", "mitigated", "patching")
    conclusions = []
    conclusions.append(("Vulnerável" if vulnerable else "Não vulnerável", vulnerable))
    if active_obs:
        conclusions.append(("Exploração ativa observada no ambiente", True))
    elif active_known:
        conclusions.append(("Exploração ativa conhecida (CISA KEV)", True))
    else:
        conclusions.append(("Sem exploração ativa conhecida", False))
    conclusions.append(("Firewall não bloqueia" if fw_blocks is not True else "Firewall bloqueia",
                        fw_blocks is not True))
    conclusions.append(("EDR não deteta" if edr_detects is not True else "EDR deteta", edr_detects is not True))
    conclusions.append(("Patch ainda indisponível" if not patch_available else "Patch disponível", not patch_available))
    unprotected = fw_blocks is not True and edr_detects is not True and not waf_protected
    critical = vulnerable and (active_obs or active_known) and unprotected and not patch_available
    reasons = [text for text, bad in conclusions if bad]
    floor = None
    if critical:
        floor = "emergency" if internet_exposed(asset) and cve is not None and cve.kev else "critical"
    return {"vulnerable": vulnerable, "active_exploitation_observed": active_obs,
            "active_exploitation_known": active_known, "firewall_blocks": fw_blocks, "edr_detects": edr_detects,
            "waf_protected": waf_protected, "patch_available": patch_available, "critical": critical,
            "floor": floor, "conclusions": [{"text": t, "adverse": b} for t, b in conclusions],
            "summary": ("Risco crítico: " + "; ".join(reasons)) if critical else
                       ("Exposição parcialmente mitigada" if vulnerable and not unprotected else
                        ("Vulnerável" if vulnerable else "Sem exposição"))}


def verdict_json(v: dict) -> str:
    import json
    return json.dumps(v, ensure_ascii=False)


def parse_factors(text: str) -> list[dict]:
    return jloads(text, [])
