"""Prioridade de remediação por **perda esperada** (impacto real), em vez de só severidade/CVSS.

    perda esperada = P(exploração) × impacto do ativo

* ``P`` parte do EPSS (ou, sem ele, da maturidade do exploit/KEV) e é multiplicada pelo veredito da simulação de exposição
  (``confirmed`` 1,0 … ``unreachable`` 0,03) e reduzida se houver controlos compensatórios eficazes;
* ``impacto`` = custo/hora de indisponibilidade do ativo (valor próprio ou por criticidade) × horas de paragem esperadas ×
  fator de valor de negócio (0,5–1,5).

Os valores por omissão (``IMPACT_*``) são **pressupostos configuráveis**, não medições: ajuste-os à realidade financeira da organização."""
from __future__ import annotations

from flask import current_app

from ..models import Asset, CveIntel, Exposure
from . import exposure_sim, risk

CRIT_KEY = {"low": "IMPACT_COST_LOW", "medium": "IMPACT_COST_MEDIUM", "high": "IMPACT_COST_HIGH", "critical": "IMPACT_COST_CRITICAL"}


def _cfg(k, d=None):
    return current_app.config.get(k, d) if current_app else d


def asset_impact(asset: Asset) -> dict:
    cost = asset.cost_per_hour if asset.cost_per_hour not in (None, 0) else float(_cfg(CRIT_KEY.get(asset.criticality, "IMPACT_COST_MEDIUM"), 1000))
    hours = float(_cfg("IMPACT_OUTAGE_HOURS", 24))
    bv = max(0, min(100, int(asset.business_value if asset.business_value is not None else 50)))
    factor = 0.5 + bv / 100
    return {"cost_per_hour": cost, "hours": hours, "business_factor": round(factor, 2), "amount": round(cost * hours * factor, 2), "own_value": bool(asset.cost_per_hour)}


def base_probability(cve: CveIntel | None) -> tuple[float, str]:
    if cve is None:
        return 0.05, "sem inteligência sobre o CVE"
    epss = cve.epss if cve.epss is not None else None
    if epss is not None:
        p, why = float(epss), f"EPSS {epss:.0%}"
    else:
        p, why = {"weaponized": 0.5, "functional": 0.3, "poc": 0.1}.get(cve.exploit_maturity or "none", 0.02), f"maturidade do exploit «{cve.exploit_maturity or 'none'}»"
    if cve.kev:
        p, why = max(p, 0.5), why + " + CISA KEV (mín. 50 %)"
    if cve.ransomware:
        p = min(1.0, p * 1.2)
    return min(1.0, p), why


def score(ex: Exposure, cve: CveIntel | None, asset: Asset, controls: list) -> dict:
    p0, why = base_probability(cve)
    sim_w = exposure_sim.WEIGHT.get(ex.exploitability or "unknown", 0.5)
    ctl = 0.4 if any(c.status in risk.EFFECTIVE_STATUS for c in controls) else 1.0
    p = round(min(1.0, p0 * sim_w * ctl), 4)
    imp = asset_impact(asset)
    loss = round(p * imp["amount"], 2)
    return {"probability": p, "base_probability": round(p0, 4), "basis": why, "simulation_weight": sim_w, "control_factor": ctl, "impact": imp, "expected_loss": loss,
            "explanation": f"{p:.1%} (base {p0:.1%} [{why}] × simulação {sim_w:g} × controlos {ctl:g}) × impacto {imp['amount']:,.0f} {_cfg('IMPACT_CURRENCY', 'EUR')}"}


def apply(ex: Exposure, cve: CveIntel | None, asset: Asset, controls: list) -> dict:
    res = score(ex, cve, asset, controls)
    ex.expected_loss = res["expected_loss"] if ex.status in ("open", "mitigated", "patching") else 0.0
    return res


def money(v: float) -> str:
    cur = _cfg("IMPACT_CURRENCY", "EUR")
    return f"{v:,.0f} {cur}".replace(",", " ")
