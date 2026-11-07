"""Módulo 12 — Compliance & Governance: NIS2, ISO/IEC 27001, DORA, PCI-DSS (Req. 6) e CIS Controls (7).

Cada requisito é calculado a partir dos dados vivos (inventário, exposições, SLA, campanhas, validações) e
devolve um estado — ``compliant``, ``partial`` ou ``gap`` — com a métrica e a evidência que o sustenta.
O mesmo resultado é exposto à API (para o OMXGRC) e aos painéis.
"""
from __future__ import annotations

from ..models import Campaign, Tenant, Validation, utcnow
from . import executive

STATUS_LABEL = {"compliant": "Conforme", "partial": "Parcial", "gap": "Lacuna"}


def _req(rid: str, title: str, status: str, metric: str, detail: str = "") -> dict:
    return {"id": rid, "title": title, "status": status, "metric": metric, "detail": detail}


def _grade(ok: bool, partial: bool = False) -> str:
    return "compliant" if ok else ("partial" if partial else "gap")


def build(tenant: Tenant) -> dict:
    k = executive.kpis(tenant)
    cats = k["by_category"]
    crit = cats["critical"] + cats["emergency"]
    total_assets = k["total_assets"] or 1
    managed_pct = round(100 * k["managed_assets"] / total_assets, 1)
    validated = Validation.query.filter_by(tenant_id=tenant.id, status="passed").count()
    sla_ok = k["sla_breaches"] == 0
    inv_ok = k["total_assets"] > 0 and k["shadow_it"] == 0
    kev_ok = k["kev_exposures"] == 0
    comp = k["patch_compliance"]
    mttr = k["mttr_days"]
    auto_patch = Campaign.query.filter_by(tenant_id=tenant.id).count() > 0

    frameworks = {
        "nis2": {"name": "NIS2 (UE 2022/2555 · DL 125/2025)", "requirements": [
            _req("Art. 21.º n.º 2 al. e)", "Vulnerabilidades críticas em aberto", _grade(crit == 0, crit <= 3),
                 f"{crit} crítica(s)/emergência", "Aquisição, desenvolvimento e manutenção seguros, incluindo o tratamento de vulnerabilidades."),
            _req("Art. 21.º n.º 2 al. e)", "Violações de SLA de remediação", _grade(sla_ok, k["sla_breaches"] <= 5),
                 f"{k['sla_breaches']} fora do prazo", "Prazos por categoria de risco definidos na organização."),
            _req("Art. 21.º n.º 2 al. f)", "Avaliação da eficácia das medidas", _grade(validated > 0 and k["validation_failed"] == 0, validated > 0),
                 f"{validated} remediações validadas; {k['validation_failed']} falhadas", "Validação em ciclo fechado e simulação de ataque."),
            _req("Art. 21.º n.º 2 al. i)", "Gestão de ativos", _grade(inv_ok, k["total_assets"] > 0),
                 f"{k['total_assets']} ativos; {k['shadow_it']} Shadow IT"),
            _req("Art. 21.º n.º 2 al. g)", "Higiene cibernética (patching)", _grade(comp >= 95, comp >= 80), f"{comp} % de compliance de patching")]},
        "iso27001": {"name": "ISO/IEC 27001:2022", "requirements": [
            _req("A.8 / A.5.9", "Gestão de ativos — inventário", _grade(managed_pct >= 95 and k["shadow_it"] == 0, managed_pct >= 70),
                 f"{managed_pct} % de ativos geridos", "Anexo A 2013 A.8; inventário de informação e ativos associados (A.5.9 na versão 2022)."),
            _req("A.8.8", "Gestão de vulnerabilidades técnicas", _grade(crit == 0 and sla_ok, crit <= 3),
                 f"{k['open_exposures']} abertas; {crit} críticas; {k['sla_breaches']} fora de prazo"),
            _req("A.8.8", "Exposição a vulnerabilidades exploradas ativamente", _grade(kev_ok, k["kev_exposures"] <= 3),
                 f"{k['kev_exposures']} exposições KEV em {k['kev_assets']} ativos"),
            _req("A.8.32", "Gestão de alterações (anéis, janelas, validação)", _grade(auto_patch and k["validation_failed"] == 0, auto_patch),
                 f"{k['campaigns_active']} campanhas ativas; {validated} validações")]},
        "dora": {"name": "DORA (Reg. UE 2022/2554)", "requirements": [
            _req("Art. 8.º", "Identificação de ativos e riscos TIC", _grade(inv_ok and k["total_assets"] > 0, k["total_assets"] > 0),
                 f"{k['total_assets']} ativos inventariados"),
            _req("Art. 9.º", "Proteção e prevenção — correções e patches", _grade(comp >= 95 and crit == 0, comp >= 80),
                 f"{comp} % compliance; MTTP {k['mttp_days'] if k['mttp_days'] is not None else 'n/d'} dias"),
            _req("Art. 9.º", "Controlos compensatórios quando não há patch", _grade(k["no_patch_open"] == 0 or k["controls_active"] > 0,
                                                                              k["controls_active"] > 0),
                 f"{k['no_patch_open']} sem patch; {k['controls_active']} controlos ativos"),
            _req("Art. 10.º", "Testes de resiliência (simulação de ataques)", _grade(k["simulations_blocked"] > 0, False),
                 f"{k['simulations_blocked']} simulações bloqueadas")]},
        "pci": {"name": "PCI-DSS v4 — Requisito 6", "requirements": [
            _req("6.3.1", "Vulnerabilidades identificadas e classificadas por risco", _grade(True),
                 f"Pontuação de risco dinâmica em {k['open_exposures']} exposições"),
            _req("6.3.3", "Patches críticos instalados em ≤ 1 mês", _grade(crit == 0 and k["sla_breaches"] == 0, crit <= 3),
                 f"{crit} críticas em aberto; MTTR {mttr if mttr is not None else 'n/d'} dias"),
            _req("6.3.3", "Restantes patches em prazo adequado", _grade(comp >= 95, comp >= 80), f"{comp} %")]},
        "cis": {"name": "CIS Controls v8 — Controlo 7", "requirements": [
            _req("7.1", "Processo de gestão de vulnerabilidades", _grade(True), "Fluxo Ativo → Exposição → Risco → Patch → Validação"),
            _req("7.2", "Processo de remediação baseado em risco", _grade(k["open_exposures"] == 0 or crit == 0, True),
                 f"{crit} críticas; SLA por categoria"),
            _req("7.3", "Gestão automatizada de patches do SO", _grade(comp >= 95, comp >= 70), f"{comp} %"),
            _req("7.4", "Gestão automatizada de patches de aplicações", _grade(comp >= 95, comp >= 70), f"{comp} %"),
            _req("7.7", "Remediar vulnerabilidades detetadas", _grade(k["open_exposures"] == 0, k["closed_period"] > 0),
                 f"{k['closed_period']} fechadas nos últimos 30 dias")]},
    }
    for fw in frameworks.values():
        reqs = fw["requirements"]
        pts = sum({"compliant": 1.0, "partial": 0.5, "gap": 0.0}[r["status"]] for r in reqs)
        fw["score"] = round(100 * pts / len(reqs))
        fw["gaps"] = sum(1 for r in reqs if r["status"] == "gap")
    return {"generated_at": utcnow().isoformat(), "tenant": tenant.slug, "frameworks": frameworks}
