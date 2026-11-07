"""Módulo 9 — AI Remediation Engine.

Pergunta típica: *«Como reduzir o risco para menos de 20 pontos?»* → plano ordenado, por exemplo:

    1. Aplicar patch KB5031234 · 2. Criar regra Defender · 3. Fechar porta TCP/8443 · 4. Atualizar Apache
    Redução prevista: 92 → 14

O **planeador é determinístico** (simulação sobre os mesmos fatores do Módulo 4, com minimização de esforço) e é
ele que garante o resultado previsto; a IA generativa (opcional, ``[ai]``) só interpreta a pergunta em linguagem
natural e redige a explicação do plano — nunca inventa ações nem pontuações.

Risco do ativo = probabilidade combinada das suas exposições abertas: 1 − Π(1 − sᵢ/100).
"""
from __future__ import annotations

import json
import logging
import re

import requests
from flask import current_app

from ..extensions import db
from ..models import CONTROL_ACTIONS, AiPlan, Asset, Campaign, ControlAction, CveIntel, Exposure, Patch, Tenant
from ..security import check_outbound_url
from . import controls, risk

log = logging.getLogger("omxpatch.advisor")
EFFORT = {"patch": 3, "upgrade": 4, "close_port": 2, "control": 1}
CONTROL_LABEL = {"edr_detection": "Criar regra de deteção no EDR (Defender / SentinelOne / CrowdStrike)",
                 "edr_block": "Criar bloqueio no EDR", "siem_rule": "Criar regra no SIEM",
                 "siem_correlation": "Criar correlação no SIEM", "virtual_patch": "Ativar virtual patch no WAF",
                 "force_mfa": "Forçar MFA no acesso afetado", "block_ioc": "Bloquear IOC na firewall",
                 "disable_account": "Desativar conta comprometida", "block_country": "Bloquear país na firewall"}


def parse_target(question: str, default: int = 20) -> int:
    m = re.search(r"(?:menos de|abaixo de|inferior a|below|under|<)\s*(\d{1,3})", question or "", re.I) \
        or re.search(r"\b(\d{1,3})\s*(?:pontos|points|pts)", question or "", re.I)
    if m:
        return max(0, min(99, int(m.group(1))))
    return default


class _State:
    """Estado simulado: pontos por fator de cada exposição aberta."""

    def __init__(self, exposures: list[Exposure]):
        self.pts: dict[int, dict[str, float]] = {}
        for ex in exposures:
            f = {x["key"]: float(x["points"]) for x in ex.factor_list}
            if not f:
                f = {"cvss": ex.risk_score * 0.4, "evidence": ex.risk_score * 0.3, "internet": ex.risk_score * 0.3}
            self.pts[ex.id] = f
        self.removed: set[int] = set()

    def clone(self) -> "_State":
        n = _State([])
        n.pts = {k: dict(v) for k, v in self.pts.items()}
        n.removed = set(self.removed)
        return n

    def score(self) -> int:
        return risk.asset_risk([int(round(min(100, sum(v.values())))) for k, v in self.pts.items() if k not in self.removed])


class Action:
    def __init__(self, kind: str, label: str, detail: str, ref: dict, apply):
        self.kind, self.label, self.detail, self.ref, self.apply = kind, label, detail, ref, apply
        self.effort = EFFORT[kind]


def _mult(state: _State, exposure_ids: list[int], effects: dict[str, float]) -> None:
    for i in exposure_ids:
        for factor, m in effects.items():
            if factor in state.pts.get(i, {}):
                state.pts[i][factor] *= m


def candidate_actions(tenant: Tenant, exposures: list[Exposure]) -> list[Action]:
    actions: list[Action] = []
    by_patch: dict[int, list[Exposure]] = {}
    for ex in exposures:
        if ex.patch_id and ex.patch_available:
            by_patch.setdefault(ex.patch_id, []).append(ex)
    for pid, exs in by_patch.items():
        p = exs[0].patch
        ids = [e.id for e in exs]
        kind = "patch" if p.installer in ("wua", "apt", "dnf", "zypper", "softwareupdate", "msi", "pkg", "exe") and not p.patch_uid.startswith("upd:") else "upgrade"
        label = (f"Aplicar patch {p.patch_uid}" if kind == "patch" else
                 f"Atualizar {p.product or exs[0].software_name} para {p.version_fixed or 'a versão corrigida'}")
        actions.append(Action(kind, label, f"Corrige {', '.join(sorted({e.cve_id for e in exs}))} em {len(exs)} exposição(ões)",
                              {"patch_id": pid, "exposure_ids": ids},
                              lambda st, ids=ids: st.removed.update(ids)))
    for ex in exposures:
        if ex.fixed_version and not ex.patch_available:
            actions.append(Action("upgrade", f"Atualizar {ex.software_name or 'software'} para {ex.fixed_version}",
                                  f"Versão instalada {ex.installed_version or 'n/d'} → {ex.fixed_version}",
                                  {"exposure_ids": [ex.id], "software": ex.software_name},
                                  lambda st, i=ex.id: st.removed.add(i)))
    ports: dict[int, list[int]] = {}
    for ex in exposures:
        if ex.port:
            ports.setdefault(ex.port, []).append(ex.id)
    for port, ids in ports.items():
        actions.append(Action("close_port", f"Fechar porta TCP/{port}", f"Bloqueia o acesso ao serviço afetado ({len(ids)} exposição(ões))",
                              {"port": port, "exposure_ids": ids, "action": "block_port"},
                              lambda st, ids=ids: _mult(st, ids, risk.CONTROL_EFFECT["block_port"])))
    seen: set[tuple] = set()
    for ex in exposures:
        for action, params in controls.suggest_specs(ex):
            if action == "block_port":
                continue
            key = (action, json.dumps(params, sort_keys=True), ex.id)
            if key in seen:
                continue
            seen.add(key)
            actions.append(Action("control", f"{CONTROL_LABEL.get(action, CONTROL_ACTIONS[action][1])} ({ex.cve_id})",
                                  f"Mitigação enquanto o patch não é aplicado em {ex.asset.name}",
                                  {"action": action, "params": params, "exposure_ids": [ex.id], "cve": ex.cve_id},
                                  lambda st, i=ex.id, a=action: _mult(st, [i], risk.CONTROL_EFFECT.get(a, {}))))
    return actions


def plan(tenant: Tenant, exposures: list[Exposure], target: int = 20) -> dict:
    """Plano de esforço mínimo para levar o risco abaixo de ``target`` (guloso + poda de passos redundantes)."""
    exposures = [e for e in exposures if e.status in ("open", "mitigated", "patching")]
    base = _State(exposures)
    before = base.score()
    actions = candidate_actions(tenant, exposures)
    chosen: list[Action] = []
    state = base.clone()
    pool = list(actions)
    while state.score() > target and pool:
        cur = state.score()
        best, best_val = None, 0.0
        for a in pool:
            s2 = state.clone()
            a.apply(s2)
            gain = cur - s2.score()
            if gain <= 0:
                continue
            val = gain / a.effort
            if val > best_val or (val == best_val and best is not None and gain > cur - _applied(state, best).score()):
                best, best_val = a, val
        if best is None:
            break
        best.apply(state)
        chosen.append(best)
        pool.remove(best)
    # poda: remove passos que deixaram de ser necessários para atingir o objetivo
    if state.score() <= target:
        for a in list(chosen):
            trial = base.clone()
            for b in chosen:
                if b is not a:
                    b.apply(trial)
            if trial.score() <= target:
                chosen.remove(a)
    final = base.clone()
    steps = []
    prev = before
    for i, a in enumerate(sorted(chosen, key=lambda x: x.effort), 1):
        a.apply(final)
        now = final.score()
        steps.append({"n": i, "kind": a.kind, "label": a.label, "detail": a.detail, "ref": a.ref,
                      "reduction": prev - now, "projected": now, "effort": a.effort})
        prev = now
    after = final.score()
    return {"before": before, "after": after, "target": target, "reached": after <= target, "steps": steps,
            "exposures": len(exposures)}


def _applied(state: _State, a: Action) -> _State:
    s = state.clone()
    a.apply(s)
    return s


# --------------------------------------------------------------------------- narrativa (IA opcional)


def narrative_fallback(asset_name: str, p: dict) -> str:
    if not p["steps"]:
        return (f"{asset_name}: o risco atual é {p['before']} e já está abaixo do objetivo ({p['target']})."
                if p["before"] <= p["target"] else f"{asset_name}: não foram encontradas ações que reduzam o risco.")
    lines = [f"Para reduzir o risco de {asset_name} de {p['before']} para {p['after']} (objetivo: abaixo de {p['target']}):"]
    lines += [f"{s['n']}. {s['label']} → risco previsto {s['projected']}" for s in p["steps"]]
    if not p["reached"]:
        lines.append("Atenção: com as ações disponíveis não é possível atingir o objetivo; reveja a aceitação de risco ou "
                     "isole o ativo.")
    return "\n".join(lines)


def narrate(question: str, asset_name: str, p: dict) -> str:
    cfg = current_app.config
    fallback = narrative_fallback(asset_name, p)
    if not (cfg["AI_ENABLED"] and cfg["AI_API_KEY"]):
        return fallback
    try:
        check_outbound_url(cfg["AI_URL"], require_https=True)
        body = {"model": cfg["AI_MODEL"], "max_tokens": 700,
                "system": ("És o assistente de remediação do OMXPatch. Explica em português europeu, de forma curta e "
                           "objetiva, o plano fornecido em JSON. Usa APENAS as ações e pontuações do JSON; não inventes "
                           "ações, CVE nem números."),
                "messages": [{"role": "user", "content": f"Pergunta: {question}\nAtivo: {asset_name}\n"
                                                         f"Plano: {json.dumps(p, ensure_ascii=False, default=str)[:6000]}"}]}
        r = requests.post(cfg["AI_URL"], json=body, timeout=int(cfg["AI_TIMEOUT"]),
                          headers={"x-api-key": cfg["AI_API_KEY"], "anthropic-version": "2023-06-01",
                                   "content-type": "application/json"})
        r.raise_for_status()
        text = "".join(b.get("text", "") for b in r.json().get("content", []) if b.get("type") == "text").strip()
        return text or fallback
    except (requests.RequestException, ValueError, KeyError) as exc:
        log.warning("IA indisponível (%s); a usar a narrativa determinística", exc)
        return fallback


# --------------------------------------------------------------------------- API do módulo


def ask(tenant: Tenant, question: str, asset: Asset | None = None, user=None, target: int | None = None) -> AiPlan:
    target = target if target is not None else parse_target(question)
    if asset is None:
        top = (db.session.query(Exposure.asset_id, db.func.max(Exposure.risk_score))
               .filter(Exposure.tenant_id == tenant.id, Exposure.status.in_(("open", "mitigated", "patching")))
               .group_by(Exposure.asset_id).order_by(db.func.max(Exposure.risk_score).desc()).first())
        asset = db.session.get(Asset, top[0]) if top else None
    exposures = (Exposure.query.filter(Exposure.tenant_id == tenant.id, Exposure.asset_id == asset.id).all()
                 if asset else [])
    p = plan(tenant, exposures, target)
    row = AiPlan(tenant_id=tenant.id, asset_id=asset.id if asset else None, question=question[:500],
                 target_score=target, before_score=p["before"], after_score=p["after"], plan=json.dumps(p["steps"]),
                 narrative=narrate(question, asset.name if asset else "—", p), created_by_id=getattr(user, "id", None))
    db.session.add(row)
    db.session.flush()
    return row


def apply_plan(tenant: Tenant, row: AiPlan, user=None) -> dict:
    """Converte o plano em ações: controlos aprovados e patches indicados (a campanha exige patch aprovado)."""
    created = {"controls": 0, "patches_to_approve": [], "campaigns": 0}
    for step in row.steps:
        ref = step.get("ref", {})
        exs = [db.session.get(Exposure, i) for i in ref.get("exposure_ids", [])]
        exs = [e for e in exs if e]
        if step["kind"] in ("patch", "upgrade") and ref.get("patch_id"):
            p = db.session.get(Patch, ref["patch_id"])
            if p and p.tenant_id == tenant.id:
                if p.status == "approved":
                    from . import deploy
                    try:
                        deploy.create_campaign(tenant, p, f"Plano IA #{row.id}: {p.patch_uid}",
                                               {"asset_ids": [row.asset_id], "cve_id": None} if row.asset_id else {}, user)
                        created["campaigns"] += 1
                    except deploy.PatchBlocked as exc:
                        created["patches_to_approve"].append(f"{p.patch_uid}: {exc}")
                else:
                    created["patches_to_approve"].append(p.patch_uid)
        elif step["kind"] in ("close_port", "control") and exs:
            action = ref.get("action", "block_port")
            params = ref.get("params") or ({"port": ref["port"], "proto": "tcp", "direction": "in"} if ref.get("port") else {})
            c = controls.make(tenant, exs[0], action, params, user=user)
            controls.approve(c, user)
            created["controls"] += 1
    row.status = "applied"
    return created
