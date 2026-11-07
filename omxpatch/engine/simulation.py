"""Módulo 14 — Threat Exposure Simulation (tipo BAS, **seguro e não destrutivo**).

Simula as fases de um ataque sem malware real nem exploração: o agente executa verificações benignas
(ficheiros canário num diretório temporário, ligações TCP a pares, leitura de configurações de proteção de
credenciais) e devolve, por passo, se a **defesa resistiu**. O resultado é *blocked* (todas resistiram),
*partial* ou *not_blocked*. Ao correr o mesmo cenário antes e depois da remediação, a plataforma demonstra se a
correção realmente bloqueia o ataque (``compare``).
"""
from __future__ import annotations

import json

from ..extensions import db
from ..models import (SIMULATIONS, Asset, ControlAction, Exposure, Simulation, Task, Tenant, utcnow)
from . import validation

SCENARIOS: dict[str, dict] = {
    "ransomware": {"steps": {
        "canary_encrypt": "A cifra de ficheiros canário foi bloqueada ou detetada",
        "shadow_copy_protection": "Cópias de segurança / shadow copies protegidas contra eliminação",
        "edr_service": "Serviço EDR/antivírus ativo",
        "controlled_folders": "Proteção de pastas/anti-tamper ativa"}},
    "lateral_movement": {"steps": {
        "smb_reach": "SMB (445) para pares bloqueado", "rdp_reach": "RDP (3389) para pares bloqueado",
        "winrm_reach": "WinRM (5985/5986) para pares bloqueado", "ssh_reach": "SSH (22) para pares bloqueado"}},
    "credential_theft": {"steps": {
        "lsa_protection": "Proteção LSA / PPL ativa (Windows)", "credential_guard": "Credential Guard ativo (Windows)",
        "wdigest_disabled": "WDigest sem credenciais em claro (Windows)",
        "shadow_permissions": "Ficheiro de hashes de passwords inacessível a não-root (Linux)",
        "ptrace_scope": "ptrace restrito (Linux)", "ssh_keys_perms": "Chaves SSH com permissões seguras (Linux/macOS)",
        "sip_enabled": "SIP ativo (macOS)", "disk_encryption": "Cifra de disco ativa (macOS/Windows/Linux)"}},
    "exploit_chain": {"steps": {
        "vuln_present": "A vulnerabilidade já não está presente (patch aplicado)",
        "service_reachable": "O serviço vulnerável não é alcançável pela rede",
        "control_in_place": "Existe controlo compensatório aplicado/verificado",
        "edr_visibility": "O EDR/antivírus está ativo para detetar a cadeia"}},
}
OUTCOME_RANK = {"error": -1, "not_blocked": 0, "partial": 1, "blocked": 2, "": -1}


def peers_of(asset: Asset, limit: int = 8) -> list[str]:
    if asset.ip.count(".") != 3:
        return []
    prefix = asset.ip.rsplit(".", 1)[0] + "."
    return [a.ip for a in Asset.query.filter(Asset.tenant_id == asset.tenant_id, Asset.id != asset.id,
                                             Asset.ip.like(prefix + "%")).limit(limit)]


def start(tenant: Tenant, asset: Asset, scenario: str, exposure: Exposure | None = None, phase: str = "baseline",
          baseline: Simulation | None = None) -> Simulation:
    if scenario not in SCENARIOS:
        raise ValueError("Cenário desconhecido")
    steps = [s for s in SCENARIOS[scenario]["steps"]]
    sim = Simulation(tenant_id=tenant.id, scenario=scenario, asset_id=asset.id, exposure_id=exposure.id if exposure else None,
                     cve_id=exposure.cve_id if exposure else "", phase=phase,
                     baseline_id=baseline.id if baseline else None, status="queued")
    db.session.add(sim)
    db.session.flush()
    mode = "agent"
    if asset.agent is None:
        sim.status, sim.outcome = "failed", "error"
        sim.steps = json.dumps([{"id": "agent", "label": "A simulação exige o agente instalado no ativo",
                                 "passed": None, "detail": "Sem agente"}])
        return sim
    t = Task(tenant_id=tenant.id, type="bas", asset_id=asset.id, mode=mode, status="queued", exposure_id=exposure.id if exposure else None,
             payload=json.dumps({"simulation_id": sim.id, "scenario": scenario, "steps": steps, "peers": peers_of(asset),
                                 "port": exposure.port if exposure else None, "cve": sim.cve_id}))
    db.session.add(t)
    db.session.flush()
    sim.task_id = t.id
    return sim


def _server_steps(sim: Simulation) -> list[dict]:
    """Passos do cenário *exploit_chain* decididos com os dados do servidor."""
    out = []
    ex = db.session.get(Exposure, sim.exposure_id) if sim.exposure_id else None
    if ex is not None:
        asset = ex.asset
        out.append({"id": "vuln_present", "passed": not validation.still_vulnerable(asset, ex),
                    "detail": f"{ex.cve_id} " + ("não detetado" if not validation.still_vulnerable(asset, ex) else "ainda presente")})
        has_control = ControlAction.query.filter(ControlAction.exposure_id == ex.id,
                                                 ControlAction.status.in_(("applied", "verified"))).count() > 0
        out.append({"id": "control_in_place", "passed": has_control,
                    "detail": "controlo compensatório ativo" if has_control else "sem controlo compensatório"})
    return out


def on_report(task: Task, report: dict) -> None:
    sim = db.session.get(Simulation, task.payload_data.get("simulation_id") or 0)
    if sim is None:
        return
    labels = SCENARIOS[sim.scenario]["steps"]
    steps = {s.get("id"): s for s in report.get("steps", []) if isinstance(s, dict)}
    if sim.scenario == "exploit_chain":
        for s in _server_steps(sim):
            steps[s["id"]] = s
    rows = []
    for sid, label in labels.items():
        s = steps.get(sid)
        if s is None or s.get("passed") is None:
            if s is not None or sim.scenario != "exploit_chain":
                rows.append({"id": sid, "label": label, "passed": None, "detail": (s or {}).get("detail", "não aplicável")})
            continue
        rows.append({"id": sid, "label": label, "passed": bool(s["passed"]), "detail": s.get("detail", "")})
    applicable = [r for r in rows if r["passed"] is not None]
    held = sum(1 for r in applicable if r["passed"])
    if report.get("status") == "failed" and not applicable:
        outcome = "error"
    elif not applicable:
        outcome = "error"
    elif held == len(applicable):
        outcome = "blocked"
    elif held == 0:
        outcome = "not_blocked"
    else:
        outcome = "partial"
    sim.steps, sim.outcome, sim.status, sim.finished_at = json.dumps(rows), outcome, "done", utcnow()


def compare(sim: Simulation) -> dict | None:
    """Resultado antes/depois da remediação. ``improved`` = a correção reduziu a exposição ao ataque."""
    if not sim.baseline_id:
        return None
    base = db.session.get(Simulation, sim.baseline_id)
    if base is None:
        return None
    b, a = OUTCOME_RANK.get(base.outcome, -1), OUTCOME_RANK.get(sim.outcome, -1)
    return {"before": base.outcome, "after": sim.outcome, "improved": a > b, "validated": sim.outcome == "blocked",
            "verdict": ("Remediação validada: o ataque simulado é bloqueado." if sim.outcome == "blocked" else
                        "Melhoria parcial: ainda há passos do ataque que não são bloqueados." if a > b else
                        "A remediação não alterou o resultado do ataque simulado.")}


def validate_after_fix(tenant: Tenant, ex: Exposure, scenario: str = "exploit_chain") -> Simulation:
    base = (Simulation.query.filter_by(tenant_id=tenant.id, asset_id=ex.asset_id, scenario=scenario, phase="baseline")
            .order_by(Simulation.id.desc()).first())
    return start(tenant, ex.asset, scenario, ex, phase="after_fix", baseline=base)


def stats(tenant_id: int) -> dict:
    q = Simulation.query.filter_by(tenant_id=tenant_id, status="done")
    return {"done": q.count(), **{o: q.filter_by(outcome=o).count() for o in ("blocked", "partial", "not_blocked")}}


__all__ = ["SIMULATIONS"]
