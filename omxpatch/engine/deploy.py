"""Módulo 6 — Automated Patch Management: campanhas, janelas de manutenção, Wake-on-LAN, controlo de largura de banda.

Máquina de estados da campanha (``advance``, chamada pelo worker):

    rascunho/agendada → em execução → [Ring 0 → avaliação → Ring 1 → … → Ring 4] → concluída
                                          ↘ (critérios falham) em pausa

Cada ativo em âmbito recebe uma ``Task`` de tipo *patch*, executada pelo agente (*pull*) ou, sem agente,
pelo Ansible. Uma tarefa só segue para o agente dentro de uma janela de manutenção (salvo emergência).
"""
from __future__ import annotations

import json
import socket
from datetime import datetime, timedelta

from flask import current_app

from ..extensions import db
from ..models import (Agent, Asset, Campaign, Exposure, MaintenanceWindow, Patch, Task, Tenant, TASK_FINAL, jloads,
                      utcnow)
from . import patches as patch_mod
from . import rings


class PatchBlocked(ValueError):
    pass


# --------------------------------------------------------------------------- âmbito


def resolve_scope(tenant: Tenant, scope: dict, patch: Patch | None = None) -> list[Asset]:
    q = Asset.query.filter_by(tenant_id=tenant.id)
    ids: set[int] | None = None
    if scope.get("asset_ids"):
        ids = {int(i) for i in scope["asset_ids"]}
    if scope.get("cve_id") or (scope.get("exposure_ids")):
        eq = Exposure.query.filter(Exposure.tenant_id == tenant.id, Exposure.status.in_(("open", "mitigated", "patching")))
        if scope.get("cve_id"):
            eq = eq.filter(Exposure.cve_id == scope["cve_id"])
        if scope.get("exposure_ids"):
            eq = eq.filter(Exposure.id.in_([int(i) for i in scope["exposure_ids"]]))
        exp_ids = {e.asset_id for e in eq}
        ids = exp_ids if ids is None else ids & exp_ids
    if ids is not None:
        q = q.filter(Asset.id.in_(ids))
    if scope.get("os_family"):
        q = q.filter(Asset.os_family == scope["os_family"])
    elif patch is not None and patch.os_family:
        q = q.filter(Asset.os_family == patch.os_family)
    assets = q.all()
    if scope.get("tags"):
        want = {t.lower() for t in scope["tags"]}
        assets = [a for a in assets if want & {t.lower() for t in a.tag_list}]
    return assets


# --------------------------------------------------------------------------- criação


def create_campaign(tenant: Tenant, patch: Patch, name: str, scope: dict, user=None, *, use_rings: bool = True,
                    start_at: datetime | None = None, use_wol: bool = False, bandwidth_kbps: int = 0,
                    reboot_policy: str = "if_needed", emergency: bool = False, origin: str = "manual",
                    run_id: int | None = None, force: bool = False, auto_promote: bool = True,
                    respect_windows: bool = True, require_preflight: bool = False) -> Campaign:
    if patch.tenant_id != tenant.id:
        raise PatchBlocked("Patch de outra organização")
    if patch.status != "approved":
        raise PatchBlocked("Aprove o patch no repositório antes de criar a campanha.")
    intel = patch_mod.intelligence(patch)
    if intel["level"] == "hold" and not force:
        raise PatchBlocked("Patch Intelligence recomenda não aplicar: " + " ".join(intel["reasons"]))
    assets = resolve_scope(tenant, scope, patch)
    if not assets:
        raise PatchBlocked("Nenhum ativo em âmbito para este patch.")
    rings.ensure_policies(tenant)
    c = Campaign(tenant_id=tenant.id, name=name[:200], patch_id=patch.id, scope=json.dumps(scope), status="scheduled",
                 use_rings=use_rings, start_at=start_at or utcnow(), use_wol=use_wol,
                 bandwidth_kbps=max(0, int(bandwidth_kbps or current_app.config["BANDWIDTH_DEFAULT_KBPS"] or 0)),
                 reboot_policy=reboot_policy if reboot_policy in ("none", "if_needed", "force") else "if_needed",
                 emergency=emergency, origin=origin, run_id=run_id, auto_promote=auto_promote,
                 respect_windows=respect_windows, require_preflight=require_preflight, created_by_id=getattr(user, "id", None))
    db.session.add(c)
    db.session.flush()
    return c


def ring_sequence(campaign: Campaign, tenant: Tenant) -> list[int]:
    if not campaign.use_rings:
        return [4]
    scope = campaign.scope_data
    present = sorted({a.ring for a in resolve_scope(tenant, scope, campaign.patch)})
    return present


# --------------------------------------------------------------------------- janelas e Wake-on-LAN


def _local_now(tz: str, now: datetime) -> datetime:
    if tz:
        try:
            from zoneinfo import ZoneInfo
            from datetime import timezone
            return now.replace(tzinfo=timezone.utc).astimezone(ZoneInfo(tz)).replace(tzinfo=None)
        except Exception:  # noqa: BLE001 - fuso inválido: usa UTC
            return now
    return now + (datetime.now().astimezone().utcoffset() or timedelta(0))   # hora local do servidor


def _in(w: MaintenanceWindow, now: datetime) -> bool:
    local = _local_now(w.timezone, now)
    try:
        hh, mm = (int(x) for x in w.start_time.split(":"))
    except ValueError:
        return False
    days = {int(d) for d in (w.weekdays or "").split(",") if d.strip().isdigit()}
    for back in (0, 1):                              # janela que começou ontem e atravessa a meia-noite
        day = local - timedelta(days=back)
        if day.weekday() in days:
            start = day.replace(hour=hh, minute=mm, second=0, microsecond=0)
            if start <= local < start + timedelta(minutes=w.duration_minutes):
                return True
    return False


def window_allows(tenant_id: int, asset: Asset, now: datetime, emergency: bool = False) -> tuple[bool, str]:
    windows = [w for w in MaintenanceWindow.query.filter_by(tenant_id=tenant_id, enabled=True)
               if (not w.group or w.group == asset.maintenance_group)
               and (not w.rings or str(asset.ring) in w.rings.split(","))]
    if not windows:
        return True, ""
    if any(_in(w, now) for w in windows):
        return True, ""
    if emergency and any(w.allow_emergency for w in windows):
        return True, "emergência"
    return False, "Fora das janelas de manutenção: " + ", ".join(w.name for w in windows)


def magic_packet(mac: str) -> bytes:
    raw = bytes.fromhex(mac.replace(":", "").replace("-", "").strip())
    if len(raw) != 6:
        raise ValueError("MAC inválido")
    return b"\xff" * 6 + raw * 16


def send_wol(mac: str, broadcast: str = "255.255.255.255", port: int = 9) -> None:
    pkt = magic_packet(mac)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(pkt, (broadcast, port))


def is_online(asset: Asset, now: datetime | None = None) -> bool:
    now = now or utcnow()
    ag = asset.agent
    if ag is not None and ag.last_seen:
        return now - ag.last_seen < timedelta(minutes=int(current_app.config["AGENT_OFFLINE_MINUTES"]))
    return asset.connection == "ansible"            # sem agente: assume-se alcançável


def wake(asset: Asset, tenant: Tenant) -> str:
    """Acorda o ativo: através de um agente online na mesma sub-rede (relay) ou do próprio servidor."""
    if not asset.mac:
        return "sem MAC registado"
    subnet = asset.ip.rsplit(".", 1)[0] if asset.ip.count(".") == 3 else None
    if subnet:
        for ag in Agent.query.filter_by(tenant_id=tenant.id, revoked=False):
            peer = ag.asset
            if peer and peer.id != asset.id and peer.ip.startswith(subnet + ".") and is_online(peer):
                db.session.add(Task(tenant_id=tenant.id, type="wake", asset_id=peer.id, status="queued", mode="agent",
                                    payload=json.dumps({"mac": asset.mac, "broadcast": subnet + ".255"})))
                return f"relay via {peer.name}"
    try:
        send_wol(asset.mac)
        return "enviado pelo servidor"
    except OSError as exc:
        return f"falhou: {exc}"


# --------------------------------------------------------------------------- tarefas


def patch_payload(c: Campaign, patch: Patch, asset: Asset) -> dict:
    return {"patch_id": patch.id, "uid": patch.patch_uid, "title": patch.title, "installer": patch.installer,
            "package": patch.package_name, "version_fixed": patch.version_fixed, "silent_args": patch.silent_args,
            "sha256": patch.sha256, "has_file": bool(patch.local_file), "download_url": patch.download_url if not patch.local_file else "",
            "reboot_policy": c.reboot_policy, "bandwidth_kbps": c.bandwidth_kbps, "cves": patch.cve_list,
            "emergency": c.emergency, "os_family": asset.os_family, "product": patch.product, "size_bytes": int(patch.size_bytes or 0),
            "reboot_required": bool(patch.reboot_required)}


def create_ring_tasks(c: Campaign, tenant: Tenant, ring: int) -> int:
    patch = c.patch
    assets = [a for a in resolve_scope(tenant, c.scope_data, patch) if (a.ring == ring or not c.use_rings)]
    n = 0
    for a in assets:
        if Task.query.filter_by(campaign_id=c.id, asset_id=a.id, type="patch").first():
            continue
        mode = "ansible" if (a.connection == "ansible" and a.agent is None) else "agent"
        t = Task(tenant_id=tenant.id, type="patch", asset_id=a.id, campaign_id=c.id, patch_id=patch.id, ring=ring,
                 mode=mode, status="pending", payload=json.dumps(patch_payload(c, patch, a)))
        db.session.add(t)
        n += 1
        for ex in Exposure.query.filter(Exposure.tenant_id == tenant.id, Exposure.asset_id == a.id,
                                        Exposure.cve_id.in_(patch.cve_list or ["-"]),
                                        Exposure.status.in_(("open", "mitigated"))):
            ex.status = "patching"
    return n


def _preflight_gate(c, tenant, t) -> str:
    from . import preflight
    return preflight.gate(c, tenant, t)


def release_tasks(c: Campaign, tenant: Tenant, now: datetime) -> int:
    """Pending → queued (ou à espera da janela / do Wake-on-LAN)."""
    n = 0
    for t in Task.query.filter(Task.campaign_id == c.id, Task.status.in_(("pending", "waiting_window", "waking"))):
        if t.not_before and t.not_before > now:
            continue
        if c.require_preflight and t.type == "patch":
            g = _preflight_gate(c, tenant, t)
            if g == "wait":
                continue
            if g == "skip":
                t.status, t.finished_at = "skipped", now
                continue
        ok, why = (True, "") if not c.respect_windows else window_allows(tenant.id, t.asset, now, c.emergency)
        if not ok:
            t.status, t.output = "waiting_window", why
            continue
        if c.use_wol and not is_online(t.asset, now):
            if t.status != "waking":
                t.status, t.output = "waking", "Wake-on-LAN: " + wake(t.asset, tenant)
                t.not_before = now + timedelta(minutes=3)
                continue
        t.status = "queued"
        n += 1
    return n


def advance(c: Campaign, tenant: Tenant, now: datetime | None = None) -> str:
    """Avança a campanha um passo. Devolve o estado resultante."""
    now = now or utcnow()
    if c.status in ("completed", "cancelled", "failed", "draft", "paused"):
        return c.status
    state = c.rings_state
    if c.status == "scheduled":
        if c.start_at and c.start_at > now:
            return c.status
        c.status, c.started_at = "running", now
        seq = ring_sequence(c, tenant)
        if not seq:
            c.status, c.finished_at = "completed", now
            return c.status
        c.current_ring = seq[0]
    seq = ring_sequence(c, tenant)
    ring = c.current_ring
    key = str(ring)
    if key not in state:
        create_ring_tasks(c, tenant, ring)
        state[key] = {"state": "active", "since": now.isoformat()}
    release_tasks(c, tenant, now)
    if c.use_rings:
        ev = rings.evaluate(c, tenant, ring, now, final=not [r for r in seq if r > ring])
        state[key].update({"metrics": {k: v for k, v in ev["metrics"].items() if k != "last_finished"},
                           "reasons": ev["reasons"], "decision": ev["decision"]})
        decision = ev["decision"]
    else:
        m = rings.metrics(c, ring)
        decision = "wait" if m["pending"] else "promote"
        state[key]["metrics"] = {k: v for k, v in m.items() if k != "last_finished"}
    if decision == "hold":
        c.status = "paused"
        state[key]["state"] = "hold"
    elif decision == "promote":
        state[key]["state"] = "done"
        later = [r for r in seq if r > ring]
        if later:
            c.current_ring = later[0]
        else:
            c.status, c.finished_at = "completed", now
    c.ring_state = json.dumps(state)
    if decision == "promote" and c.status == "running":
        return advance(c, tenant, now)           # anel seguinte: cria logo as tarefas (no máx. 5 níveis)
    return c.status


def resume(c: Campaign, tenant: Tenant, override: bool = False) -> None:
    """Retoma uma campanha em pausa. Com ``override`` promove mesmo sem cumprir os critérios (decisão humana)."""
    state = c.rings_state
    key = str(c.current_ring)
    if c.status == "paused":
        c.status = "running"
        if override and key in state:
            state[key]["state"] = "done"
            state[key]["override"] = True
            seq = ring_sequence(c, tenant)
            later = [r for r in seq if r > c.current_ring]
            if later:
                c.current_ring = later[0]
            else:
                c.status, c.finished_at = "completed", utcnow()
        elif key in state:
            state[key]["state"] = "active"
        c.ring_state = json.dumps(state)


def cancel(c: Campaign) -> None:
    c.status, c.finished_at = "cancelled", utcnow()
    for t in Task.query.filter(Task.campaign_id == c.id, Task.status.notin_(TASK_FINAL)):
        if t.status != "running":
            t.status = "cancelled"
    for ex in Exposure.query.filter_by(tenant_id=c.tenant_id, status="patching"):
        if any(cv in c.patch.cve_list for cv in [ex.cve_id]) and not Task.query.filter(
                Task.tenant_id == c.tenant_id, Task.asset_id == ex.asset_id, Task.type == "patch",
                Task.status.notin_(TASK_FINAL)).first():
            ex.status = "open"


# --------------------------------------------------------------------------- agentes


def poll(agent: Agent, limit: int = 3) -> list[dict]:
    """Tarefas em fila para o ativo do agente; passam a *enviada*."""
    if agent.asset_id is None:
        return []
    out = []
    now = utcnow()
    tasks = Task.query.filter(Task.tenant_id == agent.tenant_id, Task.asset_id == agent.asset_id, Task.mode == "agent",
                              Task.status == "queued").order_by(Task.id).limit(limit).all()
    for t in tasks:
        t.status, t.sent_at, t.attempts = "sent", now, (t.attempts or 0) + 1
        out.append({"id": t.id, "type": t.type, "payload": t.payload_data})
    return out


def requeue_stale(tenant_id: int | None = None) -> int:
    """Tarefas enviadas/em execução que o agente nunca concluiu voltam à fila (ou falham ao fim de 3 tentativas)."""
    limit = utcnow() - timedelta(minutes=int(current_app.config["AGENT_TASK_TIMEOUT_MINUTES"]))
    n = 0
    q = Task.query.filter(Task.status.in_(("sent", "running")), Task.sent_at < limit)
    if tenant_id:
        q = q.filter(Task.tenant_id == tenant_id)
    for t in q:
        if (t.attempts or 0) >= 3:
            t.status, t.finished_at, t.output = "failed", utcnow(), (t.output or "") + "\nSem resposta do agente."
        else:
            t.status = "queued"
        n += 1
    return n


def complete_task(task: Task, report: dict) -> Task:
    """Regista o resultado enviado pelo agente (ou devolvido pelo Ansible) e encadeia o fluxo seguinte."""
    status = report.get("status", "failed")
    if status not in ("succeeded", "failed", "rolled_back"):
        status = "failed"
    now = utcnow()
    task.status, task.finished_at = status, now
    task.output = str(report.get("output", ""))[-60000:]
    task.result = json.dumps({k: v for k, v in report.items() if k not in ("output", "software", "hotfixes")},
                             default=str)
    task.started_at = task.started_at or task.sent_at or now
    tenant = db.session.get(Tenant, task.tenant_id)
    asset = task.asset
    if report.get("reboot_pending") is not None:
        asset.reboot_pending = bool(report["reboot_pending"])
    if task.type == "patch" and task.patch_id:
        duration = int(report.get("duration_s") or (now - task.started_at).total_seconds())
        patch_mod.record_telemetry(task.tenant_id, task.patch_id, task.asset_id,
                                   "success" if status == "succeeded" else status, task_id=task.id, ring=task.ring, crashed=bool(report.get("crashed")),
                                   ux_score=report.get("ux_score"), duration_s=duration)
        patch = task.patch
        exps = Exposure.query.filter(Exposure.tenant_id == task.tenant_id, Exposure.asset_id == task.asset_id,
                                     Exposure.cve_id.in_(patch.cve_list or ["-"]),
                                     Exposure.status.in_(("open", "mitigated", "patching")))
        if status == "succeeded":
            from . import validation
            for ex in exps:
                ex.status, ex.patched_at = "remediated", now
                validation.schedule(ex, tenant, source_task=task)
        elif status == "failed" and (task.attempts or 0) < 2:
            task.status, task.not_before = "pending", now + timedelta(minutes=30)
        else:
            for ex in exps:
                if ex.status == "patching":
                    ex.status = "open"
    elif task.type == "validate":
        from . import validation
        validation.on_report(task, report)
    elif task.type == "simulate":
        from . import preflight
        preflight.on_report(task, report)
    elif task.type == "bas":
        from . import simulation
        simulation.on_report(task, report)
    elif task.type == "control":
        from . import controls
        controls.on_report(task, report)
    elif task.type == "inventory":
        from . import inventory
        inventory.ingest_inventory(tenant, asset, report)
    return task


def campaign_summary(c: Campaign) -> dict:
    tasks = Task.query.filter_by(campaign_id=c.id, type="patch").all()
    by: dict[str, int] = {}
    for t in tasks:
        by[t.status] = by.get(t.status, 0) + 1
    done = by.get("succeeded", 0)
    return {"total": len(tasks), "by_status": by, "succeeded": done,
            "progress": int(100 * sum(by.get(s, 0) for s in TASK_FINAL) / len(tasks)) if tasks else 0}


__all__ = ["jloads"]
