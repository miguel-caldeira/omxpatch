"""API dos agentes (Windows / Linux / macOS): registo, contacto (poll), inventário, resultados e pacotes.

Autenticação por chave do agente (Bearer), guardada com hash; sem cookies nem CSRF. Os agentes só *puxam* trabalho
(sem portas de entrada nos postos) e só descarregam pacotes referenciados por tarefas do seu próprio ativo.
"""
from __future__ import annotations

import hashlib
import json
import secrets

from flask import Blueprint, abort, current_app, g, jsonify, request, send_file

from ..engine import agentops, correlate, deploy, inventory, patches
from .. import ratelimit
from ..extensions import db
from ..models import Agent, EnrollmentToken, Task, Tenant, utcnow

bp = Blueprint("agent", __name__, url_prefix="/agent/v1")
AGENT_VERSION_MIN = "1.0.0"


def agent_urls(cfg) -> list:
    """Endereços (por ordem de preferência) que os agentes devem usar: AGENT_SERVER_URLS, ou o URL base configurado."""
    urls = [u.strip().rstrip("/") for u in str(cfg.get("AGENT_SERVER_URLS") or "").split(",") if u.strip()]
    return urls or [str(cfg["AGENT_BASE_URL"]).rstrip("/")]


_bundle_cache: dict = {}


def trust_block(agent=None) -> dict:
    """Confiança publicada aos agentes: impressões digitais (atual + seguinte), chaves de assinatura e oferta de atualização."""
    from .. import signing, tls
    cfg = current_app.config
    out = {"task_keys": signing.public_keys(cfg), "pins": tls.agent_pins(cfg) if cfg["TLS_ENABLED"] else []}
    if agent is not None:
        out["agent_id"] = agent.id
    if cfg.get("AGENT_AUTO_UPDATE", True):
        data, digest = bundle_bytes()
        import omxpatch_agent
        key = (omxpatch_agent.__version__, digest, out["task_keys"][0])      # a rotação da chave invalida a assinatura em cache
        if _bundle_cache.get("key") != key:
            _bundle_cache.update(key=key, sig=signing.sign(cfg, "bundle", {"version": omxpatch_agent.__version__, "sha256": digest}))
        out.update(agent_version=omxpatch_agent.__version__, bundle_sha256=digest, bundle_sig=_bundle_cache["sig"])
    return out


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _too_many(retry: int):
    r = jsonify({"error": "Demasiados pedidos: tente mais tarde"})
    r.status_code = 429
    r.headers["Retry-After"] = str(retry)
    return r


@bp.before_request
def _auth():
    g.agent = None
    cfg = current_app.config
    ip = request.remote_addr or "?"
    if request.endpoint in ("agent.enroll", "agent.bundle"):
        # registo/pacote: limite por IP (tentativas de adivinhar tokens) e por token
        if ratelimit.peek(f"authfail:{ip}") >= int(cfg["RATE_AUTH_FAIL_PER_MIN"]) > 0:    # tentativas falhadas (adivinhar tokens)
            return _too_many(30)
        ok, retry = ratelimit.hit(f"enroll:{ip}", int(cfg["RATE_ENROLL_PER_MIN"]))
        if not ok:
            return _too_many(retry)
        raw = request.headers.get("X-Enrollment-Token") or (request.get_json(silent=True) or {}).get("token") or ""
        if raw:
            ok, retry = ratelimit.hit(f"enroll-token:{_hash(str(raw))}", int(cfg["RATE_ENROLL_PER_MIN"]) * 3)
            if not ok:
                return _too_many(retry)
        return None                      # autenticação própria (token de registo)
    if ratelimit.peek(f"authfail:{ip}") >= int(cfg["RATE_AUTH_FAIL_PER_MIN"]) > 0:
        return _too_many(30)
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith("bearer "):
        ratelimit.hit(f"authfail:{ip}", 10 ** 6)
        return jsonify({"error": "Chave de agente em falta"}), 401
    agent = Agent.query.filter_by(key_hash=_hash(header[7:].strip()), revoked=False).first()
    if agent is None:
        ratelimit.hit(f"authfail:{ip}", 10 ** 6)
        return jsonify({"error": "Chave de agente inválida ou revogada"}), 401
    if not agent.hostname.startswith("loadtest-"):         # os agentes simulados do teste de carga não são limitados
        ok, retry = ratelimit.hit(f"agent:{agent.id}", int(cfg["RATE_AGENT_PER_MIN"]))
        if not ok:
            return _too_many(retry)
    tenant = db.session.get(Tenant, agent.tenant_id)
    from .. import licensing
    if tenant is None or not tenant.active or licensing.is_suspended(tenant):
        return jsonify({"error": "Organização inativa ou licença suspensa"}), 403
    g.agent, g.tenant = agent, tenant
    return None


def _touch(agent: Agent, body: dict | None = None) -> None:
    agent.last_seen = utcnow()
    agent.ip = (request.remote_addr or "")[:64]
    if body:
        agent.version = str(body.get("version", agent.version))[:32]
        if isinstance(body.get("state"), dict):
            st = {k: (v if isinstance(v, (int, float, bool)) else str(v)[:80]) for k, v in list(body["state"].items())[:12]}
            agent.status_json = json.dumps(st)
    if agent.asset is not None:
        agent.asset.last_seen = utcnow()


@bp.post("/enroll")
def enroll():
    data = request.get_json(silent=True) or {}
    raw = str(data.get("token", ""))
    tok = EnrollmentToken.query.filter_by(token_hash=_hash(raw), revoked=False).first() if raw else None
    if tok is None or (tok.expires_at and tok.expires_at < utcnow()) or (tok.max_uses and tok.uses >= tok.max_uses):
        ratelimit.hit(f"authfail:{request.remote_addr or '?'}", 10 ** 6)
        return jsonify({"error": "Token de registo inválido, expirado ou esgotado"}), 401
    tenant = db.session.get(Tenant, tok.tenant_id)
    from .. import licensing
    if tenant is None or not tenant.active or licensing.is_suspended(tenant):
        return jsonify({"error": "Organização inativa ou licença suspensa"}), 403
    host = str(data.get("hostname", "")).strip()[:255]
    os_family = data.get("os_family") if data.get("os_family") in ("windows", "linux", "macos") else ""
    if not host or not os_family:
        return jsonify({"error": "hostname e os_family (windows|linux|macos) são obrigatórios"}), 400
    mid = str(data.get("machine_id") or "")[:190]
    if mid:
        other = Agent.query.filter(Agent.machine_id == mid, Agent.tenant_id != tenant.id, Agent.revoked.is_(False)).first()
        if other is not None:
            return jsonify({"error": "Este equipamento já reporta a outra organização. Revogue/elimine o agente nessa organização "
                                     "antes de o registar aqui (um agente só reporta a uma organização)."}), 409
    asset, _ = inventory.upsert_asset(tenant, {"uid": host, "name": host, "fqdn": data.get("fqdn", ""),
                                               "ip": data.get("ip", ""), "mac": data.get("mac", ""), "os_family": os_family,
                                               "os_name": data.get("os_name", ""), "os_version": data.get("os_version", ""),
                                               "ring": tok.ring, "managed": True, "connection": "agent",
                                               "kind": data.get("kind") or ("server" if "server" in str(data.get("os_name", "")).lower() else "workstation")},
                                      source="agent")
    asset.ring = tok.ring if asset.ring == 4 else asset.ring
    asset.shadow_it = False
    existing = Agent.query.filter_by(tenant_id=tenant.id, asset_id=asset.id, revoked=False).first()
    key = "omxa_" + secrets.token_urlsafe(32)
    if existing is not None:
        existing.revoked = True                     # reinstalação: a chave anterior deixa de valer
    agent = Agent(tenant_id=tenant.id, asset_id=asset.id, key_hash=_hash(key), key_prefix=key[:10], hostname=host, machine_id=mid,
                  os_family=os_family, version=str(data.get("version", ""))[:32], ip=(request.remote_addr or "")[:64], last_seen=utcnow())
    tok.uses += 1
    db.session.add(agent)
    from ..security import audit
    audit("agent_enrolled", f"{host} ({os_family})", tenant_id=tenant.id)
    db.session.commit()
    return jsonify({"agent_key": key, "agent_id": agent.id, "poll_seconds": int(current_app.config["AGENT_HEARTBEAT_SECONDS"]),
                    "asset_id": asset.id, "tenant": {"slug": tenant.slug, "name": tenant.name},
                    "trust": {k: v for k, v in trust_block(agent).items() if k in ("task_keys", "pins", "agent_id")}}), 201


@bp.post("/poll")
def poll():
    agent: Agent = g.agent
    body = request.get_json(silent=True) or {}
    _touch(agent, body)
    asset = agent.asset
    need_inventory = asset is not None and (asset.software.count() == 0 or not asset.cmdb_synced_at and False)
    from .. import signing
    tasks = [signing.sign_task(current_app.config, agent.id, t) for t in deploy.poll(agent, limit=3)]
    db.session.commit()
    return jsonify({"tasks": tasks, "trust": trust_block(agent), "updates": {"scan_hours": int(current_app.config["UPDATES_SCAN_HOURS"])},
                    "agent_config": agentops.agent_config(agent), "poll_seconds": int(current_app.config["AGENT_HEARTBEAT_SECONDS"]),
                    "inventory_requested": bool(need_inventory), "server_time": utcnow().isoformat(),
                    "server_urls": agent_urls(current_app.config)})


@bp.post("/logs")
def post_logs():
    agent: Agent = g.agent
    body = request.get_json(silent=True) or {}
    events = body.get("events")
    if not isinstance(events, list):
        abort(400, description="events em falta")
    _touch(agent)
    n = agentops.ingest(agent, events)
    db.session.commit()
    return jsonify({"ok": True, "stored": n})


@bp.post("/inventory")
def post_inventory():
    agent: Agent = g.agent
    if agent.asset is None:
        abort(409, description="Agente sem ativo associado")
    report = request.get_json(silent=True) or {}
    _touch(agent, report)
    res = inventory.ingest_inventory(g.tenant, agent.asset, report)
    corr = correlate.correlate_asset(g.tenant, agent.asset)
    db.session.commit()
    return jsonify({"software": res, "correlation": corr})


@bp.post("/updates")
def post_updates():
    """Descoberta de atualizações instaláveis enviada pelo agente. A resposta confirma a receção (o agente guarda o relatório até a receber)."""
    from ..engine import updates as updates_mod
    agent: Agent = g.agent
    if agent.asset is None:
        abort(409, description="Agente sem ativo associado")
    if (request.content_length or 0) > 16 * 1024 * 1024:
        abort(413)
    _touch(agent, request.get_json(silent=True) and {"version": agent.version})
    try:
        res = updates_mod.ingest(g.tenant, agent, agent.asset, request.get_json(silent=True) or {})
    except updates_mod.ScanError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    db.session.commit()
    return jsonify(res)


@bp.post("/tasks/<int:task_id>/start")
def task_start(task_id: int):
    task = _task(task_id)
    if task.status in ("sent", "queued"):
        task.status, task.started_at = "running", utcnow()
        from ..engine import plans
        plans.on_task_started(task)
        db.session.commit()
    return jsonify({"ok": True})


@bp.post("/tasks/<int:task_id>/result")
def task_result(task_id: int):
    task = _task(task_id)
    report = request.get_json(silent=True) or {}
    _touch(g.agent)
    if task.status in ("succeeded", "failed", "rolled_back", "cancelled"):
        return jsonify({"ok": True, "duplicate": True})
    deploy.complete_task(task, report)
    db.session.commit()
    return jsonify({"ok": True, "status": task.status})


def _task(task_id: int) -> Task:
    task = db.session.get(Task, task_id)
    agent: Agent = g.agent
    if task is None or task.tenant_id != agent.tenant_id or task.asset_id != agent.asset_id:
        abort(404)
    return task


@bp.get("/package/<int:patch_id>")
def package(patch_id: int):
    agent: Agent = g.agent
    # só pacotes referenciados por tarefas ativas deste ativo
    ok = Task.query.filter(Task.tenant_id == agent.tenant_id, Task.asset_id == agent.asset_id, Task.patch_id == patch_id,
                           Task.status.in_(("sent", "running", "queued"))).first()
    if ok is None:
        abort(404)
    patch = ok.patch
    path = patches.local_path(patch, g.tenant)
    if path is None:
        abort(404)
    resp = send_file(path, as_attachment=True, download_name=path.name, conditional=True)
    resp.headers["X-Content-SHA256"] = patch.sha256
    return resp


def bundle_bytes() -> tuple[bytes, str]:
    """Zip do pacote ``omxpatch_agent`` (apenas biblioteca padrão), usado pelos scripts de auto-instalação."""
    import io
    import zipfile
    from pathlib import Path

    import omxpatch_agent
    root = Path(omxpatch_agent.__file__).resolve().parent
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(root.rglob("*.py")):
            z.write(f, f"omxpatch_agent/{f.relative_to(root).as_posix()}")
    data = buf.getvalue()
    return data, hashlib.sha256(data).hexdigest()


@bp.get("/bundle")
def bundle():
    """Agente para os scripts de instalação. Exige um token de registo válido (ou a chave de um agente)."""
    from flask import Response
    raw = request.headers.get("X-Enrollment-Token", "")
    ok = False
    if raw:
        tok = EnrollmentToken.query.filter_by(token_hash=_hash(raw), revoked=False).first()
        ok = tok is not None and not (tok.expires_at and tok.expires_at < utcnow())
    else:
        header = request.headers.get("Authorization", "")
        ok = header.lower().startswith("bearer ") and Agent.query.filter_by(key_hash=_hash(header[7:].strip()), revoked=False).first() is not None
    if not ok:
        ratelimit.hit(f"authfail:{request.remote_addr or '?'}", 10 ** 6)
        return jsonify({"error": "Token de registo inválido ou expirado"}), 401
    data, digest = bundle_bytes()
    return Response(data, mimetype="application/zip", headers={"X-Content-SHA256": digest,
                                                                "Content-Disposition": "attachment; filename=omxpatch_agent.zip"})
