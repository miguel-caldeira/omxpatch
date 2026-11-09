"""Descoberta de atualizações instaláveis (enviada pelos agentes) e descarga proativa para o repositório do servidor.

Fluxo: o agente varre as origens do SO (apt, dnf, zypper, Windows Update, winget, Chocolatey, softwareupdate, brew) → ``ingest`` grava
cada atualização (``AvailableUpdate``), cria/liga o ``Patch`` do repositório (partilhado entre ativos), associa-o às exposições (por CVE ou
por pacote + versão corrigida) e regista a receção (``UpdateScan``) → o worker descarrega os ficheiros (``download_pending``) com
verificação de SHA-256 → ficam disponíveis para simulação e remediação (planos) e o agente recebe-os do servidor.

Segurança: os URL vêm de agentes (dados não confiáveis): só se descarrega com SHA-256 anunciado (salvo ``UPDATES_ALLOW_UNHASHED``),
validado contra SSRF em cada redirecionamento, com limite de tamanho e verificação do hash antes de gravar."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin, urlsplit

import requests
from flask import current_app

from ..extensions import db
from ..models import Agent, Asset, AvailableUpdate, Exposure, Patch, Task, Tenant, UpdateScan, utcnow
from ..security import OutboundURLError, check_outbound_url
from . import patches
from .versions import compare

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
SEVERITIES = ("low", "medium", "high", "critical")
FILE_INSTALLERS = ("msi", "exe", "msu", "cab", "pkg", "apt", "dnf", "yum", "zypper")
MAX_ITEMS = 2000
MAX_ATTEMPTS = 3


class ScanError(ValueError):
    pass


def _s(v, n: int) -> str:
    return str(v if v is not None else "")[:n]


def _clean(item: dict, os_family: str) -> dict | None:
    if not isinstance(item, dict):
        return None
    source, uid = _s(item.get("source"), 16).strip(), _s(item.get("uid"), 190).strip()
    if not source or not uid:
        return None
    url = _s(item.get("download_url"), 1000).strip()
    if url and urlsplit(url).scheme not in ("http", "https"):
        url = ""
    sha = _s(item.get("sha256"), 64).lower()
    sev = _s(item.get("severity"), 12).lower()
    return {"source": source, "uid": uid, "name": _s(item.get("name"), 255), "title": _s(item.get("title") or item.get("name"), 500),
            "current_version": _s(item.get("current_version"), 120), "new_version": _s(item.get("new_version"), 120), "kb": _s(item.get("kb"), 32),
            "severity": sev if sev in SEVERITIES else "medium", "category": _s(item.get("category"), 16) or "update",
            "cves": sorted({c.upper() for c in (item.get("cves") or []) if isinstance(c, str) and CVE_RE.match(c.upper())})[:50],
            "size_bytes": max(0, int(item.get("size_bytes") or 0)) if str(item.get("size_bytes") or "0").isdigit() else 0, "reboot": bool(item.get("reboot")),
            "installer": _s(item.get("installer"), 16), "package": _s(item.get("package") or item.get("name"), 255), "origin": _s(item.get("origin"), 200),
            "download_url": url, "sha256": sha if re.fullmatch(r"[0-9a-f]{64}", sha) else "", "silent_args": _s(item.get("silent_args"), 500)}


# --------------------------------------------------------------------------- ingestão


def _patch_uid(c: dict) -> str:
    base = c["kb"] or f"{c['source']}:{c['name'] or c['uid']}={c['new_version']}"
    tag = c["sha256"][:8] or (hashlib.md5(c["download_url"].encode(), usedforsecurity=False).hexdigest()[:8] if c["download_url"] else "")  # nosec B324 - só identifica
    return (base + (f"#{tag}" if tag and not c["kb"] else ""))[:190]


def ensure_patch(tenant: Tenant, asset: Asset, c: dict) -> Patch:
    uid = _patch_uid(c)
    p = Patch.query.filter_by(tenant_id=tenant.id, patch_uid=uid).first()
    fields = dict(title=c["title"], product=c["name"], os_family=asset.os_family or "", installer=c["installer"] or "ansible", package_name=c["package"],
                  version_fixed=c["new_version"], download_url=c["download_url"], sha256=c["sha256"], size_bytes=c["size_bytes"], severity=c["severity"],
                  silent_args=c["silent_args"], reboot_required=c["reboot"], source="discovery", vendor=c["origin"][:200])
    if p is None:
        p = Patch(tenant_id=tenant.id, patch_uid=uid, status="identified", cves=json.dumps(c["cves"]))
        db.session.add(p)
        for k, v in fields.items():
            setattr(p, k, v)
        db.session.flush()
    else:
        for k in ("download_url", "sha256"):
            if not getattr(p, k) and fields[k]:
                setattr(p, k, fields[k])
        if c["cves"]:
            p.cves = json.dumps(sorted(set(p.cve_list) | set(c["cves"])))
    return p


def _link_exposures(tenant: Tenant, asset: Asset, au: AvailableUpdate, patch: Patch) -> int:
    """Associa o patch descoberto às exposições abertas do ativo: por CVE, ou pelo pacote + versão corrigida."""
    n = 0
    name = (au.name or au.package or "").lower()
    for ex in Exposure.query.filter(Exposure.tenant_id == tenant.id, Exposure.asset_id == asset.id, Exposure.status.in_(("open", "mitigated"))):
        by_cve = ex.cve_id in au.cve_list
        sw = (ex.software_name or "").lower().replace(" ", "")
        by_pkg = bool(name) and bool(sw) and (name.replace(" ", "") == sw or name.split(":")[0] == sw) and ex.fixed_version and \
            compare(au.new_version.split(":")[-1] or "0", ex.fixed_version.split(":")[-1] or "0") >= 0
        if by_cve or by_pkg:
            if ex.cve_id not in patch.cve_list:
                patch.cves = json.dumps(sorted(set(patch.cve_list) | {ex.cve_id}))
            ex.patch_id, ex.patch_available = patch.id, True
            if not ex.fixed_version and au.new_version:
                ex.fixed_version = au.new_version
            n += 1
    return n


def ingest(tenant: Tenant, agent: Agent, asset: Asset, report: dict) -> dict:
    """Grava uma descoberta. Idempotente por ``scan_id``. Devolve o que a consola registou (confirmação ao agente)."""
    scan_id = _s(report.get("scan_id"), 64)
    items = report.get("updates")
    if not scan_id or not isinstance(items, list) or len(items) > MAX_ITEMS:
        raise ScanError("Relatório inválido: scan_id e lista de atualizações (máx. %d) são obrigatórios" % MAX_ITEMS)
    prev = UpdateScan.query.filter_by(asset_id=asset.id, scan_id=scan_id).first()
    if prev is not None:
        return {"ok": True, "duplicate": True, "received": prev.total, "scan_id": scan_id}
    sources = report.get("sources") if isinstance(report.get("sources"), dict) else {}
    now = utcnow()
    seen: set[tuple] = set()
    new = linked = 0
    for raw in items:
        c = _clean(raw, asset.os_family)
        if c is None:
            continue
        key = (c["source"], c["uid"])
        seen.add(key)
        au = AvailableUpdate.query.filter_by(tenant_id=tenant.id, asset_id=asset.id, source=c["source"], uid=c["uid"]).first()
        if au is None:
            au = AvailableUpdate(tenant_id=tenant.id, asset_id=asset.id, source=c["source"], uid=c["uid"], first_seen=now)
            db.session.add(au)
            new += 1
        elif au.status in ("installed", "superseded"):
            au.status, au.resolved_at, au.attempts = "discovered", None, 0         # reapareceu: voltou a estar pendente
        for k in ("name", "title", "current_version", "new_version", "kb", "severity", "category", "size_bytes", "reboot", "installer", "package", "origin",
                  "download_url", "sha256", "silent_args"):
            setattr(au, k, c[k])
        au.cves, au.last_seen = json.dumps(c["cves"]), now
        patch = ensure_patch(tenant, asset, c)
        db.session.flush()
        au.patch_id = patch.id
        if patch.local_file and au.status not in ("downloaded",):
            au.status, au.detail = "downloaded", ""
        elif not au.status or au.status == "discovered":
            au.status = "discovered"
        linked += _link_exposures(tenant, asset, au, patch)
    # o que uma origem com varrimento completo já não lista foi instalado (ou substituído)
    resolved = 0
    for src, st in sources.items():
        if not (isinstance(st, dict) and st.get("ok") is True):
            continue
        for au in AvailableUpdate.query.filter(AvailableUpdate.tenant_id == tenant.id, AvailableUpdate.asset_id == asset.id, AvailableUpdate.source == src,
                                               AvailableUpdate.status.notin_(("installed", "superseded"))):
            if (au.source, au.uid) not in seen:
                au.status, au.resolved_at = "installed", now
                resolved += 1
    scanned_at = None
    try:
        scanned_at = datetime.fromtimestamp(float(report.get("scanned_at")), tz=timezone.utc).replace(tzinfo=None)
    except (TypeError, ValueError, OSError):
        pass
    clean_sources = {_s(k, 16): {kk: (vv if isinstance(vv, (bool, int, float)) else _s(vv, 300)) for kk, vv in v.items() if kk in ("ok", "count", "note", "error", "seconds")}
                     for k, v in sources.items() if isinstance(v, dict)}
    db.session.add(UpdateScan(tenant_id=tenant.id, asset_id=asset.id, agent_id=agent.id if agent else None, scan_id=scan_id, scanned_at=scanned_at, received_at=now,
                              total=len(seen), new=new, resolved=resolved, sources=json.dumps(clean_sources)))
    hw = asset.hw
    hw["updates"] = {"last_scan": now.isoformat(), "total": len(seen), "sources": clean_sources}
    asset.hardware = json.dumps(hw)
    asset.last_seen = now
    return {"ok": True, "received": len(seen), "new": new, "resolved": resolved, "linked_exposures": linked, "scan_id": scan_id}


# --------------------------------------------------------------------------- pedir descoberta


def request_scan(tenant: Tenant, asset_ids: list[int] | None = None) -> int:
    """Cria tarefas «descobrir atualizações» (uma por agente, sem duplicar as pendentes)."""
    q = Agent.query.filter_by(tenant_id=tenant.id, revoked=False)
    n = 0
    for ag in q:
        if ag.asset_id is None or (asset_ids is not None and ag.asset_id not in asset_ids):
            continue
        if Task.query.filter(Task.tenant_id == tenant.id, Task.asset_id == ag.asset_id, Task.type == "update_scan",
                             Task.status.in_(("pending", "queued", "sent", "running"))).first():
            continue
        db.session.add(Task(tenant_id=tenant.id, type="update_scan", asset_id=ag.asset_id, ring=ag.asset.ring, mode="agent", status="queued", payload="{}"))
        n += 1
    return n


# --------------------------------------------------------------------------- descarga proativa


def _cfg(key: str, default=None):
    return current_app.config.get(key, default)


def _free_disk(path) -> int:
    return shutil.disk_usage(path).free


def _get(url: str, max_hops: int = 4):
    """GET em *streaming*, validando o destino em cada redirecionamento (anti-SSRF)."""
    for _ in range(max_hops + 1):
        check_outbound_url(url, require_https=False)
        r = requests.get(url, stream=True, timeout=(15, 120), allow_redirects=False, headers={"User-Agent": "OMXPatch-updates/1"})
        if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
            url = urljoin(url, r.headers["Location"])
            r.close()
            continue
        r.raise_for_status()
        return r
    raise ValueError("Demasiados redirecionamentos")


def _eligible(patch: Patch) -> str:
    """Motivo pelo qual NÃO se descarrega (vazio = pode)."""
    if not patch.download_url:
        return "Sem URL de transferência na origem: a atualização usa o gestor/serviço do próprio equipamento"
    if not patch.sha256 and not _cfg("UPDATES_ALLOW_UNHASHED", False):
        return "Origem sem SHA-256 verificável: a atualização usa o gestor de pacotes do equipamento (que valida a assinatura)"
    if patch.download_url.lower().startswith("http://") and not (patch.sha256 and _cfg("UPDATES_ALLOW_HTTP_WITH_HASH", True)):
        return "URL sem TLS e sem SHA-256: recusado"
    return ""


def fetch_patch(patch: Patch, tenant: Tenant) -> None:
    """Descarrega para o repositório com verificação de SHA-256; lança em caso de falha (nada fica gravado)."""
    limit = int(_cfg("UPDATES_MAX_DOWNLOAD_MB", 1024)) * 1024 * 1024
    folder = patches.package_dir(tenant)
    r = _get(patch.download_url)
    try:
        size = int(r.headers.get("Content-Length") or 0)
        if size and size > limit:
            raise ValueError(f"Ficheiro de {size // 1048576} MB acima do limite ({limit // 1048576} MB)")
        if _free_disk(folder) < (size or 0) * 2 + 512 * 1024 * 1024:
            raise OSError("Espaço em disco insuficiente no repositório")
        h, total = hashlib.sha256(), 0
        fd, tmp = tempfile.mkstemp(prefix=".dl-", dir=str(folder))
        try:
            with os.fdopen(fd, "wb") as fh:
                for chunk in r.iter_content(1 << 20):
                    total += len(chunk)
                    if total > limit:
                        raise ValueError("Ficheiro acima do limite configurado")
                    h.update(chunk)
                    fh.write(chunk)
            digest = h.hexdigest()
            if patch.sha256 and patch.sha256.lower() != digest:
                raise ValueError("SHA-256 não confere com o anunciado pela origem: ficheiro rejeitado")
            name = patch.download_url.rsplit("/", 1)[-1].split("?")[0] or patch.patch_uid
            final = folder / f"{patch.id}-{patches._safe_name(name)}"
            os.replace(tmp, final)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    finally:
        r.close()
    patch.local_file, patch.sha256, patch.size_bytes = final.name, digest, total
    if patch.status == "identified":
        patch.status = "downloaded"


def download_pending(tenant: Tenant, limit: int = 3, now: datetime | None = None) -> dict:
    """Descarrega até ``limit`` patches descobertos ainda fora do repositório. Devolve contagens."""
    now = now or utcnow()
    out = {"downloaded": 0, "failed": 0, "skipped": 0}
    pend = AvailableUpdate.query.filter(AvailableUpdate.tenant_id == tenant.id, AvailableUpdate.status.in_(("discovered", "queued", "failed")),
                                        AvailableUpdate.patch_id.isnot(None)).order_by(AvailableUpdate.id).all()
    done_patches: set[int] = set()
    for au in pend:
        if au.patch_id in done_patches:
            continue
        done_patches.add(au.patch_id)
        patch = au.patch
        group = AvailableUpdate.query.filter(AvailableUpdate.tenant_id == tenant.id, AvailableUpdate.patch_id == patch.id,
                                             AvailableUpdate.status.notin_(("installed", "superseded"))).all()
        if patch.local_file and patches.local_path(patch, tenant):
            for x in group:
                x.status, x.detail = "downloaded", ""
            continue
        why = _eligible(patch)
        if why:
            for x in group:
                x.status, x.detail = "not_downloadable", why
            out["skipped"] += 1
            continue
        if au.status == "failed" and (au.attempts >= MAX_ATTEMPTS or (au.last_attempt_at and now - au.last_attempt_at < timedelta(minutes=30 * max(1, au.attempts)))):
            continue
        if out["downloaded"] + out["failed"] >= limit:
            break
        for x in group:
            x.status = "downloading"
        db.session.flush()
        try:
            fetch_patch(patch, tenant)
            for x in group:
                x.status, x.detail, x.attempts = "downloaded", "", 0
            out["downloaded"] += 1
        except (requests.RequestException, OutboundURLError, ValueError, OSError) as exc:
            for x in group:
                x.status, x.detail, x.attempts, x.last_attempt_at = "failed", str(exc)[:300], x.attempts + 1, now
            out["failed"] += 1
    return out


# --------------------------------------------------------------------------- vigilância (worker)


def tick(tenant: Tenant, now: datetime | None = None) -> dict:
    """Chamado pelo worker: garante que cada agente descobre com a periodicidade certa e descarrega o que ficou pendente."""
    now = now or utcnow()
    res = {"scan_requests": 0}
    hours = max(1, int(_cfg("UPDATES_SCAN_HOURS", 6)))
    stale = now - timedelta(hours=hours * 2)                # o agente descobre sozinho; isto é a rede de segurança
    last = {s.asset_id: s.received_at for s in UpdateScan.query.filter_by(tenant_id=tenant.id).order_by(UpdateScan.id)}
    ids = [ag.asset_id for ag in Agent.query.filter_by(tenant_id=tenant.id, revoked=False) if ag.asset_id and (last.get(ag.asset_id) or datetime.min) < stale
           and ag.last_seen and now - ag.last_seen < timedelta(minutes=int(_cfg("AGENT_OFFLINE_MINUTES", 20)))]
    if ids:
        res["scan_requests"] = request_scan(tenant, ids)
    if _cfg("UPDATES_AUTO_DOWNLOAD", True):
        res.update(download_pending(tenant, int(_cfg("UPDATES_DOWNLOAD_PER_TICK", 3)), now))
    return res


# --------------------------------------------------------------------------- resumo (UI / painel / API)


def summary(tenant: Tenant, now: datetime | None = None) -> dict:
    now = now or utcnow()
    rows = AvailableUpdate.query.filter(AvailableUpdate.tenant_id == tenant.id, AvailableUpdate.status.notin_(("installed", "superseded"))).all()
    by_status, by_sev, by_source = {}, {}, {}
    for u in rows:
        by_status[u.status] = by_status.get(u.status, 0) + 1
        by_sev[u.severity] = by_sev.get(u.severity, 0) + 1
        by_source[u.source] = by_source.get(u.source, 0) + 1
    hours = max(1, int(_cfg("UPDATES_SCAN_HOURS", 6)))
    agents = Agent.query.filter_by(tenant_id=tenant.id, revoked=False).all()
    last = {}
    for s in UpdateScan.query.filter_by(tenant_id=tenant.id).order_by(UpdateScan.id):
        last[s.asset_id] = s
    never = [a for a in agents if a.asset_id and a.asset_id not in last]
    stale = [a for a in agents if a.asset_id in last and now - last[a.asset_id].received_at > timedelta(hours=hours * 2)]
    return {"pending": len(rows), "assets": len({u.asset_id for u in rows}), "by_status": by_status, "by_severity": by_sev, "by_source": by_source,
            "security": sum(1 for u in rows if u.category == "security"), "downloaded": by_status.get("downloaded", 0),
            "repo_bytes": sum(int(u.size_bytes or 0) for u in rows if u.status == "downloaded"), "agents": len(agents), "scanned": len(last),
            "never_scanned": len(never), "stale": len(stale), "scan_hours": hours,
            "last_received": max((s.received_at for s in last.values()), default=None)}


# --------------------------------------------------------------------------- diagnóstico (porque é que a lista está vazia?)

MIN_AGENT_VERSION = (1, 10)             # primeira versão do agente com descoberta de atualizações


def _ver(v: str) -> tuple:
    try:
        return tuple(int(x) for x in (v or "0").split(".")[:2])
    except ValueError:
        return (0, 0)


def diagnose(tenant: Tenant, now: datetime | None = None) -> list[dict]:
    """Uma linha por agente com o veredicto: agente antigo, sem contacto, sem descoberta, origens com erro ou OK."""
    now = now or utcnow()
    offline = timedelta(minutes=int(_cfg("AGENT_OFFLINE_MINUTES", 20)))
    last = {}
    for sc in UpdateScan.query.filter_by(tenant_id=tenant.id).order_by(UpdateScan.id):
        last[sc.asset_id] = sc
    rows = []
    for ag in Agent.query.filter_by(tenant_id=tenant.id, revoked=False):
        sc = last.get(ag.asset_id)
        errs = []
        if sc:
            errs = [f"{k}: {v.get('error', 'erro')}" for k, v in sc.source_data.items() if v.get("ok") is False]
        if _ver(ag.version) < MIN_AGENT_VERSION:
            verdict, level = f"Agente {ag.version or '?'} é anterior à descoberta de atualizações (≥ 1.10): atualize o agente.", "high"
        elif not ag.last_seen or now - ag.last_seen > offline:
            verdict, level = "Agente sem contacto recente com a consola.", "high"
        elif not sc:
            verdict, level = "Ainda sem descoberta recebida (use «Descobrir agora»; se persistir, veja o registo do agente).", "medium"
        elif errs:
            verdict, level = "Descoberta recebida, mas há origens com erro: " + "; ".join(errs)[:300], "medium"
        elif not sc.total:
            verdict, level = "Descoberta recebida: o equipamento não tem atualizações pendentes.", "ok"
        else:
            verdict, level = f"Descoberta recebida: {sc.total} atualização(ões).", "ok"
        rows.append({"agent": ag, "last_scan": sc.received_at if sc else None, "total": sc.total if sc else None, "verdict": verdict, "level": level})
    return rows
