"""Integração com o OMXVuln (ferramenta irmã) através da sua API REST ``/api/v1``.

* **Entrada** — ``pull_findings``: importa as vulnerabilidades abertas do OMXVuln como ativos + exposições
  (software, versão instalada, versão corrigida, CVE, risco). O OMXVuln é a fonte de verdade da deteção; o
  OMXPatch trata da mitigação, do patch e da validação.
* **Ativos** — ``fetch_assets``/``ingest_assets``: importa o inventário de ativos do OMXVuln (``/assets``, com recurso a ``/targets``):
  nome, IP, FQDN, SO, criticidade, etiquetas, responsável e software. Os ativos geridos por agente só são completados (campos
  vazios), nunca sobrescritos. ``sync`` junta ativos + vulnerabilidades e permite **simular** a importação (nada é gravado).
* **Saída** — ``push_status``: quando a validação em ciclo fechado confirma o patch, o OMXPatch marca a
  vulnerabilidade como *remediada* no OMXVuln (``POST /findings/<id>/status``) e pede um novo scan ao ativo
  (``POST /scans``) para que o OMXVuln feche a deteção com verificação independente.
"""
from __future__ import annotations

import json
import logging
import re

import requests

from ..extensions import db
from ..models import Asset, CveIntel, Exposure, Tenant, utcnow
from ..engine import correlate, inventory
from .http import request
from .store import ConnectorError, effective

log = logging.getLogger("omxpatch.omxvuln")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
SEV_CVSS = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}


def _headers(c) -> dict:
    tid = c.opts.get("tenant_id")
    return {"X-Tenant-ID": str(tid)} if tid else {}


def fetch_findings(c, limit: int = 500, max_pages: int = 20) -> list[dict]:
    out: list[dict] = []
    for page in range(max_pages):
        r = request(c, "GET", "/api/v1/findings", params={"limit": limit, "offset": page * limit},
                    extra_headers=_headers(c), timeout=60)
        r.raise_for_status()
        data = r.json()
        out += data
        if len(data) < limit:
            break
    return out


SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def ingest_findings(tenant: Tenant, findings: list[dict], min_severity: str = "", samples: dict | None = None) -> dict:
    """Converte findings do OMXVuln em ativos + exposições (idempotente). ``min_severity`` ignora deteções abaixo do nível."""
    new_assets = new_exp = skipped = 0
    floor = SEV_ORDER.get((min_severity or "").lower(), 0)
    samples = samples if samples is not None else {}
    seen: set[int] = set()
    open_states = ("open", "assigned", "in_progress", "fp_review")
    for f in findings:
        cves = [c.upper() for c in (f.get("cves") or []) if CVE_RE.fullmatch(str(c))]
        host = (f.get("host") or "").strip()
        if not cves or not host or f.get("status") not in open_states or SEV_ORDER.get(str(f.get("severity") or "").lower(), 2) < floor:
            skipped += 1
            continue
        import ipaddress
        try:
            ipaddress.ip_address(host)
            ip, name = host, host
        except ValueError:
            ip, name = "", host
        asset, created = inventory.upsert_asset(tenant, {"uid": host, "name": name, "ip": ip, "fqdn": name if not ip else "",
                                                         "managed": False}, source="omxvuln")
        if created:
            new_assets += 1
            samples.setdefault("assets", []).append(asset.name)
        if f.get("port"):
            ports = set(asset.ports) | ({int(f["port"])} if str(f["port"]).isdigit() else set())
            asset.open_ports = ",".join(str(p) for p in sorted(ports))
        component = (f.get("component") or "")[:255]
        for cve_id in cves:
            row = CveIntel.query.filter_by(cve_id=cve_id).first()
            if row is None:
                row = CveIntel(cve_id=cve_id, title=(f.get("title") or "")[:500], sources="omxvuln")
                db.session.add(row)
            if not row.description and f.get("description"):
                row.description = str(f["description"])[:4000]
            if row.cvss is None:
                row.cvss = f.get("cvss_score") or SEV_CVSS.get(f.get("severity", ""), 5.0)
            if f.get("kev"):
                row.kev = True
            risk = f.get("risk") or {}
            if risk.get("epss") is not None and row.epss is None:
                row.epss = float(risk["epss"])
            if risk.get("ransomware"):
                row.ransomware = True
            ex = Exposure.query.filter_by(tenant_id=tenant.id, asset_id=asset.id, cve_id=cve_id, software_name=component).first()
            if ex is None:
                ex = Exposure(tenant_id=tenant.id, asset_id=asset.id, cve_id=cve_id, software_name=component,
                              source="omxvuln", installed_version=(f.get("installed_version") or "")[:120],
                              fixed_version=(f.get("fixed_version") or "")[:120],
                              port=int(f["port"]) if str(f.get("port") or "").isdigit() else None)
                db.session.add(ex)
                db.session.flush()
                new_exp += 1
                samples.setdefault("exposures", []).append(f"{cve_id} @ {asset.name}")
            elif ex.status in ("closed", "remediated") and ex.source == "omxvuln":
                ex.status, ex.closed_at = "open", None
            ex.omxvuln_finding_id = f.get("id")
            ex.last_seen = utcnow()
            seen.add(ex.id)
            correlate.refresh(ex, tenant, row)
    return {"findings": len(findings), "new_assets": new_assets, "new_exposures": new_exp, "skipped": skipped,
            "seen": seen}


# --------------------------------------------------------------------------- ativos


def _rows(data) -> list[dict]:
    if isinstance(data, dict):
        for k in ("items", "results", "data", "assets", "targets"):
            if isinstance(data.get(k), list):
                return data[k]
        return []
    return data if isinstance(data, list) else []


def fetch_assets(c, limit: int = 500, max_pages: int = 20) -> list[dict]:
    """Ativos do OMXVuln. Caminho configurável (opção ``assets_path``); sem ele tenta ``/api/v1/assets`` e depois ``/api/v1/targets``."""
    paths = [c.opts.get("assets_path")] if c.opts.get("assets_path") else ["/api/v1/assets", "/api/v1/targets"]
    last = None
    for path in paths:
        out: list[dict] = []
        for page in range(max_pages):
            r = request(c, "GET", path, params={"limit": limit, "offset": page * limit}, extra_headers=_headers(c), timeout=60)
            if r.status_code == 404:
                last = r
                break
            r.raise_for_status()
            rows = _rows(r.json())
            out += rows
            if len(rows) < limit:
                return out
        else:
            return out
    raise ConnectorError(f"O OMXVuln não expõe a lista de ativos (HTTP {getattr(last, 'status_code', '?')}); defina a opção «assets_path».")


def _first(row: dict, *keys):
    for k in keys:
        v = row.get(k)
        if v not in (None, "", [], {}):
            return v
    return None


def asset_record(row: dict) -> dict | None:
    """Normaliza um ativo do OMXVuln (aceita vários nomes de campo) para os campos do CMDB do OMXPatch."""
    raw = _first(row, "hostname", "name", "fqdn", "host", "address", "ip", "value")
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if not raw:
        return None
    host = str(raw).strip()
    ip = str(_first(row, "ip", "ip_address", "address") or "").strip()
    try:
        import ipaddress
        ipaddress.ip_address(host)
        ip = ip or host
        fqdn = ""
    except ValueError:
        fqdn = str(_first(row, "fqdn") or (host if "." in host else "")).strip()
    try:
        import ipaddress
        ipaddress.ip_address(ip)
    except ValueError:
        ip = ""
    crit = str(_first(row, "criticality", "criticidade", "importance", "business_criticality") or "").lower()
    crit = {"urgent": "critical", "very_high": "critical", "normal": "medium", "moderate": "medium", "very_low": "low"}.get(crit, crit)
    tags = _first(row, "tags", "labels", "groups")
    if isinstance(tags, list):
        tags = ",".join(str(t.get("name") if isinstance(t, dict) else t) for t in tags)
    os_name = str(_first(row, "os_name", "os", "operating_system", "platform") or "")
    rec = {"uid": host.lower(), "name": host, "ip": ip, "fqdn": fqdn, "mac": _first(row, "mac", "mac_address") or "",
           "os_name": os_name[:120], "os_version": str(_first(row, "os_version") or "")[:120],
           "criticality": crit if crit in ("low", "medium", "high", "critical") else "", "tags": str(tags or "")[:500],
           "owner": str(_first(row, "owner", "responsible", "contact") or "")[:255], "department": str(_first(row, "department", "team") or "")[:120],
           "managed": False}
    fam = str(_first(row, "os_family") or "").lower()
    if fam in ("windows", "linux", "macos"):
        rec["os_family"] = fam
    kind = str(_first(row, "kind", "type", "asset_type") or "").lower()
    if kind:
        rec["kind"] = {"host": "server", "vm": "server", "web": "server"}.get(kind, kind)
    ports = _first(row, "open_ports", "ports")
    if isinstance(ports, list):
        ports = ",".join(str(p.get("port") if isinstance(p, dict) else p) for p in ports)
    if ports:
        rec["open_ports"] = str(ports)[:500]
    rec["_software"] = [{"name": str(i.get("name") or i.get("product") or ""), "version": str(i.get("version") or ""),
                         "vendor": str(i.get("vendor") or "")} for i in (_first(row, "software", "packages", "services") or []) if isinstance(i, dict)]
    rec["_ref"] = str(_first(row, "id", "uuid") or "")
    return rec


def ingest_assets(tenant: Tenant, rows: list[dict], samples: dict | None = None) -> dict:
    """Importa/atualiza ativos. Os que já são geridos (agente) só recebem os campos que estavam vazios."""
    samples = samples if samples is not None else {}
    new = updated = skipped = sw = 0
    for row in rows:
        rec = asset_record(row)
        if rec is None:
            skipped += 1
            continue
        software, ref = rec.pop("_software"), rec.pop("_ref")
        existing = Asset.query.filter_by(tenant_id=tenant.id, uid=rec["uid"]).first()
        if existing is not None and (existing.managed or existing.source in ("agent",)):
            rec = {k: v for k, v in rec.items() if k in ("tags", "owner", "department", "fqdn", "mac") and not getattr(existing, k)}
            rec["uid"] = existing.uid
        asset, created = inventory.upsert_asset(tenant, rec, source="omxvuln")
        if ref and not asset.cmdb_ref:
            asset.cmdb_ref = f"omxvuln:{ref}"[:190]
        if software and not asset.managed:
            sw += inventory.set_software(asset, software, source="omxvuln", replace=False).get("added", 0)
        if created:
            new += 1
            samples.setdefault("assets", []).append(asset.name)
        else:
            updated += 1
    return {"assets": len(rows), "new_assets": new, "updated_assets": updated, "skipped_assets": skipped, "software_added": sw}


# --------------------------------------------------------------------------- orquestração


def sync(tenant: Tenant, what: str = "both", dry_run: bool = False) -> dict:
    """Importa ``assets``, ``findings`` ou ``both``. ``dry_run`` executa tudo numa transação que é desfeita no fim:
    o relatório (contagens e exemplos) é exatamente o que a importação real faria."""
    c = effective(tenant.id, "omxvuln")
    if c is None:
        raise ConnectorError("OMXVuln não configurado (Integrações → OMXVuln, ou [omxvuln] no ficheiro de configuração)")
    if what not in ("assets", "findings", "both"):
        raise ConnectorError("Âmbito inválido: assets, findings ou both")
    report: dict = {"what": what, "dry_run": dry_run}
    samples: dict = {}
    assets_rows = fetch_assets(c) if what in ("assets", "both") else []
    findings_rows = fetch_findings(c) if what in ("findings", "both") else []
    nested = db.session.begin_nested() if dry_run else None
    try:
        if what in ("assets", "both"):
            report.update(ingest_assets(tenant, assets_rows, samples))
        if what in ("findings", "both"):
            res = ingest_findings(tenant, findings_rows, str(c.opts.get("min_severity") or ""), samples)
            seen = res.pop("seen")
            report.update(res)
            from ..engine import validation
            gone = 0
            for ex in Exposure.query.filter(Exposure.tenant_id == tenant.id, Exposure.source == "omxvuln",
                                            Exposure.status.in_(("open", "mitigated", "patching"))):
                if ex.id not in seen:
                    ex.status, ex.patched_at = "remediated", utcnow()
                    validation.schedule(ex, tenant)
                    gone += 1
                    samples.setdefault("closed", []).append(f"{ex.cve_id} @ {ex.asset.name}")
            report["closed_upstream"] = gone
    except Exception:
        if nested is not None:
            nested.rollback()
        raise
    report["samples"] = {k: v[:12] for k, v in samples.items()}
    if dry_run:
        nested.rollback()
        db.session.expire_all()
        return report
    if c.id:
        c.last_sync_at, c.last_ok = utcnow(), True
        c.last_detail = ", ".join(f"{report[k]} {lab}" for k, lab in (("assets", "ativos"), ("findings", "findings"), ("new_exposures", "novas exposições")) if k in report)
    db.session.commit()
    return report


def pull_findings(tenant: Tenant) -> dict:
    c = effective(tenant.id, "omxvuln")
    if c is None:
        raise ConnectorError("OMXVuln não configurado (Integrações → OMXVuln, ou [omxvuln] no ficheiro de configuração)")
    res = ingest_findings(tenant, fetch_findings(c), str(c.opts.get("min_severity") or ""))
    # exposições vindas do OMXVuln que deixaram de constar como abertas: remediadas (validar)
    seen = res.pop("seen")
    from ..engine import validation
    gone = 0
    for ex in Exposure.query.filter(Exposure.tenant_id == tenant.id, Exposure.source == "omxvuln",
                                    Exposure.status.in_(("open", "mitigated", "patching"))):
        if ex.id not in seen:
            ex.status, ex.patched_at = "remediated", utcnow()
            validation.schedule(ex, tenant)
            gone += 1
    res["closed_upstream"] = gone
    if c.id:
        c.last_sync_at, c.last_ok, c.last_detail = utcnow(), True, f"{res['findings']} findings, {res['new_exposures']} novas exposições"
    db.session.commit()
    return res


def push_status(tenant: Tenant, ex: Exposure, status: str = "remediated", note: str = "") -> bool:
    c = effective(tenant.id, "omxvuln")
    if c is None or not ex.omxvuln_finding_id or str(c.opts.get("push_status", "true")).lower() not in ("1", "true", "yes", "sim"):
        return False
    try:
        r = request(c, "POST", f"/api/v1/findings/{ex.omxvuln_finding_id}/status", extra_headers=_headers(c),
                    json_body={"status": status, "note": note or f"OMXPatch: {ex.cve_id} remediado e validado"})
        ok = r.status_code < 300
        if ok and str(c.opts.get("rescan", "true")).lower() in ("1", "true", "yes", "sim"):
            rescan(c, ex.asset)
        return ok
    except (requests.RequestException, ConnectorError) as exc:
        log.warning("OMXVuln push_status: %s", exc)
        return False


def rescan(c, asset: Asset) -> bool:
    """Pede ao OMXVuln novo scan ao ativo (procura o alvo registado com o mesmo valor)."""
    try:
        r = request(c, "GET", "/api/v1/targets", extra_headers=_headers(c))
        r.raise_for_status()
        wanted = {asset.ip, asset.name, asset.fqdn} - {""}
        for t in r.json():
            if wanted & set(t.get("value") or []):
                r2 = request(c, "POST", "/api/v1/scans", extra_headers=_headers(c),
                             json_body={"target_id": t["id"], "profile": "auto"})
                return r2.status_code < 300
    except (requests.RequestException, ConnectorError, ValueError) as exc:
        log.warning("OMXVuln rescan: %s", exc)
    return False


def test(c) -> tuple[bool, str]:
    try:
        r = request(c, "GET", "/api/v1/me", extra_headers=_headers(c))
        return r.status_code == 200, (f"Autenticado como {r.json().get('email')}" if r.status_code == 200 else f"HTTP {r.status_code}")
    except (requests.RequestException, ConnectorError, ValueError) as exc:
        return False, str(exc)[:300]


__all__ = ["json"]
