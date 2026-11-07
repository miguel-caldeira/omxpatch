"""Módulo 3 — Exposure Management multi-vendor: recolha de sinais de outras plataformas de segurança.

Fabricantes: Defender, SentinelOne, CrowdStrike, Tenable, Qualys, Rapid7, Wiz, Prisma Cloud, Check Point, Palo Alto,
Fortinet, Zscaler. Cada sinal é normalizado em ``Signal`` (kind: vuln, active_exploit, fw_blocked, fw_allowed,
edr_detected, edr_missed, waf_protected, ioc), que o motor de risco cruza para concluir, por exemplo:
*vulnerável + exploração ativa + firewall não bloqueia + EDR não deteta + sem patch ⇒ risco crítico*.

Duas vias de entrada:

* ``ingest`` — webhook / ficheiro (JSON ou CSV) com normalizadores para Defender, CrowdStrike Spotlight e Tenable e um
  normalizador genérico por *aliases* de campos (cobre os restantes fabricantes e exportações de SIEM/SOAR);
* ``pull`` — consulta periódica da API do conector (caminho/itens/mapeamento configuráveis em ``options``).
"""
from __future__ import annotations

import csv
import io
import json
import logging
import re

import requests

from ..extensions import db
from ..models import SIGNAL_KINDS, Asset, Connector, Signal, Tenant, utcnow
from .http import request
from .store import ConnectorError

log = logging.getLogger("omxpatch.signals")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
ALIASES = {
    "cve": ("cve", "cveId", "cve_id", "cves", "vulnerability", "vuln_id", "plugin.cve", "cve.id"),
    "asset": ("asset", "hostname", "computerDnsName", "host", "device", "deviceName", "dest", "dst", "destination", "ip",
              "ipv4", "asset.hostname", "host_info.hostname", "machine"),
    "value": ("value", "port", "dest_port", "dport", "rule", "ioc", "indicator", "signature", "url"),
    "kind": ("kind", "type", "signal"),
    "action": ("action", "disposition", "verdict", "result"),
    "source": ("source", "vendor", "product"),
}
BLOCK = {"block", "blocked", "deny", "denied", "drop", "dropped", "reset", "prevented", "prevent", "quarantined"}
ALLOW = {"allow", "allowed", "permit", "permitted", "accept", "accepted", "pass", "passed"}
DETECT = {"detected", "alert", "alerted", "detect"}
MISS = {"missed", "undetected", "not_detected", "no_alert"}


def dig(obj, dotted: str):
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and cur and isinstance(cur[0], dict) and part in cur[0]:
            cur = cur[0][part]
        else:
            return None
    return cur


def _pick(rec: dict, key: str):
    for alias in ALIASES[key]:
        v = dig(rec, alias) if "." in alias else rec.get(alias)
        if v not in (None, "", []):
            return v
    return None


def _cves(v) -> list[str]:
    if v is None:
        return [""]
    items = v if isinstance(v, list) else [v]
    out = []
    for it in items:
        out += [m.upper() for m in CVE_RE.findall(str(it))]
    return out or [""]


def _kind(rec: dict, default: str) -> str:
    k = str(_pick(rec, "kind") or "").lower()
    if k in SIGNAL_KINDS:
        return k
    action = str(_pick(rec, "action") or "").lower()
    if action in BLOCK:
        return "fw_blocked"
    if action in ALLOW:
        return "fw_allowed"
    if action in DETECT:
        return "edr_detected"
    if action in MISS:
        return "edr_missed"
    if rec.get("exploited") or rec.get("exploit_observed") or rec.get("actively_exploited"):
        return "active_exploit"
    return default


def normalize_generic(records: list[dict], source: str, default_kind: str = "vuln") -> list[dict]:
    out = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        kind = _kind(rec, default_kind)
        asset = _pick(rec, "asset")
        value = _pick(rec, "value")
        for cve in _cves(_pick(rec, "cve")):
            if kind == "vuln" and not cve:
                continue
            out.append({"source": str(_pick(rec, "source") or source)[:32], "kind": kind, "cve": cve,
                        "asset": str(asset or ""), "value": str(value or "")[:500]})
    return out


def normalize_defender(payload) -> list[dict]:
    rows = payload.get("value", []) if isinstance(payload, dict) else payload
    return [{"source": "defender", "kind": "vuln", "cve": str(r.get("cveId", "")).upper(),
             "asset": r.get("computerDnsName") or r.get("deviceName") or "", "value": r.get("productName", "")}
            for r in rows if isinstance(r, dict) and r.get("cveId")]


def normalize_crowdstrike(payload) -> list[dict]:
    rows = payload.get("resources", []) if isinstance(payload, dict) else payload
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        cve = str((r.get("cve") or {}).get("id") or "").upper()
        asset = (r.get("host_info") or {}).get("hostname") or ""
        if not cve:
            continue
        out.append({"source": "crowdstrike", "kind": "vuln", "cve": cve, "asset": asset,
                    "value": (r.get("app") or {}).get("product_name_version", "")})
        if int((r.get("cve") or {}).get("exploit_status") or 0) >= 90:      # 90 = usado ativamente
            out.append({"source": "crowdstrike", "kind": "active_exploit", "cve": cve, "asset": asset, "value": ""})
    return out


def normalize_tenable(payload) -> list[dict]:
    rows = payload.get("vulnerabilities", payload) if isinstance(payload, dict) else payload
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        cves = (r.get("plugin") or {}).get("cve") or r.get("cve") or []
        asset = (r.get("asset") or {}).get("hostname") or (r.get("asset") or {}).get("ipv4") or r.get("asset_hostname") or ""
        for cve in _cves(cves):
            if cve:
                out.append({"source": "tenable", "kind": "vuln", "cve": cve, "asset": str(asset), "value": ""})
                if (r.get("plugin") or {}).get("exploited_by_malware") or (r.get("plugin") or {}).get("exploit_available") and r.get("exploited"):
                    out.append({"source": "tenable", "kind": "active_exploit", "cve": cve, "asset": str(asset), "value": ""})
    return out


NORMALIZERS = {"defender": normalize_defender, "crowdstrike": normalize_crowdstrike, "tenable": normalize_tenable}
DEFAULT_KIND = {"defender": "vuln", "sentinelone": "vuln", "crowdstrike": "vuln", "tenable": "vuln", "qualys": "vuln",
                "rapid7": "vuln", "wiz": "vuln", "prisma": "vuln", "checkpoint": "fw_blocked", "paloalto": "fw_blocked",
                "fortinet": "fw_blocked", "zscaler": "fw_blocked"}


def parse_body(text: str, content_type: str = "") -> list[dict]:
    text = (text or "").lstrip("﻿")
    if "csv" in content_type or (not text.lstrip().startswith(("{", "["))):
        return list(csv.DictReader(io.StringIO(text)))
    data = json.loads(text)
    if isinstance(data, dict):
        for key in ("signals", "items", "records", "events", "vulnerabilities", "value", "resources", "data"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    return data


def normalize(vendor: str, payload, raw_text_records: list[dict] | None = None) -> list[dict]:
    fn = NORMALIZERS.get(vendor)
    if fn is not None and isinstance(payload, (dict, list)):
        rows = fn(payload)
        if rows:
            return rows
    records = raw_text_records if raw_text_records is not None else (
        payload if isinstance(payload, list) else (payload.get("signals") or payload.get("items") or [payload])
        if isinstance(payload, dict) else [])
    return normalize_generic(records, vendor, DEFAULT_KIND.get(vendor, "vuln"))


def store(tenant: Tenant, rows: list[dict], vendor: str) -> dict:
    """Grava sinais (resolvendo o ativo por nome/FQDN/IP); sinais de vulnerabilidade geram também a exposição."""
    new = 0
    unknown = 0
    now = utcnow()
    for r in rows:
        ref = (r.get("asset") or "").strip()
        asset = None
        if ref:
            asset = (Asset.query.filter(Asset.tenant_id == tenant.id,
                                        db.or_(db.func.lower(Asset.name) == ref.lower(), db.func.lower(Asset.fqdn) == ref.lower(),
                                               Asset.ip == ref, Asset.uid == ref.lower())).first())
            if asset is None:
                unknown += 1
        dup = Signal.query.filter_by(tenant_id=tenant.id, source=r["source"], kind=r["kind"], cve_id=r.get("cve", ""),
                                     asset_id=asset.id if asset else None, asset_ref=ref[:255], value=r.get("value", "")).first()
        if dup:
            dup.observed_at = now
            continue
        db.session.add(Signal(tenant_id=tenant.id, source=r["source"], kind=r["kind"], cve_id=r.get("cve", ""),
                              asset_id=asset.id if asset else None, asset_ref=ref[:255], value=r.get("value", ""),
                              observed_at=now, raw=json.dumps(r)[:2000]))
        new += 1
    db.session.commit()
    return {"received": len(rows), "new": new, "unknown_assets": unknown, "vendor": vendor}


def ingest(tenant: Tenant, vendor: str, text: str, content_type: str = "application/json") -> dict:
    is_json = "csv" not in content_type and text.lstrip("﻿").lstrip().startswith(("{", "["))
    if is_json:
        payload = json.loads(text.lstrip("﻿"))
        records = None
        if not isinstance(payload, list) and not (isinstance(payload, dict) and vendor in NORMALIZERS):
            records = parse_body(text, content_type)
        rows = normalize(vendor, payload, records)
    else:
        rows = normalize_generic(parse_body(text, content_type), vendor, DEFAULT_KIND.get(vendor, "vuln"))
    return store(tenant, rows, vendor)


def pull(c: Connector, tenant: Tenant) -> dict:
    """Consulta periódica da API do conector (``options.path`` ou ``vuln_path``)."""
    o = c.opts
    path = o.get("path") or o.get("vuln_path")
    if not path:
        raise ConnectorError(f"{c.kind}: indique o caminho da API em options.path (ou use o webhook /api/v1/signals)")
    try:
        r = request(c, "GET", path, timeout=90)
        r.raise_for_status()
        payload = r.json()
    except (requests.RequestException, ValueError) as exc:
        c.last_ok, c.last_detail = False, str(exc)[:300]
        raise ConnectorError(str(exc)) from exc
    rows = normalize(c.kind, payload)
    res = store(tenant, rows, c.kind)
    c.last_sync_at, c.last_ok, c.last_detail = utcnow(), True, f"{res['new']} novos sinais"
    return res
