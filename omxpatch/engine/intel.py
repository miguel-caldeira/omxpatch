"""Módulo 2 — Vulnerability Intelligence Engine.

Fontes: NVD (CVSS, CPE afetados, referências de exploit), CISA KEV (exploração ativa, ransomware), EPSS (FIRST),
MITRE CVE (descrição/CNA), feeds de ameaças (maturidade do exploit, malware, ransomware) e avisos de fabricantes.
Cada fonte é independente e tolerante a falhas: sem Internet a plataforma continua com o catálogo existente.
Os *parsers* são funções puras (testáveis offline); ``sync_*`` faz os pedidos HTTP e grava em ``CveIntel``.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime

import requests
from flask import current_app

from ..extensions import db
from ..models import MATURITY_RANK, CveIntel, jloads, utcnow
from ..security import OutboundURLError, check_outbound_url

log = logging.getLogger("omxpatch.intel")
UA = {"User-Agent": "OMXPatch/1.0"}


def _date(value) -> datetime | None:
    if not value:
        return None
    text = str(value).replace("Z", "")
    for fmt, size in (("%Y-%m-%dT%H:%M:%S", 19), ("%Y-%m-%d", 10)):
        try:
            return datetime.strptime(text[:size], fmt)
        except ValueError:
            continue
    return None


def get_or_create(cve_id: str) -> CveIntel:
    cve_id = cve_id.strip().upper()
    row = CveIntel.query.filter_by(cve_id=cve_id).first()
    if row is None:
        row = CveIntel(cve_id=cve_id)
        db.session.add(row)
    return row


def _add_source(row: CveIntel, name: str) -> None:
    srcs = {s for s in (row.sources or "").split(",") if s}
    srcs.add(name)
    row.sources = ",".join(sorted(srcs))
    row.updated_at = utcnow()


def _raise_maturity(row: CveIntel, level: str) -> None:
    if MATURITY_RANK.get(level, 0) > MATURITY_RANK.get(row.exploit_maturity or "none", 0):
        row.exploit_maturity = level


# --------------------------------------------------------------------------- parsers (puros)


def parse_kev(data: dict) -> list[dict]:
    out = []
    for v in data.get("vulnerabilities", []):
        if not v.get("cveID"):
            continue
        out.append({"cve": v["cveID"].upper(), "title": v.get("vulnerabilityName", ""),
                    "added": _date(v.get("dateAdded")), "due": _date(v.get("dueDate")),
                    "ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
                    "vendor": v.get("vendorProject", ""), "product": v.get("product", ""),
                    "action": v.get("requiredAction", "")})
    return out


def parse_epss(data: dict) -> list[dict]:
    out = []
    for r in data.get("data", []):
        try:
            out.append({"cve": r["cve"].upper(), "epss": float(r["epss"]), "percentile": float(r.get("percentile", 0))})
        except (KeyError, ValueError, TypeError):
            continue
    return out


def parse_nvd(data: dict) -> list[dict]:
    """Respostas da API NVD 2.0: CVSS, CWE, descrição, CPE afetados e referências."""
    out = []
    for item in data.get("vulnerabilities", []):
        c = item.get("cve", {})
        cve_id = c.get("id")
        if not cve_id:
            continue
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        score, vector = None, ""
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = c.get("metrics", {}).get(key)
            if metrics:
                m = metrics[0].get("cvssData", {})
                score, vector = m.get("baseScore"), m.get("vectorString", "")
                break
        cwes = sorted({d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])
                       if d.get("value", "").startswith("CWE-")})
        affected = []
        for conf in c.get("configurations", []):
            for node in conf.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    if not m.get("vulnerable"):
                        continue
                    parts = m.get("criteria", "").split(":")
                    if len(parts) < 6:
                        continue
                    ent = {"vendor": parts[3], "product": parts[4],
                           "version_start": m.get("versionStartIncluding") or "",
                           "start_excl": m.get("versionStartExcluding") or "",
                           "version_end": m.get("versionEndIncluding") or "",
                           "end_excl": m.get("versionEndExcluding") or "",
                           "exact": parts[5] if parts[5] not in ("*", "-") else ""}
                    if ent["end_excl"]:
                        ent["fixed"] = ent["end_excl"]
                    affected.append(ent)
        refs = c.get("references", [])
        exploit_refs = [r["url"] for r in refs if "Exploit" in (r.get("tags") or [])]
        patch_refs = [r["url"] for r in refs if {"Patch", "Vendor Advisory"} & set(r.get("tags") or [])]
        out.append({"cve": cve_id.upper(), "description": desc, "cvss": score, "vector": vector,
                    "cwe": ",".join(cwes), "published": _date(c.get("published")), "affected": affected[:200],
                    "exploit_refs": exploit_refs[:10], "patch_refs": patch_refs[:10]})
    return out


def parse_mitre(data: dict) -> dict | None:
    """Formato CVE JSON 5 (cveawg.mitre.org)."""
    meta = data.get("cveMetadata", {})
    cve_id = meta.get("cveId")
    if not cve_id:
        return None
    cna = data.get("containers", {}).get("cna", {})
    desc = next((d["value"] for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")), "")
    affected = []
    for a in cna.get("affected", []):
        for v in a.get("versions", []):
            if v.get("status") == "affected":
                ent = {"vendor": (a.get("vendor") or "").lower(), "product": (a.get("product") or "").lower(),
                       "version_start": v.get("version") if v.get("version") not in ("0", "n/a", None) else "",
                       "end_excl": v.get("lessThan") or "", "version_end": v.get("lessThanOrEqual") or ""}
                if ent["end_excl"]:
                    ent["fixed"] = ent["end_excl"]
                affected.append(ent)
    return {"cve": cve_id.upper(), "title": cna.get("title", ""), "description": desc,
            "published": _date(meta.get("datePublished")), "affected": affected[:100]}


def parse_threat_feed(data) -> list[dict]:
    """Feed JSON simples: lista (ou {"items": [...]}) de {cve, exploit, malware[], ransomware, exploited}."""
    items = data.get("items", []) if isinstance(data, dict) else data
    out = []
    for r in items if isinstance(items, list) else []:
        if isinstance(r, dict) and r.get("cve"):
            out.append({"cve": str(r["cve"]).upper(), "exploit": r.get("exploit", ""),
                        "malware": r.get("malware") or [], "ransomware": bool(r.get("ransomware")),
                        "exploited": bool(r.get("exploited")), "ref": r.get("ref", "")})
    return out


def parse_advisories(data) -> list[dict]:
    """Avisos de fabricante: lista de {cve, vendor, product, fixed_version, kb, url, os_family, package}."""
    items = data.get("advisories", []) if isinstance(data, dict) else data
    return [r for r in items if isinstance(r, dict) and r.get("cve")] if isinstance(items, list) else []


# --------------------------------------------------------------------------- gravação


def apply_kev(entries: list[dict]) -> int:
    n = 0
    for e in entries:
        row = get_or_create(e["cve"])
        row.kev, row.kev_added, row.kev_due = True, e["added"], e["due"]
        row.ransomware = row.ransomware or e["ransomware"]
        row.title = row.title or e["title"]
        _raise_maturity(row, "weaponized")
        if e["vendor"] and not row.affected_list:
            row.affected = json.dumps([{"vendor": e["vendor"].lower(), "product": e["product"].lower()}])
        _add_source(row, "kev")
        n += 1
    return n


def apply_epss(entries: list[dict]) -> int:
    n = 0
    for e in entries:
        row = CveIntel.query.filter_by(cve_id=e["cve"]).first()
        if row is None:
            continue
        row.epss, row.epss_percentile = e["epss"], e["percentile"]
        if e["epss"] >= 0.5:
            _raise_maturity(row, "functional")
        _add_source(row, "epss")
        n += 1
    return n


def _merge_affected(row: CveIntel, new: list[dict]) -> None:
    cur = row.affected_list
    seen = {json.dumps(a, sort_keys=True) for a in cur}
    for a in new:
        key = json.dumps(a, sort_keys=True)
        if key not in seen:
            cur.append(a)
            seen.add(key)
    row.affected = json.dumps(cur[:300])


def apply_nvd(entries: list[dict]) -> int:
    for e in entries:
        row = get_or_create(e["cve"])
        if e["cvss"] is not None:
            row.cvss, row.cvss_vector = float(e["cvss"]), e["vector"]
        row.description = e["description"] or row.description
        row.cwe, row.published = e["cwe"] or row.cwe, e["published"] or row.published
        _merge_affected(row, e["affected"])
        if e["exploit_refs"]:
            row.exploit_refs = "\n".join(e["exploit_refs"])
            _raise_maturity(row, "poc")
        if e["patch_refs"]:
            adv = row.advisory_list
            have = {a.get("url") for a in adv}
            adv += [{"vendor": "", "url": u} for u in e["patch_refs"] if u not in have]
            row.advisories = json.dumps(adv[:50])
        _add_source(row, "nvd")
    return len(entries)


def apply_mitre(e: dict | None) -> int:
    if not e:
        return 0
    row = get_or_create(e["cve"])
    row.title = e["title"] or row.title
    row.description = row.description or e["description"]
    row.published = row.published or e["published"]
    _merge_affected(row, e["affected"])
    _add_source(row, "mitre")
    return 1


def apply_threat_feed(entries: list[dict]) -> int:
    for e in entries:
        row = get_or_create(e["cve"])
        level = {"weaponized": "weaponized", "functional": "functional", "poc": "poc"}.get(str(e["exploit"]).lower())
        if level:
            _raise_maturity(row, level)
        elif e["exploited"]:
            _raise_maturity(row, "weaponized")
        if e["malware"]:
            cur = set(row.malware_list) | {str(m) for m in e["malware"]}
            row.malware = ",".join(sorted(cur))
        row.ransomware = row.ransomware or e["ransomware"]
        if e["ref"]:
            row.exploit_refs = ((row.exploit_refs or "") + "\n" + e["ref"]).strip()
        _add_source(row, "threat-feed")
    return len(entries)


def apply_advisories(entries: list[dict]) -> int:
    for e in entries:
        row = get_or_create(e["cve"])
        adv = row.advisory_list
        item = {k: e.get(k, "") for k in ("vendor", "product", "fixed_version", "kb", "url", "os_family", "package",
                                           "installer", "download_url", "sha256", "silent_args")}
        if item not in adv:
            adv.append(item)
        row.advisories = json.dumps(adv[:100])
        if e.get("product") and e.get("fixed_version"):
            _merge_affected(row, [{"vendor": (e.get("vendor") or "").lower(), "product": e["product"].lower(),
                                   "end_excl": e["fixed_version"], "fixed": e["fixed_version"]}])
        _add_source(row, "vendor")
    return len(entries)


# --------------------------------------------------------------------------- HTTP


def _get(url: str, params: dict | None = None, headers: dict | None = None, timeout: int = 30):
    check_outbound_url(url)
    resp = requests.get(url, params=params, headers={**UA, **(headers or {})}, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def sync_kev() -> int:
    cfg = current_app.config
    if not cfg["KEV_ENABLED"]:
        return 0
    n = apply_kev(parse_kev(_get(cfg["KEV_URL"], timeout=60)))
    db.session.commit()
    return n


def sync_epss(cves: list[str] | None = None) -> int:
    cfg = current_app.config
    if not cfg["EPSS_ENABLED"]:
        return 0
    cves = cves or [c.cve_id for c in CveIntel.query.with_entities(CveIntel.cve_id).all()]
    total = 0
    for i in range(0, len(cves), 100):
        chunk = cves[i:i + 100]
        total += apply_epss(parse_epss(_get(cfg["EPSS_URL"], {"cve": ",".join(chunk)})))
    db.session.commit()
    return total


def sync_nvd(cves: list[str], budget: int | None = None) -> int:
    cfg = current_app.config
    if not cfg["NVD_ENABLED"]:
        return 0
    headers = {"apiKey": cfg["NVD_API_KEY"]} if cfg["NVD_API_KEY"] else {}
    n = 0
    for cve in cves[: budget or int(cfg["NVD_BUDGET"])]:
        try:
            n += apply_nvd(parse_nvd(_get(cfg["NVD_URL"], {"cveId": cve}, headers)))
        except (requests.RequestException, ValueError, OutboundURLError) as exc:
            log.warning("NVD %s: %s", cve, exc)
            break
    db.session.commit()
    return n


def sync_mitre(cves: list[str], budget: int = 20) -> int:
    cfg = current_app.config
    if not cfg["MITRE_ENABLED"]:
        return 0
    n = 0
    for cve in cves[:budget]:
        try:
            n += apply_mitre(parse_mitre(_get(f"{cfg['MITRE_URL'].rstrip('/')}/{cve}")))
        except (requests.RequestException, ValueError, OutboundURLError) as exc:
            log.warning("MITRE %s: %s", cve, exc)
            break
    db.session.commit()
    return n


def sync_feeds() -> dict:
    cfg = current_app.config
    res = {"threat": 0, "advisories": 0}
    for url in [u.strip() for u in str(cfg["THREAT_FEEDS"]).splitlines() if u.strip()]:
        try:
            res["threat"] += apply_threat_feed(parse_threat_feed(_get(url)))
        except (requests.RequestException, ValueError, OutboundURLError) as exc:
            log.warning("Feed %s: %s", url, exc)
    for url in [u.strip() for u in str(cfg["VENDOR_ADVISORIES"]).splitlines() if u.strip()]:
        try:
            res["advisories"] += apply_advisories(parse_advisories(_get(url)))
        except (requests.RequestException, ValueError, OutboundURLError) as exc:
            log.warning("Avisos %s: %s", url, exc)
    db.session.commit()
    return res


def enrich(cves: list[str]) -> None:
    """Completa os CVE em falta (sob demanda, com orçamento): NVD → MITRE → EPSS."""
    missing = [c for c in cves if not (CveIntel.query.filter_by(cve_id=c).first() or CveIntel(cvss=None)).cvss]
    if missing:
        sync_nvd(missing)
        sync_mitre([c for c in missing if not (CveIntel.query.filter_by(cve_id=c).first() or CveIntel()).description])
    try:
        sync_epss(cves)
    except (requests.RequestException, ValueError, OutboundURLError) as exc:
        log.warning("EPSS: %s", exc)


def sync_all() -> dict:
    """Atualização completa (tarefa diária do worker). Devolve o resumo por fonte; erros não interrompem."""
    res: dict[str, object] = {}
    for name, fn in (("kev", sync_kev), ("feeds", sync_feeds)):
        try:
            res[name] = fn()
        except (requests.RequestException, ValueError, OutboundURLError) as exc:
            res[name] = f"erro: {exc}"
            log.warning("Sincronização %s: %s", name, exc)
    try:
        stale = [c.cve_id for c in CveIntel.query.filter(CveIntel.cvss.is_(None)).limit(int(current_app.config["NVD_BUDGET"]))]
        res["nvd"] = sync_nvd(stale)
        res["epss"] = sync_epss()
    except (requests.RequestException, ValueError, OutboundURLError) as exc:
        res["nvd_epss"] = f"erro: {exc}"
    return res


def import_file(text: str) -> dict:
    """Importação manual (ambientes isolados): JSON do KEV, EPSS, NVD, feed de ameaças ou avisos."""
    data = json.loads(text)
    if isinstance(data, dict) and "vulnerabilities" in data and data["vulnerabilities"] and "cveID" in data["vulnerabilities"][0]:
        n = apply_kev(parse_kev(data)); kind = "kev"
    elif isinstance(data, dict) and "vulnerabilities" in data:
        n = apply_nvd(parse_nvd(data)); kind = "nvd"
    elif isinstance(data, dict) and "data" in data and data["data"] and "epss" in data["data"][0]:
        n = apply_epss(parse_epss(data)); kind = "epss"
    elif isinstance(data, dict) and "advisories" in data:
        n = apply_advisories(parse_advisories(data)); kind = "advisories"
    else:
        n = apply_threat_feed(parse_threat_feed(data)); kind = "threat-feed"
    db.session.commit()
    return {"kind": kind, "count": n}


def stats() -> dict:
    q = CveIntel.query
    return {"total": q.count(), "kev": q.filter_by(kev=True).count(), "with_epss": q.filter(CveIntel.epss.isnot(None)).count(),
            "ransomware": q.filter_by(ransomware=True).count(),
            "weaponized": q.filter_by(exploit_maturity="weaponized").count()}


__all__ = ["jloads"]
