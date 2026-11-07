"""Módulos 5 e 6 (repositório) — identificação de patches e Patch Intelligence.

* ``identify_for_cve``: converte avisos de fabricante e versões corrigidas (NVD/MITRE) em registos ``Patch``
  *identificados* no repositório da organização.
* ``intelligence``: antes da aplicação valida taxa de sucesso (base comunitária + telemetria dos clientes),
  incidentes conhecidos do fabricante, problemas reportados, histórico de rollback e impacto operacional, e
  devolve uma recomendação (go / caution / hold) com os motivos.
* ``download``: obtém o ficheiro para o repositório local, com verificação SHA-256 obrigatória.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import requests
from flask import current_app

from ..extensions import db
from ..models import CveIntel, Exposure, Patch, PatchTelemetry, Tenant, jloads, utcnow
from ..security import check_outbound_url
from .versions import compare

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
DEFAULT_INSTALLER = {"windows": "winget", "linux": "apt", "macos": "brew"}
KB_RE = re.compile(r"\bKB\d{6,8}\b", re.I)


def _installer_for(adv: dict, os_family: str) -> str:
    if adv.get("installer"):
        return adv["installer"]
    if adv.get("kb") or KB_RE.search(adv.get("package", "") or ""):
        return "wua"
    return DEFAULT_INSTALLER.get(os_family, "ansible")


def _upsert_patch(tenant_id: int, uid: str, **fields) -> tuple[Patch, bool]:
    uid = uid[:190]
    p = Patch.query.filter_by(tenant_id=tenant_id, patch_uid=uid).first()
    created = p is None
    if created:
        p = Patch(tenant_id=tenant_id, patch_uid=uid)
        db.session.add(p)
    for k, v in fields.items():
        if v not in (None, "") and (created or not getattr(p, k, None)):
            setattr(p, k, v)
    return p, created


def identify_for_cve(tenant_id: int, cve: CveIntel) -> list[Patch]:
    """Patches identificados para um CVE (idempotente). Devolve os registos do repositório."""
    out: list[Patch] = []
    sev = cve.severity
    for adv in cve.advisory_list:
        kb = (adv.get("kb") or "").upper()
        pkg = adv.get("package") or ""
        fixed = adv.get("fixed_version") or ""
        if not (kb or pkg or fixed or adv.get("download_url")):
            continue                                        # só links genéricos: não é um patch aplicável
        os_family = adv.get("os_family") or ("windows" if kb else "")
        uid = kb or (f"{os_family or 'any'}:{pkg or adv.get('product', '')}:{fixed}")
        p, _ = _upsert_patch(tenant_id, uid, title=f"{adv.get('vendor') or ''} {adv.get('product') or pkg or kb} "
                                                   f"{fixed}".strip()[:500],
                             vendor=adv.get("vendor", ""), product=adv.get("product", ""), os_family=os_family,
                             installer=_installer_for(adv, os_family), package_name=pkg or adv.get("product", ""),
                             version_fixed=fixed, download_url=adv.get("download_url", ""),
                             sha256=adv.get("sha256", ""), silent_args=adv.get("silent_args", ""),
                             bulletin_url=adv.get("url", ""), severity=sev, source="vendor")
        _add_cve(p, cve.cve_id)
        out.append(p)
    for a in cve.affected_list:
        fixed = a.get("fixed") or a.get("end_excl")
        product = a.get("product")
        if not (fixed and product):
            continue
        if any(p.version_fixed == fixed and (p.product or "").lower().replace(" ", "") == product.lower().replace("_", "").replace(" ", "")
               for p in out):
            continue                                   # já coberto por um aviso do fabricante
        uid = f"upd:{product}:{fixed}"
        p, _ = _upsert_patch(tenant_id, uid, title=f"Atualizar {a.get('vendor', '')} {product} para ≥ {fixed}".strip(),
                             vendor=a.get("vendor", ""), product=product, installer="ansible", package_name=product,
                             version_fixed=fixed, severity=sev, source="vendor")
        _add_cve(p, cve.cve_id)
        out.append(p)
    db.session.flush()
    return out


def _add_cve(p: Patch, cve_id: str) -> None:
    cves = p.cve_list
    if cve_id not in cves:
        cves.append(cve_id)
        p.cves = json.dumps(sorted(cves))
    if SEV_RANK.get(p.severity, 0) < SEV_RANK.get(cve_severity(cve_id), 0):
        p.severity = cve_severity(cve_id)


def cve_severity(cve_id: str) -> str:
    row = CveIntel.query.filter_by(cve_id=cve_id).first()
    return row.severity if row else "medium"


def link_exposure(exposure: Exposure, cve: CveIntel | None) -> Patch | None:
    """Associa a exposição ao melhor patch do repositório (da família do SO do ativo, o mais recente)."""
    if cve is None:
        return None
    candidates = identify_for_cve(exposure.tenant_id, cve)
    fam = exposure.asset.os_family
    pool = [p for p in Patch.query.filter_by(tenant_id=exposure.tenant_id).all()
            if cve.cve_id in p.cve_list and p.status != "rejected"]
    pool = [p for p in (pool or candidates) if not p.os_family or p.os_family == fam]
    if exposure.software_name:
        named = [p for p in pool if p.product and p.product.lower().replace(" ", "") in exposure.software_name.lower().replace(" ", "")]
        pool = named or pool
    if not pool:
        exposure.patch_id, exposure.patch_available = None, False
        return None

    def rank(p: Patch):
        return (p.status in ("approved", "downloaded"), bool(p.os_family == fam), p.version_fixed or "")

    best = pool[0]
    for p in pool[1:]:
        if rank(p)[:2] > rank(best)[:2] or (rank(p)[:2] == rank(best)[:2] and compare(p.version_fixed or "0", best.version_fixed or "0") > 0):
            best = p
    exposure.patch_id, exposure.patch_available = best.id, True
    if best.version_fixed and not exposure.fixed_version:
        exposure.fixed_version = best.version_fixed
    return best


# --------------------------------------------------------------------------- Patch Intelligence


def tenant_stats(patch: Patch) -> dict:
    rows = PatchTelemetry.query.filter_by(tenant_id=patch.tenant_id, patch_id=patch.id).all()
    n = len(rows)
    ok = sum(1 for r in rows if r.result == "success")
    ux = [r.ux_score for r in rows if r.ux_score is not None]
    return {"n": n, "success": ok, "failed": sum(1 for r in rows if r.result == "failed"),
            "rollbacks": sum(1 for r in rows if r.result == "rolled_back"),
            "crashes": sum(1 for r in rows if r.crashed),
            "success_rate": round(ok * 100 / n, 1) if n else None,
            "crash_rate": round(sum(1 for r in rows if r.crashed) * 100 / n, 1) if n else None,
            "ux": round(sum(ux) / len(ux), 1) if ux else None}


def intelligence(patch: Patch) -> dict:
    ts = tenant_stats(patch)
    c_n = patch.community_reports or 0
    c_rate = patch.community_success_rate
    t_n, t_rate = ts["n"], ts["success_rate"]
    if c_rate is not None and t_rate is not None and (c_n + t_n):
        combined = (c_rate * c_n + t_rate * t_n) / (c_n + t_n)
    else:
        combined = t_rate if t_rate is not None else c_rate
    issues = patch.known_issues
    severe = [i for i in issues if str(i.get("severity", "")).lower() in ("high", "critical")]
    reasons: list[str] = []
    level = "go"
    if combined is None:
        reasons.append("Sem histórico de aplicação: começar no Ring 0 (laboratório).")
        level = "caution"
    else:
        if combined < 80 and (c_n + t_n) >= 5:
            level = "hold"
            reasons.append(f"Taxa de sucesso baixa ({combined:.0f} %).")
        elif combined < 95:
            level = "caution"
            reasons.append(f"Taxa de sucesso de {combined:.0f} % (abaixo de 95 %).")
    if severe:
        level = "hold"
        reasons.append(f"{len(severe)} incidente(s) grave(s) conhecido(s) do fabricante: "
                       + "; ".join(i.get("title", "?") for i in severe[:3]))
    elif issues and level == "go":
        level = "caution"
        reasons.append(f"{len(issues)} incidente(s) conhecido(s) do fabricante.")
    if (patch.reported_problems or 0) >= 5 and level == "go":
        level = "caution"
        reasons.append(f"{patch.reported_problems} problemas reportados pela comunidade.")
    if ts["rollbacks"] >= 3:
        level = "hold"
        reasons.append(f"{ts['rollbacks']} rollbacks no histórico da organização.")
    elif ts["rollbacks"]:
        level = "caution" if level == "go" else level
        reasons.append(f"{ts['rollbacks']} rollback(s) no histórico da organização.")
    if patch.impact == "high" or (patch.reboot_required and patch.impact == "medium"):
        level = "caution" if level == "go" else level
        reasons.append("Impacto operacional elevado (reinício/serviço crítico).")
    if patch.superseded_by:
        reasons.append(f"Substituído por {patch.superseded_by}.")
    if not reasons:
        reasons.append("Sem alertas: taxa de sucesso elevada e sem incidentes conhecidos.")
    score = 100 if combined is None else int(combined)
    score -= 25 * len(severe) + 5 * (len(issues) - len(severe)) + 8 * ts["rollbacks"]
    return {"level": level, "score": max(0, min(100, score)), "reasons": reasons, "tenant": ts,
            "community": {"reports": c_n, "success_rate": c_rate}, "combined_success_rate": combined,
            "known_issues": issues, "reported_problems": patch.reported_problems or 0, "impact": patch.impact,
            "reboot_required": patch.reboot_required}


def record_telemetry(tenant_id: int, patch_id: int, asset_id: int | None, result: str, task_id: int | None = None,
                     ring: int = 4, crashed: bool = False, ux_score: int | None = None, duration_s: int = 0) -> None:
    db.session.add(PatchTelemetry(tenant_id=tenant_id, patch_id=patch_id, asset_id=asset_id, task_id=task_id,
                                  ring=ring, result=result, crashed=crashed, ux_score=ux_score, duration_s=duration_s))


def import_community(tenant_id: int, items: list[dict]) -> int:
    """Base comunitária / fabricantes: [{patch_uid, success_rate, reports, problems, issues[], impact, superseded_by}]."""
    n = 0
    for it in items:
        p = Patch.query.filter_by(tenant_id=tenant_id, patch_uid=str(it.get("patch_uid", ""))[:190]).first()
        if p is None:
            continue
        if it.get("success_rate") is not None:
            p.community_success_rate = float(it["success_rate"])
        p.community_reports = int(it.get("reports", p.community_reports or 0))
        p.reported_problems = int(it.get("problems", p.reported_problems or 0))
        if it.get("issues") is not None:
            p.vendor_known_issues = json.dumps(it["issues"])
        if it.get("impact") in ("low", "medium", "high"):
            p.impact = it["impact"]
        if it.get("superseded_by"):
            p.superseded_by = str(it["superseded_by"])
        n += 1
    db.session.commit()
    return n


# --------------------------------------------------------------------------- repositório local


def package_dir(tenant: Tenant) -> Path:
    d = Path(current_app.config["AGENT_PACKAGE_DIR"]) / str(tenant.id)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe_name(name: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    name = re.sub(r"\.{2,}", ".", name).lstrip(".-")
    return name[:120] or "package"


def store_file(patch: Patch, tenant: Tenant, data: bytes, filename: str) -> Patch:
    digest = hashlib.sha256(data).hexdigest()
    if patch.sha256 and patch.sha256.lower() != digest:
        raise ValueError("O SHA-256 do ficheiro não corresponde ao registado no patch")
    path = package_dir(tenant) / f"{patch.id}-{_safe_name(filename)}"
    path.write_bytes(data)
    patch.local_file, patch.sha256, patch.size_bytes = path.name, digest, len(data)
    if patch.status == "identified":
        patch.status = "downloaded"
    return patch


def download(patch: Patch, tenant: Tenant, timeout: int = 300) -> Patch:
    """Descarrega o instalador do fabricante para o repositório. Exige SHA-256 conhecido (anti-adulteração)."""
    if not patch.download_url:
        raise ValueError("O patch não tem URL de transferência")
    if not patch.sha256:
        raise ValueError("Indique o SHA-256 do fabricante antes de descarregar (verificação de integridade)")
    check_outbound_url(patch.download_url, require_https=True)
    resp = requests.get(patch.download_url, timeout=timeout, stream=True, headers={"User-Agent": "OMXPatch/1.0"})
    resp.raise_for_status()
    limit = int(current_app.config["MAX_CONTENT_LENGTH"])
    buf = bytearray()
    for chunk in resp.iter_content(1 << 20):
        buf += chunk
        if len(buf) > limit:
            raise ValueError("Ficheiro acima do limite configurado")
    name = patch.download_url.rsplit("/", 1)[-1].split("?")[0] or patch.patch_uid
    return store_file(patch, tenant, bytes(buf), name)


def local_path(patch: Patch, tenant: Tenant) -> Path | None:
    if not patch.local_file:
        return None
    p = (package_dir(tenant) / patch.local_file).resolve()
    return p if p.is_file() and package_dir(tenant).resolve() in p.parents else None


__all__ = ["jloads", "utcnow"]
