"""Avaliação de atualizações em equipamentos de rede e firewalls (Check Point, FortiGate, Palo Alto, Cisco, Juniper, Arista).

O Ansible só **consulta** o equipamento (somente leitura) e devolve a saída bruta; este módulo faz a análise:

1. **extrai** versão, modelo e (quando o fabricante as indica) as versões disponíveis;
2. aplica a **política de versões** do administrador (mínima, recomendada, fim de suporte — ``NetBaseline``);
3. cruza a versão com o **catálogo de CVE** (versões afetadas conhecidas) — correspondência aproximada, a confirmar no aviso do fabricante;
4. devolve um veredicto: atualizado, atualização disponível, abaixo do mínimo, fim de suporte, vulnerável ou indeterminado.

Não há catálogo de versões embutido: um catálogo desatualizado seria pior do que nenhum. As versões disponíveis vêm do próprio equipamento
(FortiGate e Palo Alto) e a política vem do administrador."""
from __future__ import annotations

import fnmatch
import json
import re
import xml.etree.ElementTree as ET  # nosec B405 - só texto da API do próprio equipamento, limitado em tamanho e sem DOCTYPE

from ..extensions import db
from ..models import CveIntel, NetBaseline, NetworkAssessment, Task, utcnow
from . import versions

MAX_RAW = 1_000_000
# palavras que identificam o produto nos catálogos de CVE (vendor/product normalizados)
CVE_HINTS = {"fortios": [("fortinet", "fortios")], "panos": [("paloaltonetworks", "pan-os"), ("paloaltonetworks", "pan_os")],
             "checkpoint": [("checkpoint", "gaia_os"), ("checkpoint", "gaia")], "cisco_ios": [("cisco", "ios"), ("cisco", "ios_xe")],
             "cisco_nxos": [("cisco", "nx-os"), ("cisco", "nx_os")], "junos": [("juniper", "junos")], "eos": [("arista", "eos")]}


def _clip(text) -> str:
    return str(text or "")[:MAX_RAW]


def _first(pattern: str, text: str, flags: int = re.I | re.M) -> str:
    m = re.search(pattern, text, flags)
    return (m.group(1) if m else "").strip()


# --------------------------------------------------------------------------- extração por plataforma


def parse_fortios(raw: dict) -> dict:
    out = {"version": "", "model": "", "hostname": "", "serial": "", "available": []}
    try:
        st = json.loads(_clip(raw.get("status"))) if raw.get("status") else {}
    except ValueError:
        st = {}
    res = st.get("results") if isinstance(st.get("results"), dict) else {}
    out["version"] = str(st.get("version") or res.get("version") or "").lstrip("v")
    out["model"] = str(res.get("model_name", "") + " " + res.get("model_number", "")).strip() or str(res.get("model", ""))
    out["hostname"], out["serial"] = str(res.get("hostname", "")), str(st.get("serial", ""))
    try:
        fw = json.loads(_clip(raw.get("firmware"))) if raw.get("firmware") else {}
    except ValueError:
        fw = {}
    r = fw.get("results") if isinstance(fw.get("results"), dict) else {}
    cur = r.get("current") if isinstance(r.get("current"), dict) else {}
    if not out["version"] and cur.get("version"):
        out["version"] = str(cur["version"]).lstrip("v")
    for a in (r.get("available") or [])[:200]:
        if isinstance(a, dict) and a.get("version"):
            out["available"].append(str(a["version"]).lstrip("v"))
    out["notes"] = "versões disponíveis lidas do FortiGuard através do equipamento" if out["available"] else "o equipamento não devolveu versões disponíveis (sem acesso ao FortiGuard?)"
    return out


def _xml(text: str):
    text = _clip(text)
    if not text.strip() or "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        return None
    try:
        return ET.fromstring(text)  # nosec B314 - sem DOCTYPE/ENTITY, tamanho limitado
    except ET.ParseError:
        return None


def parse_panos(raw: dict) -> dict:
    out = {"version": "", "model": "", "hostname": "", "serial": "", "available": [], "downloaded": []}
    root = _xml(raw.get("info"))
    if root is not None:
        sysn = root.find(".//system")
        if sysn is not None:
            g = lambda t: (sysn.findtext(t) or "").strip()  # noqa: E731
            out.update(version=g("sw-version"), model=g("model"), hostname=g("hostname"), serial=g("serial"))
    sw = _xml(raw.get("software"))
    if sw is not None:
        for e in sw.findall(".//entry")[:300]:
            v = (e.findtext("version") or "").strip()
            if not v:
                continue
            out["available"].append(v)
            if (e.findtext("downloaded") or "").strip().lower() == "yes":
                out["downloaded"].append(v)
    out["notes"] = ("versões listadas pelo equipamento (request system software check)" if out["available"]
                    else "o equipamento não listou versões (sem acesso ao servidor de atualizações da Palo Alto?)")
    return out


def parse_checkpoint(raw: dict) -> dict:
    t = _clip(raw.get("version"))
    return {"version": _first(r"Check Point Gaia\s+(R[\w.\-]+)", t) or _first(r"Product version\s+(?:Check Point\s+)?(?:Gaia\s+)?(R[\w.\-]+)", t),
            "model": _first(r"^\s*(?:Appliance|Model)[^:\n]*:\s*(.+)$", t), "hostname": "", "serial": "", "available": [],
            "build": _first(r"OS build\s+(\d+)", t), "kernel": _first(r"OS kernel version\s+(\S+)", t),
            "notes": "o Check Point não publica versões disponíveis por esta via: use a política de versões e o aviso do fabricante (Jumbo Hotfix)"}


def parse_cisco_ios(raw: dict) -> dict:
    t = _clip(raw.get("version"))
    v = _first(r"Cisco IOS(?: XE)? Software.*?Version\s+([\w.()\-]+)", t, re.I | re.S) or _first(r"^\s*Version\s+([\w.()\-]+)", t)
    m = _first(r"Model [Nn]umber\s*:\s*(\S+)", t) or _first(r"^[Cc]isco\s+(\S+)\s+\(.*?\)\s+processor", t)
    return {"version": v.rstrip(","), "model": m, "hostname": _first(r"^(\S+)\s+uptime is", t), "serial": _first(r"System [Ss]erial [Nn]umber\s*:\s*(\S+)", t), "available": [],
            "notes": "a Cisco só publica software com contrato: use a política de versões e os avisos de segurança (PSIRT)"}


def parse_cisco_nxos(raw: dict) -> dict:
    t = _clip(raw.get("version"))
    return {"version": _first(r"(?:NXOS|system):\s+version\s+([\w.()\-]+)", t), "model": _first(r"^\s*cisco\s+(Nexus\S*\s+\S+)", t), "hostname": _first(r"Device name:\s*(\S+)", t),
            "serial": _first(r"Processor Board ID\s+(\S+)", t), "available": [], "notes": "use a política de versões e os avisos de segurança da Cisco (PSIRT)"}


def parse_junos(raw: dict) -> dict:
    t = _clip(raw.get("version"))
    return {"version": _first(r"^\s*Junos:\s*(\S+)", t) or _first(r"JUNOS [\w ]+\[([\w.\-]+)\]", t), "model": _first(r"^\s*Model:\s*(\S+)", t),
            "hostname": _first(r"^\s*Hostname:\s*(\S+)", t), "serial": "", "available": [], "notes": "use a política de versões e os avisos de segurança da Juniper (JSA)"}


def parse_eos(raw: dict) -> dict:
    t = _clip(raw.get("version"))
    return {"version": _first(r"Software image version:\s*(\S+)", t), "model": _first(r"^\s*Arista\s+(\S+)", t), "hostname": "", "serial": _first(r"Serial number:\s*(\S+)", t),
            "available": [], "notes": "use a política de versões e os avisos de segurança da Arista"}


PARSERS = {"fortios": parse_fortios, "panos": parse_panos, "checkpoint": parse_checkpoint, "cisco_ios": parse_cisco_ios, "cisco_nxos": parse_cisco_nxos,
           "junos": parse_junos, "eos": parse_eos}


# --------------------------------------------------------------------------- avaliação


def _train(v: str) -> tuple:
    nums = re.findall(r"\d+", v or "")
    return tuple(nums[:2])


def best_baseline(tenant_id: int, platform: str, model: str) -> NetBaseline | None:
    rows = NetBaseline.query.filter_by(tenant_id=tenant_id, platform=platform).all()
    hits = [r for r in rows if fnmatch.fnmatch((model or "").lower(), (r.model_glob or "*").lower())]
    return max(hits, key=lambda r: len((r.model_glob or "*").replace("*", "").replace("?", "")), default=None)


def cve_matches(platform: str, version: str, limit: int = 20) -> list[str]:
    from . import correlate
    hints = CVE_HINTS.get(platform, [])
    if not hints or not version:
        return []
    found = []
    for c in CveIntel.query.order_by(CveIntel.cvss.desc().nullslast()).limit(5000):
        for e in c.affected_list:
            key = ((e.get("vendor") or "").lower().replace(" ", "_"), (e.get("product") or "").lower().replace(" ", "_"))
            if any(key[0] == v and key[1] == p for v, p in hints) and correlate.entry_affects(version, e):
                found.append(c.cve_id)
                break
        if len(found) >= limit:
            break
    return found


def evaluate(tenant_id: int, platform: str, facts: dict) -> dict:
    """Veredicto + recomendação + motivos a partir dos factos extraídos."""
    version, model = facts.get("version", ""), facts.get("model", "")
    reasons, verdict, recommended = [], "unknown", ""
    if not version:
        return {"verdict": "unknown", "recommended": "", "reasons": ["Não foi possível ler a versão do equipamento (credenciais, permissões ou formato de saída)."], "cves": [], "available_newer": []}
    avail = [a for a in facts.get("available", []) if versions.compare(a, version) > 0]
    same_train = sorted([a for a in avail if _train(a) == _train(version)], key=lambda a: [t for t in re.findall(r"\d+", a)])
    newer = sorted(avail, key=lambda a: [int(t) for t in re.findall(r"\d+", a)])
    bl = best_baseline(tenant_id, platform, model)
    cves = cve_matches(platform, version)
    verdict = "current"
    if avail:
        verdict = "update"
        recommended = same_train[-1] if same_train else newer[-1]
        reasons.append(f"O equipamento indica {len(avail)} versão(ões) mais recente(s); mesma linha: {same_train[-1] if same_train else 'nenhuma'}.")
    if bl:
        if bl.recommended and versions.compare(bl.recommended, version) > 0:
            verdict = "update" if verdict == "current" else verdict
            recommended = bl.recommended
            reasons.append(f"Política: versão recomendada {bl.recommended}.")
        if bl.min_version and versions.compare(version, bl.min_version) < 0:
            verdict = "below_min"
            reasons.append(f"Abaixo do mínimo da política ({bl.min_version}).")
        if bl.eol_below and versions.compare(version, bl.eol_below) < 0:
            verdict = "eol"
            reasons.append(f"Versão em fim de suporte (anterior a {bl.eol_below}).")
    elif not avail:
        reasons.append("Sem política de versões definida para esta plataforma/modelo nem versões disponíveis indicadas pelo equipamento: defina a política em «Avaliação de rede».")
        verdict = "unknown" if not cves else verdict
    if cves and verdict not in ("eol",):
        verdict = "vulnerable" if verdict in ("current", "unknown") else verdict
        reasons.append(f"{len(cves)} CVE conhecidos afetam esta versão (correspondência aproximada: confirme no aviso do fabricante).")
    if verdict == "current":
        reasons.append("Sem versões mais recentes indicadas e dentro da política.")
    return {"verdict": verdict, "recommended": recommended, "reasons": reasons, "cves": cves, "available_newer": newer[-10:]}


def process(task: Task, report: dict) -> NetworkAssessment | None:
    """Recebe o resultado do playbook ``net_assess.yml``, extrai, avalia e grava."""
    asset = task.asset
    platform = (report.get("platform") or asset.platform or "")
    parser = PARSERS.get(platform)
    if parser is None or report.get("status") != "succeeded":
        return None
    facts = parser(report.get("raw") or {})
    ev = evaluate(task.tenant_id, platform, facts)
    row = NetworkAssessment(tenant_id=task.tenant_id, asset_id=asset.id, task_id=task.id, assessed_at=utcnow(), platform=platform,
                            model=(facts.get("model") or "")[:120], version=(facts.get("version") or "")[:120], verdict=ev["verdict"], recommended=ev["recommended"][:120],
                            detail=json.dumps({"reasons": ev["reasons"], "cves": ev["cves"], "available_newer": ev["available_newer"], "hostname": facts.get("hostname", ""),
                                               "serial": facts.get("serial", ""), "notes": facts.get("notes", "")}))
    db.session.add(row)
    if facts.get("version"):                                   # o ativo passa a ter a versão real no inventário
        asset.os_name = {"fortios": "FortiOS", "panos": "PAN-OS", "checkpoint": "Check Point Gaia", "cisco_ios": "Cisco IOS", "cisco_nxos": "NX-OS", "junos": "Junos", "eos": "Arista EOS"}[platform]
        asset.os_version = facts["version"][:120]
        asset.kind = "network"
    return row
