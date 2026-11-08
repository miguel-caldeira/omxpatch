"""Módulo 1 — Asset Discovery & Inventory (CMDB integrada).

* ``upsert_asset``: criação/atualização idempotente por ``uid``; cada alteração a um campo relevante fica em
  ``CmdbChange`` (histórico da CMDB) e o ativo deixa de ser *Shadow IT* quando passa a gerido.
* ``ingest_inventory``: relatório do agente (hardware, software, utilizador, portas, reboot pendente).
* ``sweep``: descoberta sem agente por ligação TCP (portas de gestão); IoT/OT só com ``probe_ot`` explícito
  e portas de protocolo apenas ligadas (sem payload), para não perturbar equipamentos industriais.
"""
from __future__ import annotations

import ipaddress
import json
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from ..extensions import db
from ..models import ASSET_KINDS, CRITICALITIES, Asset, AssetSoftware, CmdbChange, Tenant, utcnow

TRACKED = ("name", "fqdn", "ip", "os_name", "os_version", "primary_user", "owner", "criticality", "country", "city",
           "kind", "ring", "department", "cmdb_ref")
MGMT_PORTS = (22, 135, 445, 3389, 5985, 5986, 443, 80, 8443)
OT_PORTS = {502: ("ot", "Modbus/TCP"), 102: ("ot", "Siemens S7"), 20000: ("ot", "DNP3"), 44818: ("ot", "EtherNet/IP"),
            47808: ("ot", "BACnet"), 1883: ("iot", "MQTT"), 554: ("iot", "RTSP"), 5683: ("iot", "CoAP")}
MAX_SWEEP_HOSTS = 1024


def _norm_uid(uid: str) -> str:
    return (uid or "").strip().lower()[:190]


def guess_os_family(text: str) -> str:
    t = (text or "").lower()
    if "win" in t:
        return "windows"
    if "mac" in t or "darwin" in t or "os x" in t:
        return "macos"
    if any(k in t for k in ("linux", "ubuntu", "debian", "rhel", "red hat", "centos", "rocky", "alma", "suse", "fedora", "amazon")):
        return "linux"
    return ""


def upsert_asset(tenant: Tenant, data: dict, source: str = "manual") -> tuple[Asset, bool]:
    """Cria ou atualiza. Devolve (ativo, criado). ``data`` aceita os campos do modelo Asset."""
    uid = _norm_uid(data.get("uid") or data.get("name") or data.get("fqdn") or data.get("ip") or "")
    if not uid:
        raise ValueError("O ativo precisa de uid, nome, FQDN ou IP")
    asset = Asset.query.filter_by(tenant_id=tenant.id, uid=uid).first()
    created = asset is None
    if created:
        asset = Asset(tenant_id=tenant.id, uid=uid, name=(data.get("name") or uid)[:255], source=source,
                      country=tenant.default_country or "")
        db.session.add(asset)
        db.session.flush()
    changes = []
    for field in ("name", "fqdn", "ip", "mac", "kind", "os_family", "os_name", "os_version", "primary_user", "owner",
                  "department", "criticality", "internet_exposed", "country", "city", "cloud_provider", "cloud_id",
                  "cluster", "tags", "open_ports", "connection", "ansible_user", "maintenance_group", "cmdb_ref"):
        if field in data and data[field] not in (None, ""):
            value = data[field]
            if field == "kind" and value not in ASSET_KINDS:
                continue
            if field == "criticality" and value not in CRITICALITIES:
                continue
            if field == "ip" and value:
                try:
                    ipaddress.ip_address(str(value).strip())
                except ValueError:
                    continue
            if isinstance(value, str):
                value = value.strip()
            old = getattr(asset, field)
            if old != value:
                setattr(asset, field, value)
                if field in TRACKED and not created:
                    changes.append((field, str(old or ""), str(value)))
    for field in ("business_value", "ring", "ansible_port"):
        if data.get(field) not in (None, ""):
            try:
                setattr(asset, field, int(data[field]))
            except (TypeError, ValueError):
                pass
    for field in ("latitude", "longitude"):
        if data.get(field) not in (None, ""):
            try:
                setattr(asset, field, float(data[field]))
            except (TypeError, ValueError):
                pass
    if data.get("hardware"):
        hw = data["hardware"] if isinstance(data["hardware"], str) else json.dumps(data["hardware"])
        asset.hardware = hw
    if not asset.os_family:
        asset.os_family = guess_os_family(f"{asset.os_name} {asset.os_version}")
    if data.get("managed") is True or source == "agent":
        asset.managed = True
    elif created:
        asset.managed = bool(data.get("managed", False))
    asset.shadow_it = bool(data["shadow_it"]) if "shadow_it" in data else (asset.shadow_it and not asset.managed)
    if source == "agent":
        asset.source = "agent"
        asset.connection = "agent"
    asset.last_seen = utcnow()
    for field, old, new in changes:
        db.session.add(CmdbChange(tenant_id=tenant.id, asset_id=asset.id, field=field, old=old[:500], new=new[:500],
                                  source=source))
    asset.cmdb_synced_at = asset.cmdb_synced_at
    return asset, created


def set_software(asset: Asset, items: list[dict], source: str = "agent", replace: bool = True) -> dict:
    """Substitui (ou acrescenta) o inventário de software do ativo; devolve {added, removed, changed}."""
    now = utcnow()
    existing = {(s.name.lower(), s.version): s for s in asset.software}
    seen = set()
    added = 0
    for it in items:
        name = (it.get("name") or "").strip()[:255]
        if not name:
            continue
        version = str(it.get("version") or "").strip()[:120]
        key = (name.lower(), version)
        seen.add(key)
        row = existing.get(key)
        if row is None:
            db.session.add(AssetSoftware(tenant_id=asset.tenant_id, asset_id=asset.id, name=name, version=version,
                                         vendor=(it.get("vendor") or "")[:200], cpe=(it.get("cpe") or "")[:300],
                                         source=source, last_seen=now))
            added += 1
        else:
            row.last_seen = now
            if it.get("vendor"):
                row.vendor = it["vendor"][:200]
    removed = 0
    if replace:
        for key, row in existing.items():
            if key not in seen:
                db.session.delete(row)
                removed += 1
    if added or removed:
        db.session.add(CmdbChange(tenant_id=asset.tenant_id, asset_id=asset.id, field="software",
                                  old=f"-{removed}", new=f"+{added}", source=source))
    return {"added": added, "removed": removed}


def _clip(v, n=200):
    return str(v)[:n] if v is not None else ""


def sanitize_context(c: dict) -> dict:
    """O contexto vem de um agente (dados não confiáveis): limita tamanhos e tipos antes de o guardar."""
    def lst(key, n, fields):
        out = []
        for it in (c.get(key) or [])[:n]:
            if isinstance(it, dict):
                out.append({k: (it[k] if isinstance(it.get(k), (int, bool)) else _clip(it.get(k))) for k in fields if k in it})
        return out
    fw = c.get("firewall") if isinstance(c.get("firewall"), dict) else {}
    acc = c.get("access") if isinstance(c.get("access"), dict) else {}
    sec = c.get("security") if isinstance(c.get("security"), dict) else {}
    ssh = acc.get("ssh") if isinstance(acc.get("ssh"), dict) else {}
    return {"collected_at": int(c.get("collected_at") or 0), "collect_ms": int(c.get("collect_ms") or 0), "platform": _clip(c.get("platform"), 16),
            "processes": lst("processes", 300, ("pid", "name", "uid", "exe")), "services": lst("services", 300, ("name", "state")),
            "listeners": [{**l, "port": int(l["port"])} for l in lst("listeners", 200, ("port", "address", "scope", "proto", "process", "pid", "exe")) if str(l.get("port", "")).isdigit()],
            "firewall": {"engine": _clip(fw.get("engine"), 24), "enabled": bool(fw.get("enabled")), "default_in": _clip(fw.get("default_in"), 12), "default_out": _clip(fw.get("default_out"), 12),
                         "allow_in_ports": [int(p) for p in (fw.get("allow_in_ports") or [])[:200] if str(p).isdigit()]},
            "access": {"admins": [_clip(a, 120) for a in (acc.get("admins") or [])[:100]], "ssh": {k: (ssh[k] if isinstance(ssh.get(k), int) else _clip(ssh.get(k), 40)) for k in ssh if k in ("permit_root_login", "password_auth", "port", "pubkey_auth", "permit_empty")},
                       **{k: bool(acc[k]) for k in ("rdp_enabled", "rdp_nla", "uac", "smb1") if k in acc}},
            "security": {k: (bool(v) if isinstance(v, bool) else _clip(v, 40)) for k, v in sec.items() if k in ("selinux", "apparmor", "defender_realtime", "defender_av", "sip")},
            "errors": [_clip(e) for e in (c.get("errors") or [])[:10]]}


def ingest_inventory(tenant: Tenant, asset: Asset, report: dict) -> dict:
    """Aplica um relatório de inventário do agente ao ativo."""
    data = {k: report.get(k) for k in ("fqdn", "ip", "mac", "os_name", "os_version", "os_family", "primary_user",
                                       "open_ports")}
    if isinstance(data.get("open_ports"), list):
        data["open_ports"] = ",".join(str(p) for p in sorted({int(p) for p in data["open_ports"] if str(p).isdigit()}))
    hw = dict(report.get("hardware") or {})
    if report.get("hotfixes"):
        hw["hotfixes"] = report["hotfixes"][:2000]        # KB instalados (Windows)
    if report.get("services"):
        hw["services"] = report["services"][:500]
    if isinstance(report.get("runtime"), dict):                  # interpretador Python do agente (antigo/moderno)
        rt = report["runtime"]
        hw["agent_runtime"] = {k: (v if isinstance(v, (bool, list)) else str(v)[:200]) for k, v in rt.items()
                               if k in ("python", "implementation", "openssl", "tls13", "tls_max", "level", "degraded", "platform", "machine")}
    if isinstance(report.get("context"), dict):                  # contexto do ativo (processos, escutas, firewall, acessos)
        hw["context"] = sanitize_context(report["context"])
    if report.get("webservers") is not None:
        hw["webservers"] = report["webservers"]               # nginx / Apache / IIS detetados (boas práticas)
    if report.get("capabilities"):
        hw["capabilities"] = report["capabilities"]          # origens de atualização utilizáveis (agente)
    if hw:
        data["hardware"] = hw
    data["uid"] = asset.uid
    asset_, _ = upsert_asset(tenant, data, source="agent")
    asset_.reboot_pending = bool(report.get("reboot_pending", False))
    if report.get("last_boot"):
        try:
            asset_.last_boot = datetime.fromisoformat(str(report["last_boot"]).replace("Z", "")[:19])
        except ValueError:
            pass
    sw = set_software(asset_, report.get("software") or [], source="agent")
    return sw


# --------------------------------------------------------------------------- descoberta sem agente


def parse_targets(spec: str) -> list[str]:
    hosts: list[str] = []
    for part in [p.strip() for p in spec.replace(",", "\n").splitlines() if p.strip()]:
        try:
            if "/" in part:
                net = ipaddress.ip_network(part, strict=False)
                hosts += [str(h) for h in net.hosts()]
            elif "-" in part and part.count(".") == 3:
                base, end = part.rsplit("-", 1)
                a = ipaddress.ip_address(base.strip())
                last = int(end)
                start = int(str(a).rsplit(".", 1)[1])
                prefix = str(a).rsplit(".", 1)[0]
                hosts += [f"{prefix}.{i}" for i in range(start, last + 1)]
            else:
                hosts.append(str(ipaddress.ip_address(part)))
        except ValueError:
            raise ValueError(f"Alvo inválido: {part}") from None
        if len(hosts) > MAX_SWEEP_HOSTS:
            raise ValueError(f"Intervalo demasiado grande (máx. {MAX_SWEEP_HOSTS} endereços por descoberta)")
    return hosts


def _probe(host: str, ports: tuple[int, ...], timeout: float) -> list[int]:
    open_ports = []
    for p in ports:
        try:
            with socket.create_connection((host, p), timeout=timeout):
                open_ports.append(p)
        except OSError:
            continue
    return open_ports


def classify(open_ports: list[int]) -> tuple[str, str]:
    """(tipo, família do SO provável) a partir das portas abertas."""
    for p in open_ports:
        if p in OT_PORTS:
            return OT_PORTS[p][0], ""
    if 3389 in open_ports or 445 in open_ports or 5985 in open_ports or 135 in open_ports:
        return "server" if 3389 not in open_ports else "workstation", "windows"
    if 22 in open_ports:
        return "server", "linux"
    return "other", ""


def sweep(tenant: Tenant, spec: str, probe_ot: bool = False, timeout: float = 0.6, workers: int = 64,
          prober=_probe) -> dict:
    """Descobre hosts por ligação TCP; novos ativos não geridos ficam marcados como Shadow IT."""
    hosts = parse_targets(spec)
    ports = MGMT_PORTS + (tuple(OT_PORTS) if probe_ot else ())
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(lambda h: (h, prober(h, ports, timeout)), hosts))
    found = new = shadow = 0
    for host, open_ports in results:
        if not open_ports:
            continue
        found += 1
        kind, fam = classify(open_ports)
        try:
            name = socket.gethostbyaddr(host)[0]
        except OSError:
            name = host
        existing = Asset.query.filter_by(tenant_id=tenant.id, ip=host).first()
        asset, created = upsert_asset(tenant, {"uid": existing.uid if existing else host, "name": name, "ip": host,
                                               "kind": kind, "os_family": fam, "open_ports": ",".join(map(str, open_ports)),
                                               "managed": False, "connection": "ansible"}, source="agentless")
        if created:
            new += 1
        if not asset.managed:
            asset.shadow_it = True
            shadow += 1
    db.session.commit()
    return {"scanned": len(hosts), "found": found, "new": new, "shadow_it": shadow}


def stats(tenant_id: int) -> dict:
    q = Asset.query.filter_by(tenant_id=tenant_id)
    total = q.count()
    return {"total": total, "managed": q.filter_by(managed=True).count(), "shadow_it": q.filter_by(shadow_it=True).count(),
            "by_os": {k: q.filter_by(os_family=k).count() for k in ("windows", "linux", "macos")},
            "by_kind": {k: n for k, n in db.session.query(Asset.kind, db.func.count(Asset.id))
                        .filter(Asset.tenant_id == tenant_id).group_by(Asset.kind).all()}}
