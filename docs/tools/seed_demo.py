"""Dados de demonstração para o manual e para formação (organização «Oramix Demo»). Uso: OMXPATCH_DATA_DIR=/tmp/demo python docs/tools/seed_demo.py"""
from __future__ import annotations

import json
import random
import sys
import time
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import omxpatch.models as m  # noqa: E402

m.PASSWORD_HASH_METHOD = "pbkdf2:sha256:1000"
from omxpatch.app import create_app  # noqa: E402
from omxpatch.engine import baseline, correlate, plans, updates  # noqa: E402
from omxpatch.extensions import db  # noqa: E402
from omxpatch.models import (Agent, Asset, AssetSoftware, AutonomousRun, ControlAction, CveIntel, Exposure, Patch, Signal, Tenant, User, Validation, utcnow)  # noqa: E402
from omxpatch.web.api import new_enrollment_token  # noqa: E402

PASSWORD = "Demo-Passw0rd!2026"
random.seed(7)


def ctx(listeners, procs, fw_enabled=True, deny=True, ssh=None, extra_access=None):
    return {"collected_at": int(time.time()), "collect_ms": 31, "platform": "linux", "processes": [{"pid": i + 1, "name": n} for i, n in enumerate(procs)],
            "services": [{"name": n, "state": "running"} for n in procs], "listeners": listeners,
            "firewall": {"engine": "ufw", "enabled": fw_enabled, "default_in": "deny" if deny else "accept", "default_out": "allow", "allow_in_ports": [22, 443]},
            "access": {"admins": ["alice", "ops"], "ssh": ssh or {"permit_root_login": "no", "password_auth": "no", "port": 22}, **(extra_access or {})}, "security": {}, "errors": []}


def L(port, scope, proc):
    return {"port": port, "address": "0.0.0.0" if scope == "all" else "127.0.0.1", "scope": scope, "proto": "tcp", "process": proc}


def main() -> None:
    app = create_app({"TESTING": False, "KEV_ENABLED": False, "NVD_ENABLED": False, "EPSS_ENABLED": False, "MITRE_ENABLED": False, "ANSIBLE_ENABLED": False, "TLS_ENABLED": False},
                     start_worker=False)
    with app.app_context():
        t = Tenant(name="Oramix Demo", slug="demo", default_country="PT")
        db.session.add(t)
        db.session.flush()
        for email, role, sa in (("admin@oramix.example", "admin", False), ("operador@oramix.example", "user", False), ("auditor@oramix.example", "auditor", False), ("root@oramix.example", "admin", True)):
            u = User(email=email, tenant_id=None if sa else t.id, role=role, is_superadmin=sa)
            u.set_password(PASSWORD)
            db.session.add(u)
        cves = [("CVE-2026-1001", 9.8, True, 0.62, "weaponized", "OpenSSL", "openssl"), ("CVE-2026-1002", 8.1, False, 0.12, "poc", "nginx", "nginx"), ("CVE-2026-1003", 9.1, True, 0.41, "functional", "Apache", "httpd"),
                ("CVE-2026-1004", 7.5, False, 0.05, "none", "MySQL", "mysql"), ("CVE-2026-1005", 6.5, False, 0.02, "none", "curl", "curl")]
        for cid, cvss, kev, epss, mat, vendor, prod in cves:
            row = CveIntel(cve_id=cid, cvss=cvss, kev=kev, epss=epss, exploit_maturity=mat, description=f"Vulnerabilidade de demonstração em {vendor}.", published=utcnow() - timedelta(days=9),
                           cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", ransomware=cid == "CVE-2026-1001")
            row.affected = json.dumps([{"vendor": vendor.lower(), "product": prod, "end_excl": "9.9", "fixed": "9.9"}])
            row.advisories = json.dumps([{"vendor": vendor, "product": prod, "fixed_version": "9.9", "os_family": "linux", "package": prod, "installer": "apt"}])
            db.session.add(row)
        db.session.flush()
        spec = [("srv-web-01", "linux", "10.0.1.11", "high", 90, [("openssl", "3.0.1"), ("nginx", "1.18.0")], ctx([L(443, "all", "nginx"), L(22, "all", "sshd")], ["nginx", "sshd"], ssh={"permit_root_login": "yes", "password_auth": "yes", "port": 22})),
                ("srv-web-02", "linux", "10.0.1.12", "high", 85, [("openssl", "3.0.1"), ("httpd", "2.4.50")], ctx([L(443, "all", "httpd")], ["httpd", "sshd"])),
                ("srv-db-01", "linux", "10.0.2.21", "critical", 100, [("mysql", "8.0.30"), ("openssl", "3.0.1")], ctx([L(3306, "loopback", "mysqld"), L(22, "all", "sshd")], ["mysqld", "sshd"])),
                ("srv-app-01", "linux", "10.0.2.31", "medium", 60, [("curl", "7.81.0"), ("openssl", "3.0.1")], ctx([L(8080, "all", "java")], ["java", "sshd"], fw_enabled=False, deny=False)),
                ("srv-win-01", "windows", "10.0.3.41", "high", 80, [("Microsoft SQL Server", "2019")], None), ("pc-fin-01", "windows", "10.0.4.51", "medium", 50, [("Google Chrome", "125.0")], None),
                ("pc-rh-01", "windows", "10.0.4.52", "low", 30, [("7-Zip", "23.01")], None), ("mac-dev-01", "macos", "10.0.5.61", "low", 20, [("openssl@3", "3.3.0")], None)]
        rings = [0, 1, 1, 2, 2, 3, 3, 4]
        raw, tok = new_enrollment_token(t, "demo")
        for i, (name, fam, ip, crit, bv, sw, c) in enumerate(spec):
            a = Asset(tenant_id=t.id, uid=name, name=name, ip=ip, os_family=fam, os_name={"linux": "Ubuntu 24.04", "windows": "Windows Server 2022" if "srv" in name else "Windows 11", "macos": "macOS 14.5"}[fam],
                      criticality=crit, business_value=bv, managed=True, source="agent", owner="ops@oramix.example", ring=rings[i], kind="server" if "srv" in name else "workstation",
                      hardware=json.dumps({"context": c, "webservers": [{"type": "nginx"}] if name == "srv-web-01" else ([{"type": "apache"}] if name == "srv-web-02" else []), "agent_runtime": {"python": "3.12.3" if fam == "linux" else "3.8.10", "level": "ok" if fam == "linux" else "legacy"}}))
            db.session.add(a)
            db.session.flush()
            for n, v in sw:
                db.session.add(AssetSoftware(tenant_id=t.id, asset_id=a.id, name=n, version=v))
            db.session.add(Agent(tenant_id=t.id, asset_id=a.id, key_hash=f"demo{i}", key_prefix="omxa_demo", hostname=name, os_family=fam, version="1.16.20261109",
                                 last_seen=utcnow() - timedelta(minutes=3 if i != 7 else 400)))
        db.session.flush()
        for a in Asset.query.filter_by(tenant_id=t.id):
            correlate.correlate_asset(t, a)
        # patches aprovados e ligação
        for p in Patch.query.filter_by(tenant_id=t.id):
            p.status, p.severity = "approved", "high"
        db.session.commit()
        # atualizações descobertas (usa o caminho real de ingestão)
        web = Asset.query.filter_by(name="srv-web-01").one()
        ag = Agent.query.filter_by(asset_id=web.id).one()
        items = [{"uid": f"{n}={v}", "source": "apt", "name": n, "title": f"{n} {v}", "current_version": "1.0", "new_version": v, "severity": s, "category": c, "installer": "apt", "package": n,
                  "size_bytes": sz, "reboot": n.startswith("linux"), "download_url": f"http://archive.ubuntu.com/ubuntu/pool/main/{n[0]}/{n}/{n}_{v}_amd64.deb", "sha256": ("%064x" % (abs(hash(n)) % 16 ** 63))}
                 for n, v, s, c, sz in (("openssl", "3.0.13-0ubuntu3.5", "high", "security", 1_900_000), ("libc6", "2.39-0ubuntu8.3", "high", "security", 3_300_000), ("nginx", "1.24.0-2ubuntu7.1", "high", "security", 600_000),
                                        ("curl", "8.5.0-2ubuntu10.5", "medium", "security", 250_000), ("linux-image-6.8.0-50-generic", "6.8.0-50.51", "medium", "update", 14_000_000), ("tzdata", "2024b-0ubuntu0.24.04", "low", "update", 270_000))]
        updates.ingest(t, ag, web, {"scan_id": "demo-scan-1", "scanned_at": time.time(), "sources": {"apt": {"ok": True, "count": len(items)}}, "updates": items})
        # simula alguns já no servidor
        for au in updates.AvailableUpdate.query.filter(updates.AvailableUpdate.name.in_(("openssl", "nginx", "curl"))):
            au.status = "downloaded"
            au.patch.local_file, au.patch.status = f"{au.patch_id}-{au.name}.deb", "approved"
        # plano simulado a aguardar OK e um concluído
        ex = Exposure.query.filter(Exposure.asset_id == web.id).first()
        p1 = Patch.query.filter_by(tenant_id=t.id).first()
        plan = plans.create(t, "Rápido: openssl", "by_patch", [web.id], [p1.id], [])
        for it in plan.items:
            plans._set_sim(it, "ready", [{"id": "applicability", "label": "Simulação (apt-get -s do ficheiro)", "status": "ok", "detail": "3.0.1 → 3.0.13"}],
                           [{"target": web.name, "kind": "instalar patch", "summary": "openssl 3.0.1 → 3.0.13 · 1,9 MB", "diff": "", "reversible": False}], {"version_after": "3.0.13"})
        done = plans.create(t, "TLS 1.2/1.3 nos servidores web", "by_asset", [web.id], [], [{"id": "tls_protocols", "params": {}}])
        for it in done.items:
            it.status, it.sim_outcome, it.sim_at = "succeeded", "ready", utcnow()
            baseline.capture(it)
        done.status = "completed"
        db.session.add(BaselineItem := m.BaselineItem(tenant_id=t.id, scope="linux", kind="patch", name="openssl", installer="apt", min_version="3.0.13", cves='["CVE-2026-1001"]', note="de plano #1"))
        # controlo, validação, sinal, fluxo autónomo
        e1 = Exposure.query.filter_by(cve_id="CVE-2026-1001").first()
        if e1:
            db.session.add(ControlAction(tenant_id=t.id, cve_id=e1.cve_id, asset_id=e1.asset_id, exposure_id=e1.id, category="firewall", action="block_port", params='{"port": 443}', status="proposed", artifact="nft add rule inet filter input tcp dport 443 drop"))
            db.session.add(Validation(tenant_id=t.id, exposure_id=e1.id, asset_id=e1.asset_id, cve_id=e1.cve_id, status="passed", checks="{}"))
            db.session.add(Signal(tenant_id=t.id, source="defender", kind="edr_missed", cve_id=e1.cve_id, asset_id=e1.asset_id))
            db.session.add(AutonomousRun(tenant_id=t.id, cve_id=e1.cve_id, stage="test", status="approval", log="[x] simulação ok\n"))
        db.session.commit()
        for e in Exposure.query.filter_by(tenant_id=t.id):
            correlate.refresh(e, t)
        db.session.commit()
        print("demo pronta:", Asset.query.count(), "ativos,", Exposure.query.count(), "exposições,", updates.AvailableUpdate.query.count(), "atualizações; utilizadores: admin/operador/auditor/root @oramix.example /", PASSWORD)


if __name__ == "__main__":
    main()
