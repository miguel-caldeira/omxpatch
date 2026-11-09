"""Descoberta de atualizações instaláveis: agente → consola (com confirmação), descarga proativa verificada, simulação e remediação."""
import hashlib
import http.server
import json
import socket
import threading
import time

import pytest

from omxpatch.engine import patches as patches_engine, plans, updates
from omxpatch.extensions import db
from omxpatch.models import Agent, Asset, AvailableUpdate, Exposure, OperationPlan, Patch, PlanItem, Task, UpdateScan, utcnow
from omxpatch_agent import updates as agent_updates
from omxpatch_agent.updates import linux as ulin, macos as umac, sync as usync, windows as uwin
from tests.conftest import login_as, make_asset, make_cve
from tests.test_flow import FakeAgent, enroll_token  # noqa: F401


# ------------------------------------------------------------------ agente: analisadores (saídas reais/representativas)

APT_SIM = """Inst libapt-pkg6.0t64 [2.8.3] (2.8.4ubuntu0.1 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst apt [2.8.3] (2.8.4ubuntu0.1 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst linux-image-6.8.0-50-generic (6.8.0-50.51 Ubuntu:24.04/noble-updates [amd64])
Inst docker-ce [5:29.9.2-1~ubuntu.24.04~noble] (5:29.9.3-1~ubuntu.24.04~noble Docker CE:noble [amd64])
Conf apt (2.8.4ubuntu0.1 Ubuntu:24.04/noble-updates [amd64])
"""
APT_URIS = """'http://archive.ubuntu.com/ubuntu/pool/main/a/apt/apt_2.8.4ubuntu0.1_amd64.deb' apt_2.8.4ubuntu0.1_amd64.deb 1396574 SHA256:ad2ea7f1
'https://download.docker.com/linux/ubuntu/dists/noble/pool/stable/amd64/docker-ce_29.9.3-1%7eubuntu.24.04%7enoble_amd64.deb' docker-ce_5%3a29.9.3-1~ubuntu.24.04~noble_amd64.deb 24586336 MD5Sum:e08ec096
"""
APT_SHOW = """Package: apt
Version: 2.8.4ubuntu0.1
Size: 1396574
Filename: pool/main/a/apt/apt_2.8.4ubuntu0.1_amd64.deb
SHA256: AD2EA7F107F250BA88B0BFDBA31812A341E3247589647AAE2CE0A1AD29D1ABF8

Package: docker-ce
Version: 5:29.9.3-1~ubuntu.24.04~noble
Size: 24586336
SHA256: c546181f0bc5f1d19085d764a3219aa86069468dbee4743fae420ee8a31809a4
"""


def test_parse_apt_outputs():
    inst = ulin.parse_apt_inst(APT_SIM)
    assert [i["name"] for i in inst] == ["libapt-pkg6.0t64", "apt", "linux-image-6.8.0-50-generic", "docker-ce"]
    assert inst[1] == {"name": "apt", "old": "2.8.3", "new": "2.8.4ubuntu0.1", "origin": "Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security"}
    assert inst[2]["old"] == "" and "security" not in inst[2]["origin"]
    uris = ulin.parse_print_uris(APT_URIS)
    assert uris["docker-ce_5:29.9.3-1~ubuntu.24.04~noble_amd64.deb"]["hash_type"] == "md5sum"
    assert uris["apt_2.8.4ubuntu0.1_amd64.deb"]["size"] == 1396574
    shown = ulin.parse_apt_show(APT_SHOW)
    assert shown[("apt", "2.8.4ubuntu0.1")]["sha256"].startswith("ad2ea7f1") and shown[("docker-ce", "5:29.9.3-1~ubuntu.24.04~noble")]["size"] == 24586336


def test_apt_scan_builds_items_with_signed_index_hash(monkeypatch):
    from omxpatch_agent.runner import Result
    monkeypatch.setattr(ulin.shutil, "which", lambda n: "/usr/bin/" + n)

    def run(cmd, timeout=60, **k):
        if cmd[:2] == ["apt-get", "-s"]:
            return Result(0, APT_SIM)
        if "--print-uris" in cmd:
            return Result(0, APT_URIS)
        if cmd[0] == "apt-cache":
            return Result(0, APT_SHOW)
        return Result(0, "")
    monkeypatch.setattr(ulin, "run", run)
    items, note = ulin.scan_apt(refresh=False)
    by = {i["name"]: i for i in items}
    assert by["apt"]["severity"] == "high" and by["apt"]["category"] == "security" and by["apt"]["sha256"].startswith("ad2ea7f1")
    assert by["apt"]["download_url"].startswith("http://archive.ubuntu.com") and by["apt"]["size_bytes"] == 1396574
    assert by["docker-ce"]["sha256"].startswith("c546181f") and by["docker-ce"]["download_url"].startswith("https://download.docker.com")   # hash do índice, não o MD5 do print-uris
    assert by["linux-image-6.8.0-50-generic"]["reboot"] and by["linux-image-6.8.0-50-generic"]["sha256"] == "" and by["linux-image-6.8.0-50-generic"]["download_url"] == ""
    assert "1 de segurança" not in note and "2 de segurança" in note


def test_parse_dnf_zypper_choco_brew_softwareupdate_winget():
    dnf = ulin.parse_dnf_check_update("\nopenssl.x86_64     1:3.0.7-28.el9     baseos\nkernel.x86_64   5.14.0-427.el9  baseos\nObsoleting Packages\n")
    assert [(p["name"], p["arch"], p["new"]) for p in dnf] == [("openssl", "x86_64", "1:3.0.7-28.el9"), ("kernel", "x86_64", "5.14.0-427.el9")]
    info = ulin.parse_dnf_updateinfo("RHSA-2024:1234 Important/Sec. openssl-1:3.0.7-28.el9.x86_64.rpm\nRHBA-2024:9 bugfix tzdata-2024a-1.el9.noarch.rpm\n")
    assert info["openssl"] == {"advisory": "RHSA-2024:1234", "severity": "high", "security": True} and info["tzdata"]["security"] is False
    z = ulin.parse_zypper_lu("S | Repository | Name | Current Version | Available Version | Arch\n--+------+------+----+----+---\nv | Update | curl | 8.0-1 | 8.0-2 | x86_64\n")
    assert z == [{"name": "curl", "old": "8.0-1", "new": "8.0-2", "repo": "Update", "arch": "x86_64"}]
    assert uwin.parse_choco_outdated("Chocolatey v2\nvlc|3.0.20|3.0.21|false\nopenssl|3.1|3.2|true\n") == [{"name": "vlc", "current": "3.0.20", "new": "3.0.21"}]
    su = umac.parse_softwareupdate("Software Update found:\n* Label: macOS Sonoma 14.5-23F79\n\tTitle: macOS Sonoma 14.5, Version: 14.5, Size: 1500000K, Recommended: YES, Action: restart,\n* Label: Safari17.5\n\tTitle: Safari, Version: 17.5, Size: 120000K, Recommended: YES,\n")
    assert su[0]["label"] == "macOS Sonoma 14.5-23F79" and su[0]["restart"] and su[0]["size_kb"] == 1500000 and su[1]["label"] == "Safari17.5" and not su[1]["restart"]
    brew = umac.parse_brew_outdated('{"formulae":[{"name":"openssl@3","installed_versions":["3.3.0"],"current_version":"3.3.1"}],"casks":[{"name":"firefox","installed_versions":["126"],"current_version":"127"}]}')
    assert [(b["name"], b["current"], b["new"]) for b in brew] == [("openssl@3", "3.3.0", "3.3.1"), ("firefox", "126", "127")]
    wg = uwin.parse_winget_upgrade("Name           Id               Version   Available  Source\n-------------------------------------------------------\nGoogle Chrome  Google.Chrome    125.0.1   126.0.2    winget\nZoom           Zoom.Zoom        5.17.0    5.18.1     winget\n2 upgrades available.\n")
    assert [(w["id"], w["current"], w["new"]) for w in wg] == [("Google.Chrome", "125.0.1", "126.0.2"), ("Zoom.Zoom", "5.17.0", "5.18.1")]
    sh = uwin.parse_winget_show("Found Google Chrome [Google.Chrome]\nInstaller:\n  Installer Type: wix\n  Installer Url: https://dl.google.com/chrome.msi\n  Installer SHA256: " + "ab" * 32 + "\n")
    assert sh == {"url": "https://dl.google.com/chrome.msi", "sha256": "ab" * 32, "installer": "msi", "silent_args": "/qn /norestart"}
    assert uwin.parse_winget_show("Installer Type: inno\nInstaller Url: https://x/y.exe\nInstaller SHA256: " + "cd" * 32)["silent_args"].startswith("/VERYSILENT")


def test_parse_wua_json():
    js = json.dumps([{"id": "g1", "rev": 200, "title": "2024-05 Cumulative Update for Windows Server 2019 (KB5037765)", "kb": "5037765", "severity": "Critical", "cves": ["CVE-2024-30051", "bad"],
                      "size": 123456789, "reboot": True, "eula": True, "categories": ["Security Updates", "Windows Server 2019"], "urls": ["https://catalog.s.download.windowsupdate.com/x.msu", "ftp://x"]},
                     {"id": "g2", "title": "Driver", "kb": "", "severity": "", "cves": [], "size": 10, "reboot": False, "eula": False, "categories": ["Drivers"], "urls": []}])
    a, b = uwin.parse_wua_json(js)
    assert a["uid"] == "KB5037765" and a["severity"] == "critical" and a["category"] == "security" and a["cves"] == ["CVE-2024-30051"] and a["reboot"]
    assert a["download_url"].startswith("https://catalog") and a["installer"] == "wua" and b["uid"] == "g2" and b["eula_pending"] and b["category"] == "update"
    assert uwin.parse_wua_json("") == []


def test_real_discovery_on_this_host_returns_valid_items():
    r = agent_updates.discover(refresh=False)
    assert r["scan_id"] and r["platform"] == "linux" and isinstance(r["sources"], dict)
    for u in r["updates"]:
        assert u["source"] and u["uid"] and u["new_version"] and u["severity"] in ("low", "medium", "high", "critical")
        assert not u["sha256"] or len(u["sha256"]) == 64


# ------------------------------------------------------------------ agente → consola: entrega garantida


def _report(items, sources=None, scan_id="scan-1"):
    return {"scan_id": scan_id, "scanned_at": time.time(), "platform": "linux", "sources": sources or {"apt": {"ok": True, "count": len(items)}}, "updates": items}


def _item(name="openssl", new="3.0.13-1", sha="", url="", **kw):
    return {"uid": f"{name}={new}", "source": "apt", "name": name, "title": f"{name} {new}", "current_version": "3.0.1", "new_version": new, "severity": "high",
            "category": "security", "installer": "apt", "package": name, "download_url": url, "sha256": sha, "size_bytes": 1000, "reboot": False, **kw}


def test_ingest_stores_confirms_and_is_idempotent(app, tenant, enroll_token):
    ag = FakeAgent(app, enroll_token, "srv1")
    rep = _report([_item(), _item("curl", "8.5-1", cves=["CVE-2026-1111"])])
    r = ag.c.post("/agent/v1/updates", headers=ag.h, json=rep)
    assert r.status_code == 200 and r.get_json()["ok"] and r.get_json()["received"] == 2 and r.get_json()["new"] == 2
    assert AvailableUpdate.query.count() == 2 and UpdateScan.query.one().total == 2
    a = Asset.query.filter_by(name="srv1").one()
    assert a.hw["updates"]["total"] == 2 and Patch.query.count() == 2 and Patch.query.filter_by(product="curl").one().cve_list == ["CVE-2026-1111"]
    again = ag.c.post("/agent/v1/updates", headers=ag.h, json=rep).get_json()
    assert again["duplicate"] and AvailableUpdate.query.count() == 2 and UpdateScan.query.count() == 1             # reenvio não duplica
    assert ag.c.post("/agent/v1/updates", headers=ag.h, json={"scan_id": "x"}).status_code == 400
    assert ag.c.post("/agent/v1/updates", headers={}, json=rep).status_code == 401


def test_ingest_reconciles_only_complete_sources_and_validates_input(app, tenant, enroll_token):
    ag = FakeAgent(app, enroll_token, "srv1")
    ag.c.post("/agent/v1/updates", headers=ag.h, json=_report([_item("a"), _item("b")], scan_id="s1"))
    # origem falhou: nada é dado como instalado
    r = ag.c.post("/agent/v1/updates", headers=ag.h, json=_report([], {"apt": {"ok": False, "error": "lock"}}, "s2")).get_json()
    assert r["resolved"] == 0 and AvailableUpdate.query.filter_by(status="discovered").count() == 2
    # origem completa sem «a»: «a» foi instalada
    r = ag.c.post("/agent/v1/updates", headers=ag.h, json=_report([_item("b")], scan_id="s3")).get_json()
    assert r["resolved"] == 1 and AvailableUpdate.query.filter_by(name="a").one().status == "installed"
    ag.c.post("/agent/v1/updates", headers=ag.h, json=_report([_item("a"), _item("b")], scan_id="s4"))              # reapareceu
    assert AvailableUpdate.query.filter_by(name="a").one().status == "discovered"
    bad = _report([_item("c", sha="xyz", url="file:///etc/passwd", severity="weird", cves=["nope", "CVE-2026-0001"]), {"uid": "", "source": ""}, "lixo"], scan_id="s5")
    ag.c.post("/agent/v1/updates", headers=ag.h, json=bad)
    c = AvailableUpdate.query.filter_by(name="c").one()
    assert c.sha256 == "" and c.download_url == "" and c.severity == "medium" and c.cve_list == ["CVE-2026-0001"]     # entrada saneada


def test_ingest_links_patch_to_exposures_by_cve_and_by_package(app, tenant, enroll_token):
    ag = FakeAgent(app, enroll_token, "srv1")
    a = Asset.query.filter_by(name="srv1").one()
    make_cve("CVE-2026-0001")
    db.session.add_all([Exposure(tenant_id=tenant.id, asset_id=a.id, cve_id="CVE-2026-0001", software_name="OpenSSL", installed_version="1.1.1k", fixed_version="1.1.1w", status="open"),
                        Exposure(tenant_id=tenant.id, asset_id=a.id, cve_id="CVE-2026-0002", software_name="curl", installed_version="7.0", fixed_version="8.0", status="open")])
    db.session.commit()
    ag.c.post("/agent/v1/updates", headers=ag.h, json=_report([_item("openssl", "1.1.1w-1", cves=["CVE-2026-0001"]), _item("curl", "8.5-1")]))
    ex1, ex2 = Exposure.query.order_by(Exposure.id).all()
    assert ex1.patch_available and ex1.patch.product == "openssl" and ex2.patch_available and ex2.patch.product == "curl"
    assert "CVE-2026-0002" in ex2.patch.cve_list                                                                    # o patch passa a conhecer o CVE


# ------------------------------------------------------------------ cliente do agente: store-and-forward


def test_agent_keeps_report_until_console_confirms(tmp_path, monkeypatch):
    monkeypatch.setattr(usync.config, "config_dir", lambda: tmp_path)
    monkeypatch.setattr(agent_updates, "discover", lambda refresh=True: _report([_item()], scan_id="sf-1"))

    class Down:
        def updates(self, report):
            raise OSError("consola em baixo")

    class Up:
        got = []

        def updates(self, report):
            Up.got.append(report["scan_id"])
            return {"ok": True, "received": len(report["updates"])}
    r = usync.run_and_upload(Down(), force=True)
    assert r["scanned"] and not r["sent"] and (tmp_path / "updates_pending.json").exists()            # fica guardado
    r = usync.run_and_upload(Up(), hours=6)
    assert r["sent"] and Up.got == ["sf-1"] and not (tmp_path / "updates_pending.json").exists()      # reenviado sem novo varrimento
    assert not usync.due(6) and usync.due(0.0000001)
    assert usync.run_and_upload(Up(), hours=6)["scanned"] is False                                  # ainda não é altura


def test_server_requested_scan_runs_through_task(app, tenant, enroll_token, monkeypatch, tmp_path):
    ag = FakeAgent(app, enroll_token, "srv1")
    a = Asset.query.filter_by(name="srv1").one()
    assert updates.request_scan(tenant) == 1 and updates.request_scan(tenant) == 0                 # não duplica
    db.session.commit()
    (t,) = [x for x in ag.poll() if x["type"] == "update_scan"]
    from omxpatch_agent import executor
    monkeypatch.setattr(usync.config, "config_dir", lambda: tmp_path)
    monkeypatch.setattr(agent_updates, "discover", lambda refresh=True: _report([_item()], scan_id="task-1"))

    class C:
        def updates(self, report):
            r = ag.c.post("/agent/v1/updates", headers=ag.h, json=report)
            return r.get_json()
    res = executor.HANDLERS["update_scan"](C(), t)
    assert res["status"] == "succeeded" and "confirmadas" in res["output"]
    assert AvailableUpdate.query.filter_by(asset_id=a.id).count() == 1


# ------------------------------------------------------------------ descarga proativa para o servidor


@pytest.fixture()
def mirror(app):
    """Espelho HTTP local (loopback) com dois pacotes."""
    files = {"/pool/ok_1.0_amd64.deb": b"DEB-OK-" * 5000, "/pool/bad_1.0_amd64.deb": b"CONTEUDO-ADULTERADO" * 100, "/pool/big_1.0_amd64.deb": b"B" * 3_000_000}
    hits = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            if self.path == "/redir":
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/latest/meta-data")
                self.end_headers()
                return
            body = files.get(self.path)
            if body is None:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    app.config["ALLOW_LOOPBACK_OUTBOUND"] = True
    yield {"base": f"http://127.0.0.1:{srv.server_address[1]}", "files": files, "hits": hits}
    srv.shutdown()


def test_proactive_download_verifies_hash_and_stores_in_repository(app, tenant, enroll_token, mirror):
    ag = FakeAgent(app, enroll_token, "srv1")
    ok = mirror["files"]["/pool/ok_1.0_amd64.deb"]
    sha = hashlib.sha256(ok).hexdigest()
    ag.c.post("/agent/v1/updates", headers=ag.h, json=_report([
        _item("ok", "1.0", sha=sha, url=mirror["base"] + "/pool/ok_1.0_amd64.deb"),
        _item("bad", "1.0", sha="0" * 64, url=mirror["base"] + "/pool/bad_1.0_amd64.deb"),
        _item("nohash", "1.0", url=mirror["base"] + "/pool/ok_1.0_amd64.deb"),
        _item("nourl", "1.0"),
        _item("evil", "1.0", sha="1" * 64, url=mirror["base"] + "/redir")]))
    res = updates.download_pending(tenant, limit=10)
    db.session.commit()
    by = {u.name: u for u in AvailableUpdate.query}
    assert res["downloaded"] == 1 and res["failed"] == 2 and res["skipped"] == 2
    assert by["ok"].status == "downloaded" and by["ok"].patch.local_file and by["ok"].patch.status == "downloaded"
    path = patches_engine.local_path(by["ok"].patch, tenant)
    assert path is not None and path.read_bytes() == ok and hashlib.sha256(path.read_bytes()).hexdigest() == sha
    assert by["bad"].status == "failed" and "SHA-256" in by["bad"].detail and not by["bad"].patch.local_file         # adulterado: rejeitado, nada gravado
    assert not list(path.parent.glob(".dl-*"))                                                                       # sem ficheiros temporários
    assert by["nohash"].status == "not_downloadable" and "SHA-256" in by["nohash"].detail
    assert by["nourl"].status == "not_downloadable" and "URL" in by["nourl"].detail
    assert by["evil"].status == "failed" and ("redirecion" in by["evil"].detail.lower() or "endereço" in by["evil"].detail.lower() or "bloque" in by["evil"].detail.lower() or "link" in by["evil"].detail.lower() or by["evil"].detail)
    assert not patches_engine.local_path(by["evil"].patch, tenant)


def test_download_respects_size_limit_unhashed_policy_and_retry_backoff(app, tenant, enroll_token, mirror):
    ag = FakeAgent(app, enroll_token, "srv1")
    big = mirror["files"]["/pool/big_1.0_amd64.deb"]
    ag.c.post("/agent/v1/updates", headers=ag.h, json=_report([_item("big", "1.0", sha=hashlib.sha256(big).hexdigest(), url=mirror["base"] + "/pool/big_1.0_amd64.deb")]))
    app.config["UPDATES_MAX_DOWNLOAD_MB"] = 1
    res = updates.download_pending(tenant)
    db.session.commit()
    u = AvailableUpdate.query.one()
    assert res["failed"] == 1 and u.status == "failed" and "limite" in u.detail and u.attempts == 1
    hits = len(mirror["hits"])
    assert updates.download_pending(tenant)["failed"] == 0 and len(mirror["hits"]) == hits                           # espera antes de repetir
    later = utcnow() + __import__("datetime").timedelta(hours=2)
    app.config["UPDATES_MAX_DOWNLOAD_MB"] = 10
    assert updates.download_pending(tenant, now=later)["downloaded"] == 1 and AvailableUpdate.query.one().status == "downloaded"
    app.config["UPDATES_ALLOW_UNHASHED"] = True                                                                       # política explícita...
    ag.c.post("/agent/v1/updates", headers=ag.h, json=_report([_item("nh", "1.0", url=mirror["base"] + "/pool/ok_1.0_amd64.deb")], scan_id="s9"))
    assert updates.download_pending(tenant)["downloaded"] == 0                                                        # ...mas sem TLS e sem hash nunca se descarrega
    assert "sem TLS" in AvailableUpdate.query.filter_by(name="nh").one().detail


def test_shared_patch_downloaded_once_for_many_assets(app, tenant, enroll_token, mirror):
    a1, a2 = FakeAgent(app, enroll_token, "srv1"), FakeAgent(app, enroll_token, "srv2")
    ok = mirror["files"]["/pool/ok_1.0_amd64.deb"]
    item = _item("ok", "1.0", sha=hashlib.sha256(ok).hexdigest(), url=mirror["base"] + "/pool/ok_1.0_amd64.deb")
    a1.c.post("/agent/v1/updates", headers=a1.h, json=_report([item]))
    a2.c.post("/agent/v1/updates", headers=a2.h, json=_report([item]))
    assert Patch.query.count() == 1 and AvailableUpdate.query.count() == 2                                            # um patch, dois ativos
    n = len(mirror["hits"])
    assert updates.download_pending(tenant)["downloaded"] == 1 and len(mirror["hits"]) == n + 1
    assert {u.status for u in AvailableUpdate.query} == {"downloaded"}


def test_worker_tick_downloads_and_requests_stale_scans(app, tenant, enroll_token, mirror):
    ag = FakeAgent(app, enroll_token, "srv1")
    ok = mirror["files"]["/pool/ok_1.0_amd64.deb"]
    ag.c.post("/agent/v1/updates", headers=ag.h, json=_report([_item("ok", "1.0", sha=hashlib.sha256(ok).hexdigest(), url=mirror["base"] + "/pool/ok_1.0_amd64.deb")]))
    res = updates.tick(tenant)
    db.session.commit()
    assert res["downloaded"] == 1 and res["scan_requests"] == 0                                                       # descoberta recente: não pede outra
    UpdateScan.query.update({"received_at": utcnow() - __import__("datetime").timedelta(hours=20)})
    Agent.query.update({"last_seen": utcnow()})
    db.session.commit()
    assert updates.tick(tenant)["scan_requests"] == 1 and Task.query.filter_by(type="update_scan").count() == 1
    app.config["UPDATES_AUTO_DOWNLOAD"] = False
    assert "downloaded" not in updates.tick(tenant)


# ------------------------------------------------------------------ servidor → agente: simulação e remediação com o ficheiro do servidor


def test_end_to_end_discovery_download_simulate_approve_remediate(app, tenant, enroll_token, mirror):
    ag = FakeAgent(app, enroll_token, "srv1", software=(("ok", "0.9"),))
    ag.inventory()
    deb = mirror["files"]["/pool/ok_1.0_amd64.deb"]
    sha = hashlib.sha256(deb).hexdigest()
    ag.c.post("/agent/v1/updates", headers=ag.h, json=_report([_item("ok", "1.0", sha=sha, url=mirror["base"] + "/pool/ok_1.0_amd64.deb")]))
    updates.download_pending(tenant)
    db.session.commit()
    au = AvailableUpdate.query.one()
    assert au.status == "downloaded"
    admin = login_as(app, "admin@alpha.example")
    assert "ok" in admin.get("/updates").get_data(as_text=True) and "No repositório do servidor" in admin.get("/updates").get_data(as_text=True)
    assert admin.get(f"/updates/{au.id}").status_code == 200
    r = admin.post("/updates/plan", {"ids": str(au.id)})
    assert r.status_code == 302 and "/plans/" in r.headers["Location"]
    plan = OperationPlan.query.one()
    it = plan.items.one()
    assert it.kind == "patch" and it.patch_id == au.patch_id and it.asset_id == au.asset_id
    assert Task.query.filter_by(type="patch").count() == 0                                                           # só simulação
    sims = [t for t in ag.poll() if t["type"] == "simulate"]
    assert sims and sims[0]["payload"]["has_file"] and sims[0]["payload"]["sha256"] == sha and sims[0]["payload"]["installer"] == "apt"
    # o agente obtém mesmo o ficheiro do servidor e o hash confere
    dl = ag.c.get(f"/agent/v1/package/{au.patch_id}", headers=ag.h)
    assert dl.status_code == 200 and dl.data == deb and dl.headers["X-Content-SHA256"] == sha
    # aprovação do patch + OK + execução
    admin.post("/updates/approve", {"ids": str(au.id)})
    db.session.expire_all()
    assert db.session.get(Patch, au.patch_id).status == "approved"
    db.session.expire_all()
    it = db.session.get(PlanItem, it.id)
    ag.c.post(f"/agent/v1/tasks/{sims[0]['id']}/start", headers=ag.h, json={})
    ag.result(sims[0]["id"], {"status": "succeeded", "checks": [{"id": "package", "label": "Pacote do servidor (SHA-256 verificado)", "status": "ok", "detail": ""},
                                                                {"id": "applicability", "label": "apt-get -s", "status": "ok", "detail": "0.9 → 1.0"}],
                               "predicted": {"version_after": "1.0"}})
    db.session.expire_all()
    plan = db.session.get(OperationPlan, plan.id)
    plans.approve(plan, None, None, all_ok=True, accept_warnings=True)
    out = plans.execute(plan, tenant)
    db.session.commit()
    it = db.session.get(PlanItem, it.id)
    assert out["queued"] == 1, (it.status, it.sim_outcome, it.output, it.check_list)
    t = Task.query.filter_by(type="patch").one()
    assert t.payload_data["has_file"] and t.payload_data["sha256"] == sha and t.payload_data["package"] == "ok"


def test_linux_patcher_installs_the_server_file_and_simulates_it(monkeypatch, tmp_path):
    from omxpatch_agent.patchers import linux as plin
    from omxpatch_agent.runner import Result
    calls = []
    monkeypatch.setattr(plin, "_manager", lambda: "apt-get")
    monkeypatch.setattr(plin, "installed_version", lambda pkg: "1.0" if calls else "0.9")
    monkeypatch.setattr(plin, "reboot_required", lambda: False)

    def run(cmd, timeout=60, **k):
        calls.append(cmd)
        return Result(0, "Inst ok [0.9] (1.0 Ubuntu [amd64])\n")
    monkeypatch.setattr(plin, "run", run)
    seen = []
    res = plin.apply({"package": "ok", "has_file": True, "reboot_policy": "none"}, lambda suffix: seen.append(suffix) or str(tmp_path / "ok.deb"))
    assert res["status"] == "succeeded" and seen == [".deb"]
    assert calls[0][:3] == ["apt-get", "install", "-y"] and calls[0][-1].endswith("ok.deb") and "--only-upgrade" not in calls[0]
    calls.clear()
    seen.clear()
    plin.apply({"package": "ok", "reboot_policy": "none"}, lambda s: pytest.fail("sem ficheiro não descarrega"))
    assert any("--only-upgrade" in c for c in calls)                                                                 # sem ficheiro: usa o repositório do SO
    calls.clear()
    monkeypatch.setattr(plin, "installed_version", lambda pkg: "0.9")
    sim = plin.simulate({"package": "ok", "has_file": True, "version_fixed": "1.0"}, lambda suffix: str(tmp_path / "ok.deb"))
    assert sim["checks"][0]["id"] == "package" and sim["checks"][1]["status"] == "ok" and sim["predicted"]["version_after"] == "1.0"
    assert calls[0][:3] == ["apt-get", "-s", "install"]


# ------------------------------------------------------------------ UI, API, RBAC e isolamento


def test_pages_api_rbac_and_tenant_isolation(app, tenant, enroll_token):
    from tests.test_web import _api_token
    ag = FakeAgent(app, enroll_token, "srv1")
    ag.c.post("/agent/v1/updates", headers=ag.h, json=_report([_item("a"), _item("b", severity="low", category="update")]))
    admin = login_as(app, "admin@alpha.example")
    html = admin.get("/updates").get_data(as_text=True)
    for needle in ("Atualizações disponíveis nos ativos", "Descobrir agora", "Descarregar agora", "Simular as selecionadas", "Histórico de descobertas"):
        assert needle in html, needle
    assert "?source=apt&severity=high".split("&")[0] and admin.get("/updates?source=apt&severity=high").get_data(as_text=True).count("<tr>") < html.count("<tr>")
    assert admin.get("/updates/scans").status_code == 200 and "srv1" in admin.get("/updates/scans").get_data(as_text=True)
    asset = Asset.query.filter_by(name="srv1").one()
    assert "Atualizações disponíveis (2)" in admin.get(f"/assets/{asset.id}").get_data(as_text=True)
    admin.post("/updates/scan", {})
    assert Task.query.filter_by(type="update_scan").count() == 1
    aud = login_as(app, "auditor@alpha.example")
    assert aud.get("/updates").status_code == 200 and "Descobrir agora" not in aud.get("/updates").get_data(as_text=True)
    assert aud.post("/updates/scan", {}).status_code == 403 and aud.post("/updates/download", {}).status_code == 403
    assert aud.post("/updates/plan", {"ids": "1"}).status_code == 403 and aud.post("/updates/approve", {"ids": "1"}).status_code == 403
    beta = login_as(app, "admin@beta.example")
    au = AvailableUpdate.query.first()
    assert beta.get(f"/updates/{au.id}").status_code == 404 and "srv1" not in beta.get("/updates").get_data(as_text=True)
    beta.post("/updates/plan", {"ids": str(au.id)})
    assert OperationPlan.query.count() == 0
    h = {"Authorization": f"Bearer {_api_token(admin)}"}
    c = app.test_client()
    got = c.get("/api/v1/updates?severity=high", headers=h).get_json()
    assert len(got) == 1 and got[0]["name"] == "a" and got[0]["in_repository"] is False
    sm = c.get("/api/v1/updates/summary", headers=h).get_json()
    assert sm["pending"] == 2 and sm["scanned"] == 1 and sm["security"] == 1
    assert c.get("/api/v1/updates/scans", headers=h).get_json()[0]["total"] == 2
    assert c.post("/api/v1/updates/scan", headers=h, json={}).status_code == 202
    assert c.post("/api/v1/updates/download", headers=h, json={}).get_json()["skipped"] >= 1
    other = _api_token(beta)
    assert c.get("/api/v1/updates", headers={"Authorization": f"Bearer {other}"}).get_json() == []


def test_dashboard_shows_updates_panel_and_actions(app, tenant, enroll_token):
    ag = FakeAgent(app, enroll_token, "srv1")
    admin = login_as(app, "admin@alpha.example")
    html = admin.get("/").get_data(as_text=True)
    assert "Atualizações descobertas nos ativos" in html and "ainda não enviaram a descoberta" in html
    ag.c.post("/agent/v1/updates", headers=ag.h, json=_report([_item()]))
    html = admin.get("/").get_data(as_text=True)
    assert "1/1" in html and "ainda não enviaram" not in html


def test_diagnose_old_agent_and_no_scan(app):
    from datetime import timedelta
    from omxpatch.engine import updates as upd
    from omxpatch.extensions import db
    from omxpatch.models import Agent, Asset, Tenant
    from omxpatch.models import utcnow
    with app.app_context():
        t = Tenant(name="D", slug="diag-t")
        db.session.add(t)
        db.session.flush()
        a = Asset(tenant_id=t.id, name="h1", uid="diag-h1")
        b = Asset(tenant_id=t.id, name="h2", uid="diag-h2")
        db.session.add_all([a, b])
        db.session.flush()
        db.session.add_all([Agent(tenant_id=t.id, asset_id=a.id, key_hash="k1", key_prefix="p1", hostname="h1", version="1.2.20261108", last_seen=utcnow()),
                            Agent(tenant_id=t.id, asset_id=b.id, key_hash="k2", key_prefix="p2", hostname="h2", version="1.17.20261109", last_seen=utcnow())])
        db.session.commit()
        rows = {r["agent"].hostname: r for r in upd.diagnose(t)}
        assert "anterior" in rows["h1"]["verdict"] and rows["h1"]["level"] == "high"
        assert "Ainda sem descoberta" in rows["h2"]["verdict"]
        assert timedelta


def test_wua_error_hint_and_encoded_powershell():
    from omxpatch_agent.updates import windows
    assert "WSUS" in windows._wua_hint("WUA_ERROR 0x8024402C Exception from HRESULT")
    assert windows._wua_hint("WUA_ERROR ? algo").startswith("? —")
    import base64
    from unittest import mock
    from omxpatch_agent import runner
    with mock.patch.object(runner, "run") as m:
        runner.powershell('Write-Output "ação"')
        cmd = m.call_args[0][0]
        assert "-EncodedCommand" in cmd
        assert "ação" in base64.b64decode(cmd[-1]).decode("utf-16-le")


def test_wua_json_tolerates_powershell_noise():
    import pytest
    from omxpatch_agent.updates import windows
    good = '[{"id":"x","rev":1,"title":"KB1 t","kb":"123","severity":"Critical","cves":[],"size":5,"reboot":true,"eula":true,"categories":["Security Updates"],"urls":[]}]'
    noisy = '#< CLIXML\n<Objs Version="1.1.0.1"><S S="progress">x</S></Objs>\nOMXJSON_BEGIN\n' + good + '\nOMXJSON_END\n'
    assert windows.parse_wua_json(noisy)[0]["kb"] == "KB123"
    assert windows.parse_wua_json("﻿OMXJSON_BEGIN\n[]\nOMXJSON_END") == []
    assert windows.parse_wua_json("") == []
    assert windows.parse_wua_json(good)[0]["category"] == "security"       # compatível com saída sem marcadores
    with pytest.raises(RuntimeError, match="erro"):
        windows.parse_wua_json('#< CLIXML\n<Objs><S S="Error">falhou_</S></Objs>')
    with pytest.raises(RuntimeError, match="inesperada"):
        windows.parse_wua_json("blá blá")
