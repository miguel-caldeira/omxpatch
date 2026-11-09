"""Fluxo completo com agentes simulados através da API real (/agent/v1): registo → inventário → correlação → patch →
campanha por anéis → validação → fecho → autónomo."""
import hashlib
import json
from datetime import datetime, timedelta

import pytest

from omxpatch.engine import autonomous, deploy, patches, rings
from omxpatch.extensions import db
from omxpatch.models import (Agent, Asset, AutonomousRun, Campaign, CveIntel, EnrollmentToken, Exposure, MaintenanceWindow,
                             Patch, PatchTelemetry, Task, Validation, utcnow)
from omxpatch.worker import Worker
from omxpatch.web.api import new_enrollment_token
from tests.conftest import make_cve


class FakeAgent:
    """Fala o protocolo real do agente contra o Flask test client."""

    def __init__(self, app, token, name, os_family="linux", software=(("OpenSSL", "1.1.1k"),), ip="10.0.0.0"):
        self.c = app.test_client()
        r = self.c.post("/agent/v1/enroll", json={"token": token, "hostname": name, "os_family": os_family, "ip": ip,
                                                  "os_name": "Ubuntu 22.04" if os_family == "linux" else "Windows 11"})
        assert r.status_code == 201, r.data
        self.key = r.get_json()["agent_key"]
        self.h = {"Authorization": f"Bearer {self.key}"}
        self.software = [{"name": n, "version": v} for n, v in software]

    def inventory(self):
        r = self.c.post("/agent/v1/inventory", headers=self.h, json={"software": self.software, "hardware": {"cpu_count": 4},
                                                                      "open_ports": [22], "reboot_pending": False, "ip": "10.0.0.5"})
        assert r.status_code == 200, r.data
        return r.get_json()

    def poll(self, state=None):
        r = self.c.post("/agent/v1/poll", headers=self.h, json={"version": "1.0.0"})
        assert r.status_code == 200, r.data
        return r.get_json()["tasks"]

    def result(self, task_id, report):
        r = self.c.post(f"/agent/v1/tasks/{task_id}/result", headers=self.h, json=report)
        assert r.status_code == 200, r.data
        return r.get_json()

    def work(self, patch_ok=True, ux=95, new_version="1.1.1w", validate_ok=True):
        n = 0
        for t in self.poll():
            n += 1
            self.c.post(f"/agent/v1/tasks/{t['id']}/start", headers=self.h, json={})
            if t["type"] == "patch":
                if patch_ok:
                    self.software = [{"name": s["name"], "version": new_version} for s in self.software]
                self.result(t["id"], {"status": "succeeded" if patch_ok else "failed", "duration_s": 60, "crashed": False,
                                      "ux_score": ux, "output": "ok"})
            elif t["type"] == "validate":
                self.result(t["id"], {"status": "succeeded", "software": self.software, "full_inventory": True,
                                      "checks": {"patch_installed": validate_ok, "service_restarted": True}, "ports_open": []})
            elif t["type"] == "simulate":
                self.result(t["id"], {"status": "succeeded", "checks": [{"id": "applicability", "label": "ok", "status": "ok", "detail": ""}],
                                      "predicted": {"version_after": "1.1.1w"}})
            elif t["type"] == "control":
                self.result(t["id"], {"status": "succeeded", "verified": True})
            else:
                self.result(t["id"], {"status": "succeeded"})
        return n


@pytest.fixture()
def enroll_token(app, tenant):
    raw, tok = new_enrollment_token(tenant, "t", ring=4, days=1)
    db.session.commit()
    return raw


def setup_vuln(tenant):
    make_cve(kev=True, epss=0.5, advisories=[{"vendor": "OpenSSL", "product": "openssl", "fixed_version": "1.1.1w",
                                               "os_family": "linux", "package": "openssl", "installer": "apt"}])
    db.session.commit()


def test_agent_enrollment_security(app, tenant):
    c = app.test_client()
    assert c.post("/agent/v1/enroll", json={"token": "x", "hostname": "h", "os_family": "linux"}).status_code == 401
    assert c.post("/agent/v1/poll").status_code == 401
    raw, tok = new_enrollment_token(tenant, "uma-vez", max_uses=1)
    db.session.commit()
    FakeAgent(app, raw, "h1")
    assert c.post("/agent/v1/enroll", json={"token": raw, "hostname": "h2", "os_family": "linux"}).status_code == 401   # esgotado
    raw2, tok2 = new_enrollment_token(tenant, "exp", days=1)
    tok2.expires_at = utcnow() - timedelta(minutes=1)
    db.session.commit()
    assert c.post("/agent/v1/enroll", json={"token": raw2, "hostname": "h3", "os_family": "linux"}).status_code == 401
    assert c.post("/agent/v1/poll", headers={"Authorization": "Bearer omxa_falsa"}).status_code == 401
    # reinstalação revoga a chave anterior
    raw3, _ = new_enrollment_token(tenant, "reinst")
    db.session.commit()
    a1 = FakeAgent(app, raw3, "h1")
    assert a1.c.post("/agent/v1/poll", headers=a1.h).status_code == 200
    a2 = FakeAgent(app, raw3, "h1")
    assert a1.c.post("/agent/v1/poll", headers=a1.h).status_code == 401 and a2.poll() == []
    assert Asset.query.filter_by(tenant_id=tenant.id, uid="h1").count() == 1


def test_agent_cannot_touch_other_assets_tasks_or_packages(app, tenant, enroll_token):
    a = FakeAgent(app, enroll_token, "a1")
    b = FakeAgent(app, enroll_token, "b1")
    t = Task(tenant_id=tenant.id, type="inventory", asset_id=Agent.query.filter_by(hostname="a1").one().asset_id, status="queued", payload="{}")
    db.session.add(t)
    db.session.commit()
    assert b.c.post(f"/agent/v1/tasks/{t.id}/result", headers=b.h, json={"status": "succeeded"}).status_code == 404
    assert b.c.get("/agent/v1/package/1", headers=b.h).status_code == 404
    assert [x["id"] for x in a.poll()] == [t.id]


def test_end_to_end_patch_with_rings_and_validation(app, tenant, enroll_token, monkeypatch):
    setup_vuln(tenant)
    lab = FakeAgent(app, enroll_token, "lab1")
    prod = FakeAgent(app, enroll_token, "prod1")
    for ag, ring in ((lab, 0), (prod, 4)):
        Asset.query.filter_by(name=ag.c and ("lab1" if ag is lab else "prod1")).one().ring = ring
    db.session.commit()
    assert lab.inventory()["correlation"]["new"] == 1 and prod.inventory()["correlation"]["new"] == 1
    exps = Exposure.query.all()
    assert len(exps) == 2 and all(e.patch_available and e.risk_score > 40 for e in exps)
    patch = exps[0].patch
    patch.status = "approved"
    patch.community_reports, patch.community_success_rate = 200, 99.0
    db.session.commit()

    c = deploy.create_campaign(tenant, patch, "OpenSSL", {"cve_id": "CVE-2026-0001"})
    db.session.commit()
    assert deploy.ring_sequence(c, tenant) == [0, 4]
    w = Worker(app)
    w.tick()
    db.session.commit()
    assert c.status == "running" and c.current_ring == 0
    assert Task.query.filter_by(campaign_id=c.id).count() == 1 and prod.poll() == []     # produção só depois do Ring 0
    assert all(e.status == "patching" for e in Exposure.query.filter_by(asset_id=Asset.query.filter_by(name="lab1").one().id))
    assert lab.work() == 1
    w.tick()                                  # Ring 0 concluído; período de observação (soak) do Ring 0 = 0 h → promove
    db.session.commit()
    assert c.current_ring == 4 and Task.query.filter_by(campaign_id=c.id).count() == 2
    assert prod.work() == 1
    w.tick()
    db.session.commit()
    assert c.status == "completed"
    # patch aplicado → validação pedida; os agentes executam-na
    assert Validation.query.filter_by(status="pending").count() == 2
    assert lab.work() == 1 and prod.work() == 1
    db.session.expire_all()
    assert {e.status for e in Exposure.query.all()} == {"closed"} and all(e.closed_at for e in Exposure.query.all())
    assert Validation.query.filter_by(status="passed").count() == 2
    assert PatchTelemetry.query.filter_by(patch_id=patch.id, result="success").count() == 2
    assert deploy.campaign_summary(c)["succeeded"] == 2


def test_ring_hold_when_criteria_fail_and_manual_promotion(app, tenant, enroll_token):
    setup_vuln(tenant)
    lab = FakeAgent(app, enroll_token, "lab1")
    prod = FakeAgent(app, enroll_token, "prod1")
    Asset.query.filter_by(name="lab1").one().ring = 0
    db.session.commit()
    lab.inventory(); prod.inventory()
    patch = Exposure.query.first().patch
    patch.status = "approved"
    db.session.commit()
    c = deploy.create_campaign(tenant, patch, "x", {"cve_id": "CVE-2026-0001"})
    db.session.commit()
    w = Worker(app)
    w.tick()
    lab.work(patch_ok=False)                   # falha 1.ª tentativa → volta a pending (30 min) e falha de novo
    t = Task.query.filter_by(campaign_id=c.id).one()
    assert t.status == "pending"
    t.not_before = utcnow() - timedelta(minutes=1)
    db.session.commit()
    w.tick()
    lab.work(patch_ok=False)
    w.tick()
    db.session.commit()
    assert c.status == "paused" and "Taxa de sucesso" in json.dumps(c.rings_state, ensure_ascii=False)
    assert prod.poll() == []                   # nada chega à produção
    deploy.resume(c, tenant, override=True)    # decisão humana registada
    db.session.commit()
    assert c.status == "running" and c.current_ring == 4 and c.rings_state["0"]["override"] is True


def test_ring_soak_blocks_promotion_until_elapsed(app, tenant, enroll_token):
    setup_vuln(tenant)
    ag = FakeAgent(app, enroll_token, "r1")
    Asset.query.filter_by(name="r1").one().ring = 1       # Ring 1 tem observação (24 h)
    prod = FakeAgent(app, enroll_token, "p1")
    ag.inventory(); prod.inventory()
    patch = Exposure.query.first().patch
    patch.status = "approved"
    db.session.commit()
    c = deploy.create_campaign(tenant, patch, "x", {"cve_id": "CVE-2026-0001"})
    db.session.commit()
    w = Worker(app)
    w.tick(); ag.work(); w.tick()
    assert c.current_ring == 1 and "observação" in " ".join(c.rings_state["1"]["reasons"])
    w.tick(now=utcnow() + timedelta(hours=25))
    db.session.commit()
    assert c.current_ring == 4


def test_maintenance_windows_wol_and_emergency(app, tenant, enroll_token, monkeypatch):
    setup_vuln(tenant)
    ag = FakeAgent(app, enroll_token, "w1")
    ag.inventory()
    asset = Asset.query.filter_by(name="w1").one()
    asset.mac = "aa:bb:cc:dd:ee:ff"
    patch = Exposure.query.first().patch
    patch.status = "approved"
    now = datetime(2026, 11, 9, 14, 0)            # segunda-feira, 14:00
    db.session.add(MaintenanceWindow(tenant_id=tenant.id, name="Noite", weekdays="0,1,2,3,4", start_time="22:00", duration_minutes=240,
                                     timezone="UTC"))
    db.session.commit()
    assert deploy.window_allows(tenant.id, asset, now)[0] is False
    assert deploy.window_allows(tenant.id, asset, datetime(2026, 11, 9, 23, 0))[0] is True
    assert deploy.window_allows(tenant.id, asset, datetime(2026, 11, 10, 1, 0))[0] is True        # atravessa a meia-noite
    assert deploy.window_allows(tenant.id, asset, now, emergency=True)[0] is True
    c = deploy.create_campaign(tenant, patch, "j", {"asset_ids": [asset.id]}, use_rings=False, use_wol=True)
    c.start_at = now
    deploy.advance(c, tenant, now)
    t = Task.query.filter_by(campaign_id=c.id).one()
    assert t.status == "waiting_window" and ag.poll() == []
    Agent.query.filter_by(asset_id=asset.id).one().last_seen = datetime(2026, 11, 9, 22, 29)
    deploy.release_tasks(c, tenant, datetime(2026, 11, 9, 22, 30))
    assert t.status == "queued"
    # Wake-on-LAN: agente desligado
    sent = []
    monkeypatch.setattr(deploy, "send_wol", lambda mac, *a, **k: sent.append(mac))
    Agent.query.filter_by(asset_id=asset.id).one().last_seen = datetime(2026, 11, 7, 10, 0)
    t.status = "pending"
    deploy.release_tasks(c, tenant, datetime(2026, 11, 9, 22, 31))
    assert t.status == "waking" and sent == ["aa:bb:cc:dd:ee:ff"]
    assert deploy.magic_packet("aa:bb:cc:dd:ee:ff") == b"\xff" * 6 + bytes.fromhex("aabbccddeeff") * 16
    with pytest.raises(ValueError):
        deploy.magic_packet("zz")


def test_campaign_blocked_by_patch_intelligence_and_unapproved(app, tenant):
    setup_vuln(tenant)
    p = Patch(tenant_id=tenant.id, patch_uid="KB9", status="identified", cves='["CVE-2026-0001"]')
    db.session.add(p)
    db.session.commit()
    with pytest.raises(deploy.PatchBlocked, match="Aprove"):
        deploy.create_campaign(tenant, p, "x", {"asset_ids": [1]})
    p.status = "approved"
    p.vendor_known_issues = json.dumps([{"title": "BSOD", "severity": "critical"}])
    with pytest.raises(deploy.PatchBlocked, match="recomenda não aplicar"):
        deploy.create_campaign(tenant, p, "x", {"asset_ids": [1]})
    with pytest.raises(deploy.PatchBlocked, match="Nenhum ativo"):
        deploy.create_campaign(tenant, p, "x", {"asset_ids": [999]}, force=True)


def test_stale_tasks_are_requeued_then_fail(app, tenant, enroll_token):
    ag = FakeAgent(app, enroll_token, "s1")
    asset = Asset.query.filter_by(name="s1").one()
    t = Task(tenant_id=tenant.id, type="inventory", asset_id=asset.id, status="queued", payload="{}")
    db.session.add(t)
    db.session.commit()
    for i in range(3):
        assert len(ag.poll()) == 1
        t.sent_at = utcnow() - timedelta(hours=5)
        deploy.requeue_stale()
        db.session.commit()
    assert t.status == "failed"


def test_autonomous_full_cycle_advise_then_auto(app, tenant, enroll_token):
    setup_vuln(tenant)
    tenant.autonomous_mode, tenant.autonomous_min_score = "auto", 30
    lab = FakeAgent(app, enroll_token, "lab1")
    prod = FakeAgent(app, enroll_token, "prod1")
    Asset.query.filter_by(name="lab1").one().ring = 0
    db.session.commit()
    lab.inventory(); prod.inventory()
    w = Worker(app)
    w.tick()                                    # monitorização: deteta o CVE novo e abre o fluxo
    db.session.commit()
    run = AutonomousRun.query.one()
    assert run.cve_id == "CVE-2026-0001" and run.mode == "auto"
    for _ in range(40):                         # a máquina de estados + agentes até concluir
        w.tick()
        lab.work(); prod.work()
        db.session.commit()
        if run.status in ("completed", "failed", "approval"):
            break
    assert run.status == "completed", run.log
    assert run.stage == "done" and run.report_data["closed"] == 2 and run.report_data["still_open"] == 0
    assert "Teste automático" in run.log and "Fecho automático" in run.log and "CMDB atualizada" in run.log
    assert Campaign.query.one().origin == "autonomous"
    assert {e.status for e in Exposure.query.all()} == {"closed"}


def test_autonomous_advise_mode_waits_for_human(app, tenant, enroll_token):
    setup_vuln(tenant)
    tenant.autonomous_mode = "advise"
    ag = FakeAgent(app, enroll_token, "a1")
    ag.inventory()
    db.session.commit()
    run = autonomous.trigger(tenant, "CVE-2026-0001")
    for _ in range(8):
        autonomous.advance(run)
    db.session.commit()
    assert run.status == "approval" and run.stage == "test" and Campaign.query.count() == 0
    autonomous.approve(run)
    autonomous.advance(run)
    db.session.commit()
    assert Campaign.query.count() == 1 and Patch.query.one().status == "approved"


def test_autonomous_no_patch_proposes_controls_and_waits(app, tenant, enroll_token):
    make_cve("CVE-2026-0777", kev=True, advisories=[])
    tenant.autonomous_mode = "auto"
    ag = FakeAgent(app, enroll_token, "a1")
    ag.software = [{"name": "OpenSSL", "version": "1.1.1k"}]
    db.session.commit()
    # sem versão corrigida no CVE: o patch não existe
    cve = CveIntel.query.filter_by(cve_id="CVE-2026-0777").one()
    cve.affected = json.dumps([{"vendor": "openssl", "product": "openssl", "version_end": "1.1.1k"}])
    db.session.commit()
    ag.inventory()
    run = autonomous.trigger(tenant, "CVE-2026-0777")
    for _ in range(6):
        autonomous.advance(run)
    db.session.commit()
    assert run.status == "waiting" and run.stage == "patch_search"
    assert "sem patch disponível" in run.log
    from omxpatch.models import ControlAction
    assert ControlAction.query.filter_by(cve_id="CVE-2026-0777").count() >= 1


def test_closure_pushes_status_to_omxvuln_and_evidence_to_omxgrc(app, tenant, enroll_token, monkeypatch):
    from omxpatch.connectors import store
    calls = []

    class R:
        status_code = 200

        def json(self):
            return []

        def raise_for_status(self):
            pass

    def fake(method, url, **kw):
        calls.append((method, url, kw.get("json")))
        return R()

    monkeypatch.setattr("omxpatch.connectors.http.requests.request", fake)
    monkeypatch.setattr("omxpatch.connectors.http.check_outbound_url", lambda u, **k: u)
    store.save(tenant.id, "omxvuln", "https://omxvuln.example", "", {"token": "tok"}, {"tenant_id": "3"}, True)
    store.save(tenant.id, "omxgrc", "https://omxgrc.example", "", {"token": "tok2"}, {}, True)
    setup_vuln(tenant)
    ag = FakeAgent(app, enroll_token, "a1")
    ag.inventory()
    ex = Exposure.query.one()
    ex.omxvuln_finding_id = 77
    ex.patch.status = "approved"
    db.session.commit()
    c = deploy.create_campaign(tenant, ex.patch, "x", {"cve_id": ex.cve_id}, use_rings=False)
    db.session.commit()
    Worker(app).tick(); ag.work(); Worker(app).tick(); ag.work()
    db.session.expire_all()
    assert Exposure.query.one().status == "closed"
    urls = [(m, u) for m, u, _ in calls]
    assert ("POST", "https://omxvuln.example/api/v1/findings/77/status") in urls
    assert any(u == "https://omxgrc.example/api/v1/evidence" for _, u in urls)
    body = next(b for m, u, b in calls if u.endswith("/findings/77/status"))
    assert body["status"] == "remediated" and "CVE-2026-0001" in body["note"]
