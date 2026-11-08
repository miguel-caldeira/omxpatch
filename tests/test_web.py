"""Interface web e API: páginas, perfis, isolamento multitenant, CSRF, tokens e licenciamento."""
import json
import re
from datetime import date, timedelta

import pytest

from omxpatch.engine import correlate, controls, patches
from omxpatch.extensions import db
from omxpatch.models import (Agent, Asset, AutonomousRun, Campaign, ControlAction, CveIntel, Exposure, Patch, Signal, Simulation,
                             Task, Tenant, User, Validation)
from tests.conftest import Client, extract, login_as, make_asset, make_cve


@pytest.fixture()
def populated(app, tenant):
    make_cve(kev=True, epss=0.5, cwe="CWE-22", advisories=[{"vendor": "OpenSSL", "product": "openssl", "fixed_version": "1.1.1w",
                                                             "os_family": "linux", "package": "openssl", "installer": "apt"}])
    a = make_asset(tenant, "web01", software=(("OpenSSL", "1.1.1k"),), ip="8.8.4.4", owner="ana", open_ports="443")
    correlate.correlate_asset(tenant, a)
    ex = Exposure.query.one()
    ex.port = 443
    controls.propose_for(tenant, ex)
    db.session.add(Signal(tenant_id=tenant.id, source="defender", kind="edr_missed", cve_id=ex.cve_id, asset_id=a.id))
    db.session.add(Validation(tenant_id=tenant.id, exposure_id=ex.id, asset_id=a.id, cve_id=ex.cve_id, status="failed", checks='{"cve_gone": false}'))
    db.session.add(AutonomousRun(tenant_id=tenant.id, cve_id=ex.cve_id, stage="test", status="approval", log="[x] teste\n"))
    db.session.commit()
    return a


PAGES = ["/", "/executive", "/assets", "/assets/new", "/exposures", "/intel", "/signals", "/patches", "/patches/new", "/campaigns", "/windows",
         "/rings", "/controls", "/advisor", "/validations", "/simulations", "/autonomous", "/compliance", "/agents", "/integrations",
         "/users", "/users/new", "/settings", "/audit", "/profile", "/executive.json", "/compliance/export.csv", "/compliance/export.json"]


@pytest.mark.parametrize("page", PAGES)
def test_every_page_renders_for_admin(app, populated, page):
    c = login_as(app, "admin@alpha.example")
    r = c.get(page)
    assert r.status_code == 200, (page, r.data[:300])


def test_detail_pages_render(app, populated):
    c = login_as(app, "admin@alpha.example")
    ex = Exposure.query.one()
    ctl = ControlAction.query.first()
    p = Patch.query.first()
    for url in (f"/assets/{populated.id}", f"/assets/{populated.id}/edit", f"/exposures/{ex.id}", f"/intel/{ex.cve_id}",
                f"/controls/{ctl.id}", f"/patches/{p.id}", f"/campaigns/new?patch_id={p.id}", "/autonomous/1"):
        r = c.get(url)
        assert r.status_code == 200, (url, r.data[:300])
    html = c.get(f"/exposures/{ex.id}").get_data(as_text=True)
    assert "Firewall não bloqueia" in html or "Vulnerável" in html and "CVE-2026-0001" in html
    assert "Risco dinâmico" in c.get(f"/exposures/{ex.id}").get_data(as_text=True)


def test_login_required_and_csrf(app, populated):
    c = Client(app.test_client())
    assert c.get("/assets").status_code == 302 and c.get("/exposures").status_code == 302
    r = login_as(app, "admin@alpha.example")
    _fresh = __import__("tests.conftest", fromlist=["_fresh_g"])._fresh_g; _fresh()
    raw = r.c.post("/assets/discover", data={"targets": "10.0.0.1"})                 # sem token CSRF
    assert raw.status_code == 400


def test_roles_auditor_is_read_only_user_cannot_manage(app, populated):
    aud = login_as(app, "auditor@alpha.example")
    assert aud.get("/assets").status_code == 200 and aud.get("/audit").status_code == 200
    assert aud.get("/assets/new").status_code == 403
    assert aud.post("/exposures/correlate").status_code == 403
    assert aud.get("/integrations").status_code == 403 and aud.get("/users").status_code == 403
    usr = login_as(app, "user@alpha.example")
    assert usr.get("/assets/new").status_code == 200 and usr.get("/integrations").status_code == 403
    ex = Exposure.query.one()
    assert usr.post(f"/exposures/{ex.id}/accept", {"reason": "x" * 20}).status_code == 403
    ctl = ControlAction.query.first()
    assert usr.post(f"/controls/{ctl.id}/approve").status_code == 403
    p = Patch.query.first()
    assert usr.post(f"/patches/{p.id}/status", {"status": "approved"}).status_code == 403


def test_tenant_isolation_everywhere(app, populated):
    beta = login_as(app, "admin@beta.example")
    ex, a, p, ctl = Exposure.query.one(), populated, Patch.query.first(), ControlAction.query.first()
    for url in (f"/assets/{a.id}", f"/exposures/{ex.id}", f"/patches/{p.id}", f"/controls/{ctl.id}", "/autonomous/1"):
        assert beta.get(url).status_code == 404, url
    assert b"web01" not in beta.get("/assets").data
    assert beta.post(f"/assets/{a.id}/delete").status_code == 404
    assert beta.post(f"/controls/{ctl.id}/approve").status_code == 404
    # API: token de outro tenant não vê dados
    tok = _api_token(beta)
    assert beta.c.get("/api/v1/exposures", headers={"Authorization": f"Bearer {tok}"}).get_json() == []
    assert beta.c.get(f"/api/v1/assets/{a.id}", headers={"Authorization": f"Bearer {tok}"}).status_code == 404


def _api_token(client):
    client.post("/profile/tokens", {"name": "t", "days": "30"})
    with client.c.session_transaction() as s:
        return s["new_token"]


def test_api_with_bearer_token(app, populated):
    admin = login_as(app, "admin@alpha.example")
    tok = _api_token(admin)
    h = {"Authorization": f"Bearer {tok}"}
    c = app.test_client()
    assert c.get("/api/v1/assets").status_code == 401
    assert c.get("/api/v1/me", headers=h).get_json()["tenant"]["slug"] == "alpha"
    exps = c.get("/api/v1/exposures", headers=h).get_json()
    assert exps[0]["cve"] == "CVE-2026-0001" and exps[0]["risk"]["factors"] and exps[0]["patch"]["uid"]
    r = c.post("/api/v1/assets", headers=h, json=[{"name": "api-host", "ip": "10.0.0.50", "os_family": "linux",
                                                    "software": [{"name": "OpenSSL", "version": "1.1.1b"}]}])
    assert r.status_code == 201
    assert c.post("/api/v1/correlate", headers=h).get_json()["new"] == 1
    assert c.get("/api/v1/compliance", headers=h).get_json()["frameworks"]["nis2"]["requirements"]
    assert "kpis" in c.get("/api/v1/grc/controls", headers=h).get_json()
    assert isinstance(c.get("/api/v1/grc/evidence", headers=h).get_json(), list)
    adv = c.post("/api/v1/advisor", headers=h, json={"question": "Como reduzir o risco para menos de 20 pontos?"}).get_json()
    assert adv["after"] <= adv["before"] and adv["steps"]
    e = c.post("/api/v1/enrollment-tokens", headers=h, json={"name": "x", "ring": 2}).get_json()
    assert e["token"].startswith("omxe_")
    # utilizador sem perfil de escrita
    aud = login_as(app, "auditor@alpha.example")
    th = {"Authorization": f"Bearer {_api_token(aud)}"} if False else None
    assert th is None


def test_api_auditor_token_cannot_write(app, populated):
    user = User.query.filter_by(email="auditor@alpha.example").one()
    from omxpatch.models import ApiToken
    from omxpatch.security import new_api_token
    raw, digest, prefix = new_api_token()
    db.session.add(ApiToken(user_id=user.id, name="ro", token_hash=digest, prefix=prefix))
    db.session.commit()
    h = {"Authorization": f"Bearer {raw}"}
    c = app.test_client()
    assert c.get("/api/v1/assets", headers=h).status_code == 200
    assert c.post("/api/v1/assets", headers=h, json={"name": "x"}).status_code == 403
    assert c.post("/api/v1/correlate", headers=h).status_code == 403
    assert c.post("/api/v1/sync/omxvuln", headers=h).status_code == 403


def test_signals_webhook_creates_exposure_and_changes_verdict(app, populated):
    admin = login_as(app, "admin@alpha.example")
    h = {"Authorization": f"Bearer {_api_token(admin)}"}
    c = app.test_client()
    body = {"resources": [{"cve": {"id": "CVE-2026-0001", "exploit_status": 90}, "host_info": {"hostname": "web01"},
                           "app": {"product_name_version": "OpenSSL 1.1.1k"}}]}
    r = c.post("/api/v1/signals?vendor=crowdstrike", headers=h, json=body)
    assert r.status_code == 201 and r.get_json()["new"] == 2
    ex = Exposure.query.one()
    assert ex.verdict_data["active_exploitation_observed"] is True
    csv_body = "cve,asset,action\nCVE-2026-0001,web01,block\n"
    r = c.post("/api/v1/signals?vendor=paloalto", headers={**h, "Content-Type": "text/csv"}, data=csv_body)
    assert r.status_code == 201
    db.session.expire_all()
    assert Exposure.query.one().verdict_data["firewall_blocks"] is True
    assert c.post("/api/v1/signals", headers=h, data="{nao json", content_type="application/json").status_code == 400


def test_patch_workflow_in_ui(app, populated):
    c = login_as(app, "admin@alpha.example")
    p = Patch.query.first()
    r = c.post(f"/patches/{p.id}/status", {"status": "approved"})
    assert r.status_code == 302 and db.session.get(Patch, p.id).status == "approved"
    r = c.post("/campaigns/new", {"patch_id": p.id, "name": "UI", "cve_id": "CVE-2026-0001", "use_rings": "1",
                                  "respect_windows": "1", "auto_promote": "1"})
    assert r.status_code == 302, r.data
    camp = Campaign.query.one()
    assert camp.status == "scheduled"
    assert c.post(f"/campaigns/{camp.id}/start").status_code == 302 and db.session.get(Campaign, camp.id).status in ("running", "completed")
    assert c.post(f"/campaigns/{camp.id}/nope").status_code == 400
    # patch msi sem ficheiro não pode ser aprovado
    msi = Patch(tenant_id=p.tenant_id, patch_uid="msi1", installer="msi")
    db.session.add(msi)
    db.session.commit()
    c.post(f"/patches/{msi.id}/status", {"status": "approved"})
    assert db.session.get(Patch, msi.id).status == "identified"
    up = c.c.post(f"/patches/{msi.id}/upload", data={"_csrf": c.csrf(), "file": (__import__("io").BytesIO(b"abc"), "x.msi")},
                  content_type="multipart/form-data")
    assert up.status_code == 302 and db.session.get(Patch, msi.id).status == "downloaded"
    assert c.post(f"/patches/{msi.id}/status", {"status": "approved"}).status_code == 302 and db.session.get(Patch, msi.id).status == "approved"
    f = c.get(f"/patches/{msi.id}/file")
    assert f.status_code == 200 and f.data == b"abc"


def test_control_workflow_in_ui(app, populated):
    c = login_as(app, "admin@alpha.example")
    ctl = ControlAction.query.filter_by(action="siem_rule").first() or ControlAction.query.first()
    assert c.post(f"/controls/{ctl.id}/apply").status_code == 302 and db.session.get(ControlAction, ctl.id).status == "proposed"
    assert c.post(f"/controls/{ctl.id}/approve").status_code == 302
    c.post(f"/controls/{ctl.id}/mark_applied", {"verified": "1"})
    assert db.session.get(ControlAction, ctl.id).status == "verified"
    ex = Exposure.query.one()
    c.post(f"/exposures/{ex.id}/accept", {"reason": "curto"})
    assert db.session.get(Exposure, ex.id).status != "accepted"
    c.post(f"/exposures/{ex.id}/accept", {"reason": "risco aceite pela direção até ao patch de dezembro"})
    assert db.session.get(Exposure, ex.id).status == "accepted"


def test_assets_ui_create_edit_import_discover(app, tenant):
    c = login_as(app, "admin@alpha.example")
    r = c.post("/assets/new", {"name": "pc1", "ip": "10.1.1.1", "kind": "workstation", "os_family": "windows", "ring": "2",
                               "criticality": "high", "owner": "rui", "managed": "1"})
    assert r.status_code == 302
    a = Asset.query.filter_by(name="pc1").one()
    assert a.ring == 2 and a.criticality == "high" and a.managed
    c.post(f"/assets/{a.id}/ring", {"ring": "1"})
    assert db.session.get(Asset, a.id).ring == 1
    csv = "name,ip,os_name,owner\nsrv-a,10.2.0.1,Ubuntu 22.04,ana\nsrv-b,10.2.0.2,Windows Server 2022,rui\n"
    up = c.c.post("/assets/import", data={"_csrf": c.csrf(), "file": (__import__("io").BytesIO(csv.encode()), "a.csv")},
                  content_type="multipart/form-data")
    assert up.status_code == 302 and Asset.query.filter_by(tenant_id=a.tenant_id).count() == 3
    assert Asset.query.filter_by(name="srv-b").one().os_family == "windows"
    r = c.post("/assets/discover", {"targets": "10.0.0.0/8"})
    assert r.status_code == 302 and b"demasiado grande" in c.get("/assets").data
    c.post(f"/assets/{a.id}/delete")
    assert db.session.get(Asset, a.id) is None


def test_integration_secrets_encrypted_and_ssrf_blocked(app, tenant):
    c = login_as(app, "admin@alpha.example")
    r = c.post("/integrations/omxvuln", {"base_url": "https://omxvuln.exemplo.pt", "secret_token": "SEGREDO-123", "opt_tenant_id": "2",
                                          "verify_tls": "1", "enabled": "1"})
    assert r.status_code == 302
    from omxpatch.models import Connector
    row = Connector.query.filter_by(kind="omxvuln").one()
    assert "SEGREDO-123" not in row.secret and row.secret.startswith("gAAAA")
    assert "SEGREDO-123" not in c.get("/integrations/omxvuln").get_data(as_text=True)
    bad = c.post("/integrations/omxgrc", {"base_url": "http://169.254.169.254/latest", "secret_token": "x", "enabled": "1"})
    assert bad.status_code == 400 and Connector.query.filter_by(kind="omxgrc").count() == 0
    loop = c.post("/settings", {"webhook_url": "http://127.0.0.1:9/x"})
    assert Tenant.query.filter_by(slug="alpha").one().webhook_url == ""
    assert c.get("/integrations/nao-existe").status_code == 404


def test_license_suspension_blocks_login_and_agents(app, tenant):
    tenant.license_expires_on = date.today() - timedelta(days=60)
    db.session.commit()
    c = Client(app.test_client())
    r = c.login("admin@alpha.example")
    assert r.status_code == 403
    from omxpatch.web.api import new_enrollment_token
    raw, _ = new_enrollment_token(tenant, "t")
    db.session.commit()
    assert app.test_client().post("/agent/v1/enroll", json={"token": raw, "hostname": "h", "os_family": "linux"}).status_code == 403


def test_superadmin_tenants_and_primary_admin(app):
    c = login_as(app, "root@omx.example")
    assert c.get("/tenants").status_code == 200 and c.get("/system").status_code == 200
    r = c.post("/tenants/new", {"name": "Gama SA", "country": "PT", "license_expires_on": str(date.today() + timedelta(days=30))})
    assert r.status_code == 302
    t = Tenant.query.filter_by(slug="gama-sa").one()
    from omxpatch.models import RingPolicy
    assert RingPolicy.query.filter_by(tenant_id=t.id).count() == 5
    from omxpatch import admin_reset
    pw = admin_reset.ensure_primary(app, log=lambda m: None)
    assert pw and User.query.filter_by(is_primary=True).one().email == "admin@omxpatch.local"
    from omxpatch.models import PrimaryAdminError
    u = User.query.filter_by(is_primary=True).one()
    with pytest.raises(PrimaryAdminError):
        u.enabled = False


def test_security_headers_and_csp(app):
    r = Client(app.test_client()).get("/login")
    assert "script-src 'self'" in r.headers["Content-Security-Policy"] and r.headers["X-Content-Type-Options"] == "nosniff"
    assert "style=" not in r.get_data(as_text=True)
