"""I1 — fiabilidade entre organizações (opt-in, k-anonimato) e avisos de problemas conhecidos no Patch Intelligence."""
from __future__ import annotations

from omxpatch.engine import fleet, patches
from omxpatch.extensions import db
from omxpatch.models import Patch, PatchAdvisory, PatchTelemetry, Tenant


def mk_tenant(n, share):
    t = Tenant(name=f"T{n}", slug=f"t{n}", share_telemetry=share)
    db.session.add(t)
    db.session.flush()
    return t


def mk_patch(t, uid="KB900", **kw):
    p = Patch(tenant_id=t.id, patch_uid=uid, os_family="windows", title="x", **kw)
    db.session.add(p)
    db.session.flush()
    return p


def feed(p, ok, bad, rolled=0):
    for i in range(ok):
        patches.record_telemetry(p.tenant_id, p.id, None, "success")
    for i in range(bad):
        patches.record_telemetry(p.tenant_id, p.id, None, "failed")
    for i in range(rolled):
        patches.record_telemetry(p.tenant_id, p.id, None, "rolled_back")
    db.session.flush()


def test_fleet_requires_optin_reciprocity_and_k_anonymity(app):
    with app.app_context():
        ts = [mk_tenant(i, True) for i in range(1, 5)]
        ps = [mk_patch(t) for t in ts]
        for p in ps[:2]:
            feed(p, 6, 0)
        assert fleet.fleet_stats(ps[0]) is None                                  # 2 organizações < 3: omitido
        feed(ps[2], 6, 0)
        st = fleet.fleet_stats(ps[0])
        assert st["tenants"] == 3 and st["n"] == 18 and st["success_rate"] == 100.0
        assert set(st) == {"tenants", "n", "success_rate", "rollback_rate", "crash_rate"}          # só agregados
        outsider = mk_tenant(9, False)
        assert fleet.fleet_stats(mk_patch(outsider)) is None                     # quem não partilha não vê (reciprocidade)
        ts[2].share_telemetry = False
        db.session.flush()
        assert fleet.fleet_stats(ps[0]) is None                                  # saiu da partilha: deixa de contar (volta a < 3)


def test_bad_fleet_results_put_patch_on_hold_even_if_local_history_is_good(app):
    with app.app_context():
        ts = [mk_tenant(i, True) for i in range(1, 5)]
        ps = [mk_patch(t, uid="KB777") for t in ts]
        feed(ps[0], 20, 0)
        assert patches.intelligence(ps[0])["level"] == "go"
        for p in ps[1:]:
            feed(p, 3, 1, rolled=3)
        i = patches.intelligence(ps[0])
        assert i["fleet"] and i["level"] == "hold" and any("Frota" in r for r in i["reasons"])
        ts[0].share_telemetry = False                                            # sem partilhar, não recebe o agregado
        db.session.flush()
        assert patches.intelligence(ps[0])["fleet"] is None


def test_advisories_feed_intelligence_by_severity_and_scope(app):
    with app.app_context():
        a, b = mk_tenant(1, False), mk_tenant(2, False)
        pa, pb = mk_patch(a, uid="KB555"), mk_patch(b, uid="KB555")
        feed(pa, 20, 0)
        feed(pb, 20, 0)
        assert patches.intelligence(pa)["level"] == "go"
        db.session.add(PatchAdvisory(tenant_id=a.id, patch_uid="kb555", title="Falha de arranque em VMs", severity="medium"))
        db.session.flush()
        assert patches.intelligence(pa)["level"] == "caution" and patches.intelligence(pb)["level"] == "go"       # só a organização A
        db.session.add(PatchAdvisory(tenant_id=None, patch_uid="KB555", title="BSOD", severity="critical", source="vendor"))
        db.session.flush()
        assert patches.intelligence(pa)["level"] == "hold" and patches.intelligence(pb)["level"] == "hold"        # global: todas
        for x in PatchAdvisory.query.all():
            x.active = False
        db.session.flush()
        assert patches.intelligence(pa)["level"] == "go"


def test_advisory_page_and_sharing_toggle(app, tenant, alpha_admin):
    with app.app_context():
        mk_patch(tenant, uid="KB321")
        db.session.commit()
    assert b"Partilha an" in alpha_admin.get("/patches/advisories").data
    alpha_admin.post("/patches/advisories", data={"act": "share", "share": "1"})
    alpha_admin.post("/patches/advisories", data={"act": "add", "patch_uid": "KB321", "title": "Reinício em ciclo", "severity": "high", "global": "1"})
    with app.app_context():
        assert Tenant.query.get(tenant.id).share_telemetry is True
        adv = PatchAdvisory.query.one()
        assert adv.tenant_id == tenant.id                                         # «global» só para superadmin: ignorado
        assert patches.intelligence(Patch.query.filter_by(patch_uid="KB321").one())["level"] == "hold"
    alpha_admin.post("/patches/advisories", data={"act": "delete", "id": str(adv.id)})
    with app.app_context():
        assert PatchAdvisory.query.count() == 0
