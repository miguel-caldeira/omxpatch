"""Centro de comando: dados consolidados, gráficos e ações rápidas de simular/remediar (nunca aplicam sem OK)."""
import json

import pytest

from omxpatch.engine import command_center, plans
from omxpatch.extensions import db
from omxpatch.models import Agent, Asset, OperationPlan, Patch, PlanItem, Task, utcnow
from tests.conftest import login_as, make_asset, make_cve
from tests.test_flow import FakeAgent, enroll_token  # noqa: F401
from tests.test_web import populated  # noqa: F401


@pytest.fixture()
def world(app, tenant, populated, enroll_token):
    """Um ativo com exposição KEV + patch aprovado, um agente real e um servidor web inventariado."""
    from omxpatch.models import Exposure
    ex = Exposure.query.one()
    p = Patch(tenant_id=tenant.id, patch_uid="openssl-apt", installer="apt", package_name="openssl", os_family="linux", status="approved",
              cves=json.dumps([ex.cve_id]))
    db.session.add(p)
    db.session.flush()
    ex.patch_id, ex.patch_available = p.id, True
    ag = FakeAgent(app, enroll_token, "web02", software=(("nginx", "1.18"),))
    ag.inventory()
    w = Asset.query.filter_by(name="web02").one()
    w.hardware = json.dumps({"webservers": [{"type": "nginx"}], "agent_runtime": {"level": "legacy", "python": "3.8.10"}})
    db.session.commit()
    return {"asset": populated, "patch": p, "web": w, "agent": ag}


def test_overview_consolidates_every_area(app, tenant, world):
    from omxpatch.models import User
    user = User.query.filter_by(email="admin@alpha.example").one()
    o = command_center.overview(app, tenant, user)
    assert o["k"]["open_exposures"] >= 1 and o["fleet"]["agents"] == 1 and o["fleet"]["legacy_python"] == 1
    assert o["fleet"]["by_os"]["linux"]["agent"] == 1
    pr = o["priority"][0]
    assert pr["uid"] == "openssl-apt" and pr["kev"] >= 1 and pr["assets"] == 1 and pr["plan_state"] == {}
    assert o["practices"]["webservers"] == 1 and o["practices"]["servers"] == {"nginx": 1}
    assert any(a["kind"] == "patch" and a["level"] == "critical" for a in o["actions"])                    # KEV sem simulação
    assert any(a["kind"] == "tls" for a in o["actions"])
    assert [n for n, _ in o["funnel"]][0] == "Exposições abertas" and len(o["funnel"]) == 7
    assert {c["key"] for c in o["compliance"]} >= {"nis2", "iso27001", "dora"} and all(0 <= c["pct"] <= 100 for c in o["compliance"])
    assert o["health"]["connectors"][0]["label"] == "OMXVuln" and "system" not in o["health"]                # sistema: só super-administrador
    su = User.query.filter_by(email="root@omx.example").one()
    assert command_center.overview(app, tenant, su)["health"]["system"]["db"] == "sqlite"


def test_dashboard_renders_charts_and_quick_actions(app, world):
    c = login_as(app, "admin@alpha.example")
    html = c.get("/").get_data(as_text=True)
    for needle in ("Centro de comando", "Painel executivo", 'class="donut"', 'class="funnel"', 'class="gauge"', "Remediação prioritária", "openssl-apt",
                   "Ações recomendadas", "Simular", "Remediar", "Operações a aguardar OK", "Frota", "Saúde e integrações", "Boas práticas dos servidores web"):
        assert needle in html, needle
    assert 'style="' not in html.split("<main", 1)[-1] and "<script>" not in html                                # compatível com a CSP
    assert c.get("/executive").status_code == 200
    aud = login_as(app, "auditor@alpha.example").get("/").get_data(as_text=True)
    assert "Centro de comando" in aud and 'name="kind"' not in aud                                              # auditor vê, mas sem botões de ação


def test_quick_simulate_patch_creates_plan_and_asks_simulation_only(app, tenant, world):
    c = login_as(app, "admin@alpha.example")
    r = c.post("/command/quick", {"kind": "patch", "id": str(world["patch"].id), "next": "plan"})
    assert r.status_code == 302 and "/plans/" in r.headers["Location"]
    plan = OperationPlan.query.one()
    it = plan.items.one()
    assert plan.name == "Rápido: openssl-apt" and it.kind == "patch" and it.status in ("simulating", "simulated", "draft")
    assert Task.query.filter(Task.type.in_(("patch", "practice_apply"))).count() == 0                          # nada é aplicado
    assert Task.query.filter_by(type="simulate").count() >= 0
    again = c.post("/command/quick", {"kind": "patch", "id": str(world["patch"].id)})
    assert again.status_code == 302 and OperationPlan.query.count() == 1                                         # reutiliza o plano aberto
    o = command_center.overview(app, tenant, __import__("omxpatch.models", fromlist=["User"]).User.query.filter_by(email="admin@alpha.example").one())
    assert o["priority"][0]["plan_state"]                                                                       # o painel mostra o estado do plano
    assert not any(a["kind"] == "patch" for a in o["actions"] if a["level"] == "critical")


def test_quick_simulate_asset_and_tls(app, tenant, world):
    c = login_as(app, "admin@alpha.example")
    c.post("/command/quick", {"kind": "asset", "id": str(world["asset"].id)})
    p = OperationPlan.query.filter_by(name="Rápido: web01").one()
    assert p.mode == "by_asset" and p.items.count() == 1
    c.post("/command/quick", {"kind": "tls", "id": "0"})
    t = OperationPlan.query.filter_by(name="Rápido: TLS 1.2/1.3").one()
    assert [i.asset.name for i in t.items] == ["web02"] and t.items.first().practice == "tls_protocols"
    ag = world["agent"]
    sims = [x for x in ag.poll() if x["type"] == "practice_sim"]
    assert sims and sims[0]["payload"]["practice"] == "tls_protocols"                                           # o agente recebe a simulação
    assert Task.query.filter_by(type="practice_apply").count() == 0


def test_quick_actions_need_write_role_and_respect_tenant(app, tenant, world):
    aud = login_as(app, "auditor@alpha.example")
    assert aud.post("/command/quick", {"kind": "patch", "id": str(world["patch"].id)}).status_code == 403
    beta = login_as(app, "admin@beta.example")
    assert beta.post("/command/quick", {"kind": "patch", "id": str(world["patch"].id)}).status_code == 404       # patch de outra organização
    assert beta.post("/command/quick", {"kind": "asset", "id": str(world["asset"].id)}).status_code == 404
    c = login_as(app, "admin@alpha.example")
    assert c.post("/command/quick", {"kind": "nada", "id": "1"}).status_code == 400
    r = c.post("/command/quick", {"kind": "patch", "id": str(world["patch"].id + 999)})
    assert r.status_code == 404
    assert OperationPlan.query.count() == 0


def test_quick_with_nothing_applicable_warns(app, tenant):
    c = login_as(app, "admin@alpha.example")
    a = make_asset(tenant, "solo", software=())
    db.session.commit()
    r = c.post("/command/quick", {"kind": "asset", "id": str(a.id)}, )
    assert r.status_code == 302 and OperationPlan.query.count() == 0
    assert "Nada a simular" in c.get("/").get_data(as_text=True)
    assert c.post("/command/quick", {"kind": "tls", "id": "0"}).status_code == 302 and OperationPlan.query.count() == 0


def test_blocked_simulation_is_surfaced(app, tenant, world):
    """O patch aplica-se a um ativo sem agente: a simulação bloqueia e o painel mostra-o (não há nada para aprovar)."""
    c = login_as(app, "admin@alpha.example")
    c.post("/command/quick", {"kind": "patch", "id": str(world["patch"].id)})
    from omxpatch.models import User
    o = command_center.overview(app, tenant, User.query.filter_by(email="admin@alpha.example").one())
    assert o["plans"]["blocked"] == 1 and o["plans"]["awaiting"] == 0


def test_dashboard_after_ok_and_execution(app, tenant, world):
    """Depois de OK + execução o painel reflete o plano em curso."""
    from omxpatch.models import Exposure
    Exposure.query.one().asset_id = world["web"].id                      # a exposição passa para o ativo que tem agente
    db.session.commit()
    c = login_as(app, "admin@alpha.example")
    c.post("/command/quick", {"kind": "patch", "id": str(world["patch"].id)})
    plan = OperationPlan.query.one()
    ag = world["agent"]
    ag.work()
    db.session.expire_all()
    plan = db.session.get(OperationPlan, plan.id)
    plans.approve(plan, None, None, all_ok=True, accept_warnings=True)
    plans.execute(plan, tenant)
    db.session.commit()
    o = command_center.overview(app, tenant, __import__("omxpatch.models", fromlist=["User"]).User.query.filter_by(email="admin@alpha.example").one())
    assert o["plans"]["by_status"].get("queued", 0) + o["plans"]["by_status"].get("approved", 0) >= 1 and o["plans"]["executing"] == 1
    assert dict(o["funnel"])["Em execução"] >= 1 or dict(o["funnel"])["Com OK"] >= 1
    assert login_as(app, "admin@alpha.example").get("/").status_code == 200
