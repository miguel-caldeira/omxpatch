"""Boas práticas (TLS 1.2/1.3 em nginx/Apache/IIS) e planos de operações: simular → OK explícito → executar (por patch ou por ativo)."""
import json
import socket
import ssl
import subprocess
import threading
from datetime import timedelta

import pytest

from omxpatch.engine import plans, practices
from omxpatch.extensions import db
from omxpatch.models import Asset, OperationPlan, Patch, PlanItem, Task, utcnow
from omxpatch_agent import practices as agent_pr
from omxpatch_agent.practices import common, iis
from omxpatch_agent.practices.webservers import nginx_statements
from omxpatch_agent.runner import Result
from tests.conftest import login_as, make_asset
from tests.test_flow import FakeAgent, enroll_token  # noqa: F401
from tests.test_web import _api_token


# ------------------------------------------------------------------ helpers do agente


def test_replace_directives_keeps_indent_and_skips_comments():
    text = "http {\n    ssl_protocols TLSv1 TLSv1.1;\n    # ssl_protocols old;\n    ssl_protocols TLSv1.2 TLSv1.3;\n}\n"
    out, n = common.replace_directives(text, r"ssl_protocols\b", "ssl_protocols TLSv1.2 TLSv1.3;")
    assert n == 1 and "    ssl_protocols TLSv1.2 TLSv1.3;\n    # ssl_protocols old;" in out
    assert common.replace_directives(out, r"ssl_protocols\b", "ssl_protocols TLSv1.2 TLSv1.3;")[1] == 0     # idempotente
    assert common.has_line(text, r"ssl_protocols") and not common.has_line("# ssl_protocols x", r"ssl_protocols")


def test_diff_and_edit_action():
    e = common.Edit("/etc/x.conf", "a\n", "b\n", "troca")
    assert e.changed and "(atual)" in e.action()["diff"] and e.action()["kind"] == "editar ficheiro"
    assert common.Edit("/etc/y.conf", None, "novo\n").action()["kind"] == "criar ficheiro"
    assert not common.Edit("/z", "a", "a").changed


def test_judge_matrix():
    good = {"TLSv1": "rejected", "TLSv1.1": "rejected", "TLSv1.2": "accepted", "TLSv1.3": "accepted"}
    assert common.judge_matrix(good, True) == (True, [])
    ok, bad = common.judge_matrix({**good, "TLSv1.1": "accepted", "TLSv1.3": "rejected"}, True)
    assert not ok and any("TLSv1.1" in b for b in bad) and any("1.3" in b for b in bad)
    assert common.judge_matrix({**good, "TLSv1.3": "untestable"}, False)[0]
    assert not common.judge_matrix({**good, "TLSv1.2": "rejected"}, False)[0]


def test_nginx_statement_parser_handles_comments_strings_and_blocks():
    text = 'http {\n  # server { fake }\n  add_header X "a;b";\n  server {\n    listen 443 ssl;\n    ssl_protocols TLSv1.2;\n  }\n}\nevents {}\n'
    st = nginx_statements(text)
    ssl_ = [s for s in st if s[0].startswith("ssl_protocols")]
    assert ssl_ and tuple(ssl_[0][1]) == ("http", "server")
    assert any(s[0].startswith("add_header") and tuple(s[1]) == ("http",) for s in st)
    assert not any("fake" in s[0] for s in st)


@pytest.fixture()
def tls_server(tmp_path):
    """Servidor TLS local (certificado auto-assinado) limitado a TLS 1.2+ para testar o verificador real."""
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt), "-days", "1",
                        "-subj", "/CN=localhost"], capture_output=True)
    if r.returncode:
        pytest.skip("openssl indisponível")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(crt, key)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    stop = threading.Event()

    def loop():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except OSError:
                continue
            try:
                ctx.wrap_socket(c, server_side=True).close()
            except (OSError, ssl.SSLError):
                c.close()

    th = threading.Thread(target=loop, daemon=True)
    th.start()
    yield srv.getsockname()[1]
    stop.set()
    th.join(2)
    srv.close()


def test_real_tls_probe_against_local_server(tls_server):
    assert common.tls_speaks("127.0.0.1", tls_server)
    assert common.tls_probe("127.0.0.1", tls_server, "TLSv1.2") == "accepted"
    assert common.tls_probe("127.0.0.1", tls_server, "TLSv1.1") in ("rejected", "untestable")      # nunca «accepted»
    ok, bad = common.judge_matrix(common.tls_matrix("127.0.0.1", tls_server), False)
    assert ok, bad


# ------------------------------------------------------------------ IIS (PowerShell simulado)


class FakePS:
    """Simula o Windows: registo e cabeçalhos em dicionários; regista os scripts executados."""

    def __init__(self, build=20348, registry=None, headers=None, fail_on=None):
        self.build, self.registry, self.headers, self.fail_on, self.scripts = build, registry or {}, headers or {}, fail_on, []

    def __call__(self, script, timeout=60, *a, **k):
        if "Get-Service W3SVC" in script:
            return Result(0, json.dumps({"status": "Running", "version": "Version 10.0", "build": self.build, "webadmin": True}))
        if "$o = @{}" in script:
            return Result(0, json.dumps(self.registry))
        if "customHeaders' -Name '.' -ErrorAction" in script:
            return Result(0, json.dumps(self.headers))
        self.scripts.append(script)
        if self.fail_on and self.fail_on in script:
            return Result(1, "acesso negado")
        return Result(0, "")


def _reg_ok(params):
    return {f"{k}|{n}": v for k, n, v in iis.schannel_targets(params, 20348)}


def test_iis_tls_plan_requires_reboot_and_is_idempotent(monkeypatch, tmp_path):
    monkeypatch.setattr(iis, "powershell", FakePS())
    monkeypatch.setattr(common, "backup_root", lambda: tmp_path)
    p = iis.plan("tls_protocols", {"tls13": "auto"})
    regs = [c for c in p["changes"] if c["type"] == "registry"]
    assert regs and p["predicted"]["reboot"] and not p["predicted"]["compliant"]
    assert any("TLS 1.0" in c["key"] and c["name"] == "Enabled" and c["new"] == 0 for c in regs)
    assert any("TLS 1.3" in c["key"] and c["new"] == 1 for c in regs)
    assert any(c["id"] == "reboot" and c["status"] == "warn" for c in p["checks"])
    monkeypatch.setattr(iis, "powershell", FakePS(registry=_reg_ok({"tls13": "auto"})))
    assert iis.plan("tls_protocols", {"tls13": "auto"})["predicted"]["compliant"]


def test_iis_old_windows_has_no_tls13_and_forced_13_blocks(monkeypatch):
    monkeypatch.setattr(iis, "powershell", FakePS(build=17763))
    p = iis.plan("tls_protocols", {"tls13": "auto"})
    assert not any("TLS 1.3" in c["key"] for c in p["changes"] if c["type"] == "registry")
    assert [c for c in p["checks"] if c["id"] == "tls13"][0]["status"] == "warn"
    assert [c for c in iis.plan("tls_protocols", {"tls13": "true"})["checks"] if c["id"] == "tls13"][0]["status"] == "block"


def test_iis_apply_success_and_auto_rollback_on_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(common, "backup_root", lambda: tmp_path)
    ps = FakePS()
    monkeypatch.setattr(iis, "powershell", ps)
    r = iis.apply("hsts", {"max_age": 100, "include_subdomains": False, "preload": False}, "item-1")
    assert r["status"] == "succeeded" and any("Strict-Transport-Security" in s and "max-age=100" in s for s in ps.scripts)
    ps2 = FakePS(headers={"X-Frame-Options": "DENY"}, fail_on="Referrer-Policy")
    monkeypatch.setattr(iis, "powershell", ps2)
    r = iis.apply("security_headers", {}, "item-2")
    assert r["status"] == "failed" and r["rolled_back"]
    assert any("X-Frame-Options" in s and "DENY" in s for s in ps2.scripts)                       # valor anterior reposto
    assert iis.rollback("item-1")                                                                   # backup do 1.º item existe


def test_iis_scripts_quote_values_safely():
    s = iis.change_script({"type": "header", "name": "X-A", "new": "it's;$(calc)"})
    assert "it''s;$(calc)" in s and "'it''s;$(calc)'" in s
    assert iis.revert_script({"type": "registry", "key": "HKLM:\\k", "name": "Enabled", "old": None, "new": 0}).startswith("Remove-ItemProperty")


def test_agent_simulate_without_webserver_blocks(monkeypatch):
    monkeypatch.setattr(agent_pr, "_servers", lambda params: [])
    r = agent_pr.simulate("tls_protocols", {})
    assert r["checks"][0]["status"] == "block" and r["actions"] == []
    assert agent_pr.simulate("nope")["checks"][0]["status"] == "block"
    assert agent_pr.apply("tls_protocols", {}, "i")["status"] == "failed"


# ------------------------------------------------------------------ servidor: catálogo e parâmetros


def test_catalog_and_param_validation():
    assert set(practices.PRACTICES) == set(agent_pr.PRACTICES)
    p = practices.clean_params("hsts", {"max_age": "999999999999", "include_subdomains": "x", "preload": "true", "evil": "1"})
    assert p == {"max_age": 63072000, "include_subdomains": True, "preload": True}
    assert practices.clean_params("tls_protocols", {"tls13": "hack"})["tls13"] == "auto"


# ------------------------------------------------------------------ fluxo: simular → OK → executar


def _agent(app, tenant, token, name="web1", os_family="linux", servers=("nginx",)):
    ag = FakeAgent(app, token, name, os_family=os_family, software=())
    ag.inventory()
    a = Asset.query.filter_by(name=name).one()
    a.hardware = json.dumps({"webservers": [{"type": s} for s in servers]})
    db.session.commit()
    return ag, a


def _sim_report(compliant=False, block=False):
    checks = [{"id": "nginx:config", "label": "nginx -t", "status": "block" if block else "ok", "detail": ""}]
    return {"status": "succeeded", "checks": checks,
            "actions": [] if compliant else [{"target": "/etc/nginx/conf.d/omx.conf", "kind": "criar ficheiro", "summary": "TLS", "diff": "+ssl_protocols TLSv1.2;", "reversible": True}],
            "predicted": {"noop": compliant, "compliant": compliant, "reload": True}}


def _answer_sims(ag, **kw):
    n = 0
    for t in ag.poll():
        if t["type"] == "practice_sim":
            ag.c.post(f"/agent/v1/tasks/{t['id']}/start", headers=ag.h, json={})
            ag.result(t["id"], _sim_report(**kw))
            n += 1
    return n


def test_practice_plan_cannot_run_before_simulation_and_ok(app, tenant, enroll_token):
    ag, a = _agent(app, tenant, enroll_token)
    plan = plans.create(tenant, "TLS", "by_asset", [a.id], [], [{"id": "tls_protocols", "params": {}}])
    db.session.commit()
    it = plan.items.first()
    assert it.status == "draft" and plans.execute(plan, tenant)["queued"] == 0
    assert Task.query.filter_by(type="practice_apply").count() == 0
    assert plans.approve(plan, [it.id], None)["approved"] == 0                      # sem simulação não há OK possível
    plans.simulate(plan, tenant)
    db.session.commit()
    assert it.status == "simulating" and plans.approve(plan, [it.id], None)["approved"] == 0
    assert _answer_sims(ag) == 1
    db.session.refresh(it)
    assert it.status == "simulated" and it.sim_outcome == "ready" and it.action_list[0]["diff"]
    assert plans.execute(plan, tenant)["queued"] == 0                               # simulado mas sem OK → nada corre
    assert Task.query.filter_by(type="practice_apply").count() == 0
    assert plans.approve(plan, [it.id], None)["approved"] == 1
    assert plans.execute(plan, tenant)["queued"] == 1
    t = Task.query.filter_by(type="practice_apply").one()
    assert t.payload_data["practice"] == "tls_protocols" and t.payload_data["plan_item_id"] == it.id
    assert it.status == "queued" and t.status == "pending"      # só sai quando a hora/janela o permitir


def test_blocked_noop_stale_and_warning_gates(app, tenant, enroll_token):
    ag, a = _agent(app, tenant, enroll_token)
    plan = plans.create(tenant, "x", "by_asset", [a.id], [], [{"id": "hsts"}])
    db.session.commit()
    it = plan.items.first()
    plans.simulate(plan, tenant)
    _answer_sims(ag, block=True)
    db.session.refresh(it)
    assert it.sim_outcome == "blocked" and not plans.eligible(it)[0] and plans.approve(plan, None, None, all_ok=True)["approved"] == 0
    plans.simulate(plan, tenant, only=[it.id])
    db.session.commit()
    _answer_sims(ag, compliant=True)
    db.session.refresh(it)
    assert it.sim_outcome == "noop" and "nada a aplicar" in plans.eligible(it)[1]
    # aviso exige aceitação explícita
    from omxpatch.engine import plans as P
    P._set_sim(it, "warning", [{"id": "c", "label": "l", "status": "warn", "detail": ""}], [{"target": "t", "kind": "k", "summary": "s", "diff": "", "reversible": True}], {})
    res = plans.approve(plan, [it.id], None)
    assert res["approved"] == 0 and "avisos" in res["refused"][0][1]
    assert plans.approve(plan, [it.id], None, accept_warnings=True)["approved"] == 1 and it.accepted_warnings
    # simulação caducada: o OK deixa de valer e a execução recusa
    it.sim_at = utcnow() - timedelta(hours=25)
    res = plans.execute(plan, tenant)
    assert res["queued"] == 0 and it.status == "simulated" and "caducou" in res["skipped"][0][1]


def test_mixed_plan_by_patch_runs_only_approved_items(app, tenant, enroll_token):
    ag1, a1 = _agent(app, tenant, enroll_token, "web1")
    ag2, a2 = _agent(app, tenant, enroll_token, "web2")
    plan = plans.create(tenant, "multi", "by_asset", [a1.id, a2.id], [], [{"id": "tls_protocols"}, {"id": "hide_version"}])
    db.session.commit()
    assert plan.items.count() == 4
    plans.simulate(plan, tenant)
    db.session.commit()
    _answer_sims(ag1); _answer_sims(ag2)
    db.session.refresh(plan)
    first = [i for i in plan.items if i.asset_id == a1.id and i.practice == "tls_protocols"][0]
    assert plans.approve(plan, [first.id], None)["approved"] == 1                  # só um dos 4 itens tem OK
    assert plans.execute(plan, tenant)["queued"] == 1
    assert Task.query.filter_by(type="practice_apply").count() == 1
    assert plans.approve(plan, None, None, all_ok=True)["approved"] == 3
    assert plans.execute(plan, tenant)["queued"] == 3


def test_task_outcomes_update_items_and_revert(app, tenant, enroll_token):
    ag, a = _agent(app, tenant, enroll_token)
    plan = plans.create(tenant, "o", "by_asset", [a.id], [], [{"id": "hsts"}, {"id": "hide_version"}])
    db.session.commit()
    plans.simulate(plan, tenant); db.session.commit(); _answer_sims(ag)
    db.session.refresh(plan)
    plans.approve(plan, None, None, all_ok=True); plans.execute(plan, tenant); db.session.commit()
    assert plans.release(tenant, utcnow()) == 2
    db.session.commit()
    tasks = ag.poll()
    assert len(tasks) == 2 and all(t["type"] == "practice_apply" for t in tasks)
    outcomes = {}
    for t, rep in zip(tasks, ({"status": "succeeded", "output": "ok"}, {"status": "failed", "rolled_back": True, "output": "nginx -t falhou"})):
        ag.c.post(f"/agent/v1/tasks/{t['id']}/start", headers=ag.h, json={})
        mid = db.session.get(PlanItem, t["payload"]["plan_item_id"])
        assert mid.status == "running"
        ag.result(t["id"], rep)
        outcomes[t["payload"]["practice"]] = rep["status"]
    db.session.expire_all()
    by = {i.practice: i for i in db.session.get(OperationPlan, plan.id).items}
    assert by["hsts"].status == "succeeded" and by["hide_version"].status == "rolled_back" and "nginx -t" in by["hide_version"].output
    assert db.session.get(OperationPlan, plan.id).status == "completed"
    with pytest.raises(plans.PlanError):
        plans.revert(by["hide_version"], tenant)
    t = plans.revert(by["hsts"], tenant)
    db.session.commit()
    assert t.type == "practice_rollback"
    (rt,) = ag.poll()
    ag.result(rt["id"], {"status": "succeeded", "output": "1 restaurado"})
    db.session.expire_all()
    assert db.session.get(PlanItem, by["hsts"].id).status == "reverted"


def test_release_respects_start_at(app, tenant, enroll_token):
    ag, a = _agent(app, tenant, enroll_token)
    future = utcnow() + timedelta(hours=2)
    plan = plans.create(tenant, "s", "by_asset", [a.id], [], [{"id": "hide_version"}], start_at=future, respect_windows=False)
    db.session.commit()
    plans.simulate(plan, tenant); db.session.commit(); _answer_sims(ag)
    db.session.refresh(plan)
    plans.approve(plan, None, None, all_ok=True); plans.execute(plan, tenant); db.session.commit()
    t = Task.query.filter_by(type="practice_apply").one()
    assert t.status == "pending" and plans.release(tenant, utcnow()) == 0
    assert plans.release(tenant, future + timedelta(minutes=1)) == 1 and t.status == "queued"


def test_asset_without_agent_and_incompatible_are_blocked(app, tenant):
    a = make_asset(tenant, "noagent", software=())
    mac = make_asset(tenant, "mac1", software=(), os_family="macos", ip="10.0.0.8")
    plan = plans.create(tenant, "b", "by_asset", [a.id, mac.id], [], [{"id": "tls_protocols"}])
    db.session.commit()
    by = {i.asset.name: i for i in plan.items}
    assert by["mac1"].sim_outcome == "blocked"
    plans.simulate(plan, tenant)
    assert by["noagent"].sim_outcome == "blocked" and "agente" in by["noagent"].output + json.dumps(by["noagent"].check_list)
    with pytest.raises(plans.PlanError):
        plans.create(tenant, "e", "by_patch", [], [], [])
    with pytest.raises(plans.PlanError):
        plans.create(tenant, "e", "by_patch", [a.id], [], [{"id": "inexistente"}])


def test_cancel_stops_everything(app, tenant, enroll_token):
    ag, a = _agent(app, tenant, enroll_token)
    plan = plans.create(tenant, "c", "by_asset", [a.id], [], [{"id": "hide_version"}])
    db.session.commit()
    plans.simulate(plan, tenant); db.session.commit(); _answer_sims(ag)
    db.session.refresh(plan)
    plans.approve(plan, None, None, all_ok=True); plans.execute(plan, tenant)
    assert plans.cancel(plan) >= 1 and plan.status == "cancelled"
    assert Task.query.filter_by(type="practice_apply").one().status == "cancelled"
    assert plans.execute(plan, tenant)["queued"] == 0


def test_patch_items_use_preflight_and_need_ok(app, tenant, enroll_token):
    ag = FakeAgent(app, enroll_token, "srv1")
    ag.inventory()
    a = Asset.query.filter_by(name="srv1").one()
    p = Patch(tenant_id=tenant.id, patch_uid="openssl-apt", installer="apt", package_name="openssl", os_family="linux", status="approved",
              cves='["CVE-2026-0001"]')
    db.session.add(p); db.session.commit()
    plan = plans.create(tenant, "p", "by_patch", [a.id], [p.id], [])
    db.session.commit()
    it = plan.items.first()
    plans.simulate(plan, tenant); db.session.commit()
    assert ag.work() == 1                                                         # só a simulação corre
    db.session.expire_all()
    it = db.session.get(PlanItem, it.id)
    assert it.kind == "patch" and it.status == "simulated" and it.sim_outcome in ("ready", "warning")
    assert Task.query.filter_by(type="patch").count() == 0
    plan = db.session.get(OperationPlan, plan.id)
    plans.approve(plan, None, None, all_ok=True, accept_warnings=True)
    assert plans.execute(plan, tenant)["queued"] == 1 and Task.query.filter_by(type="patch").count() == 1


# ------------------------------------------------------------------ web e API


def _form(client, url, data):
    return client.post(url, data)


def test_ui_pages_and_ok_checkbox_required(app, tenant, enroll_token):
    ag, a = _agent(app, tenant, enroll_token)
    admin = login_as(app, "admin@alpha.example")
    assert admin.get("/practices").status_code == 200 and b"TLS 1.2" in admin.get("/practices").data
    assert admin.get("/plans").status_code == 200 and admin.get(f"/plans/new?asset_id={a.id}&practice=tls_protocols").status_code == 200
    r = admin.post("/plans/new", {"name": "UI", "mode": "by_asset", "asset_ids": str(a.id), "practice_tls_protocols": "1"})
    assert r.status_code in (302, 303), r.data[:300]
    plan = OperationPlan.query.filter_by(name="UI").one()
    assert admin.get(f"/plans/{plan.id}").status_code == 200 and admin.get(f"/plans/{plan.id}?by=asset").status_code == 200
    admin.post(f"/plans/{plan.id}/simulate", {})
    _answer_sims(ag)
    assert admin.get(f"/plans/{plan.id}").status_code == 200
    admin.post(f"/plans/{plan.id}/approve", {"all_ok": "1"})                         # sem a caixa OK
    db.session.expire_all()
    assert plan.items.first().status == "simulated"
    admin.post(f"/plans/{plan.id}/approve", {"all_ok": "1", "confirm_ok": "1"})
    db.session.expire_all()
    assert plan.items.first().status == "approved"
    admin.post(f"/plans/{plan.id}/execute", {})
    assert Task.query.filter_by(type="practice_apply").count() == 1
    assert admin.get(f"/plans/items/{plan.items.first().id}").status_code == 200


def test_rbac_and_tenant_isolation_for_plans(app, tenant):
    from omxpatch.models import Tenant
    a = make_asset(tenant, "w", software=())
    plan = plans.create(tenant, "iso", "by_asset", [a.id], [], [{"id": "hsts"}])
    db.session.commit()
    aud = login_as(app, "auditor@alpha.example")
    assert aud.get("/plans").status_code == 200
    assert aud.post(f"/plans/{plan.id}/simulate", {}).status_code == 403
    assert aud.post(f"/plans/{plan.id}/approve", {"confirm_ok": "1", "all_ok": "1"}).status_code == 403
    beta = login_as(app, "admin@beta.example")
    assert beta.get(f"/plans/{plan.id}").status_code == 404
    assert beta.post(f"/plans/{plan.id}/execute", {}).status_code == 404


def test_api_plans_require_explicit_ok(app, tenant, enroll_token):
    ag, a = _agent(app, tenant, enroll_token)
    admin = login_as(app, "admin@alpha.example")
    h = {"Authorization": f"Bearer {_api_token(admin)}"}
    c = app.test_client()
    cat = c.get("/api/v1/practices", headers=h).get_json()
    assert {x["id"] for x in cat} == set(practices.PRACTICES)
    r = c.post("/api/v1/plans", headers=h, json={"name": "api", "mode": "by_asset", "asset_ids": [a.id], "practices": [{"id": "tls_protocols"}]})
    assert r.status_code == 201
    pid = r.get_json()["id"]
    assert c.post("/api/v1/plans", headers=h, json={"asset_ids": [a.id], "practices": [{"id": "x"}]}).status_code == 400
    assert c.post(f"/api/v1/plans/{pid}/execute", headers=h).get_json()["queued"] == 0
    assert c.post(f"/api/v1/plans/{pid}/simulate", headers=h).status_code == 202
    _answer_sims(ag)
    assert c.post(f"/api/v1/plans/{pid}/approve", headers=h, json={"all_ok": True}).status_code == 400      # falta "ok": true
    assert c.post(f"/api/v1/plans/{pid}/execute", headers=h).get_json()["queued"] == 0
    assert c.post(f"/api/v1/plans/{pid}/approve", headers=h, json={"ok": True, "all_ok": True}).get_json()["approved"] == 1
    assert c.post(f"/api/v1/plans/{pid}/execute", headers=h).get_json()["queued"] == 1
    got = c.get(f"/api/v1/plans/{pid}", headers=h).get_json()
    assert got["items"][0]["status"] == "queued" and got["items"][0]["actions"][0]["diff"]
    assert len(c.get("/api/v1/plans", headers=h).get_json()) == 1
