"""Isolamento do ativo, linha de base (gold images), endurecimento do SO e governação ITSM (desativada por omissão)."""
import json
import time

import pytest
import requests

from omxpatch.connectors import store
from omxpatch.engine import baseline, controls, itsm, plans
from omxpatch.extensions import db
from omxpatch.models import Asset, BaselineItem, ControlAction, OperationPlan, Patch, PlanItem, Task, utcnow
from omxpatch_agent import isolation
from omxpatch_agent.practices import common, oshardening
from omxpatch_agent.runner import Result
from tests.conftest import login_as, make_asset
from tests.test_connectors import Resp, http  # noqa: F401
from tests.test_flow import FakeAgent, enroll_token  # noqa: F401
from tests.test_practices import _agent, _answer_sims


# ------------------------------------------------------------------ isolamento (agente)


@pytest.fixture()
def iso(tmp_path, monkeypatch):
    monkeypatch.setattr(isolation.config, "config_dir", lambda: tmp_path)
    monkeypatch.setattr(isolation, "platform_family", lambda: "linux")
    monkeypatch.setattr(isolation.shutil, "which", lambda n: "/usr/sbin/" + n if n == "nft" else None)
    calls = []

    def run(cmd, timeout=60, input_text=None, **k):
        calls.append((cmd, input_text))
        return Result(0, "")
    monkeypatch.setattr(isolation, "run", run)
    monkeypatch.setattr(isolation, "console_endpoints", lambda: [("10.0.0.5", 4444)])
    monkeypatch.setattr(isolation, "reachable", lambda eps, timeout=4.0: True)
    return calls


def test_isolation_keeps_only_console_and_is_reversible(iso):
    r = isolation.isolate({"ttl_minutes": 30})
    assert r["verified"] and "Libertação automática em 30 min" in r["detail"]
    rules = iso[0][1]
    assert "policy drop" in rules and "ip daddr 10.0.0.5 tcp dport 4444 accept" in rules and "iif lo accept" in rules and "ct state established,related accept" in rules
    assert "tcp dport 22" not in rules and isolation.state()["active"]
    assert isolation.isolate({})["detail"] == "O ativo já está isolado"
    out = isolation.release({})
    assert "removido" in out["detail"] and any(c[0][:4] == ["nft", "delete", "table", "inet"] for c in iso) and not isolation.state()["active"]


def test_isolation_safeguards(iso, monkeypatch):
    r = isolation.nft_ruleset([("10.0.0.5", 4444), ("2001:db8::5", 4444)], ["192.0.2.7"])
    assert "ip6 daddr 2001:db8::5 tcp dport 4444 accept" in r and "ip saddr 192.0.2.7 tcp dport 22 accept" in r
    with pytest.raises(isolation.IsolationError):
        isolation.isolate({"keep_ssh_from": ["não-é-ip"]})
    monkeypatch.setattr(isolation, "console_endpoints", lambda: [])
    with pytest.raises(isolation.IsolationError, match="cortar-se"):                                                   # sem lista da consola: recusa
        isolation.isolate({})
    assert not isolation.state().get("active")
    monkeypatch.setattr(isolation, "console_endpoints", lambda: [("10.0.0.5", 4444)])
    monkeypatch.setattr(isolation, "reachable", lambda eps, timeout=4.0: False)
    with pytest.raises(isolation.IsolationError, match="desfeito automaticamente"):                                    # consola inacessível: desfaz sozinho
        isolation.isolate({})
    assert not isolation.state()["active"]
    assert ["nft", "delete", "table", "inet", isolation.TABLE] in [c[0] for c in iso]
    monkeypatch.setattr(isolation, "reachable", lambda eps, timeout=4.0: True)
    isolation.isolate({"ttl_minutes": 1})                                                                              # mínimo de 5 min
    assert isolation.state()["ttl_minutes"] == 5 and not isolation.expired() and isolation.expired(time.time() + 400)
    assert isolation.release_if_expired() is False
    st = isolation.state()
    st["expires_at"] = time.time() - 1
    isolation._save(st)
    assert isolation.release_if_expired() is True and not isolation.state()["active"]                                   # validade: liberta sozinho
    assert max(5, min(99999, isolation.MAX_TTL)) == 1440


def test_isolation_task_through_executor(iso):
    from omxpatch_agent import executor
    res = executor.HANDLERS["control"](None, {"payload": {"op": "isolate", "ttl_minutes": 20}})
    assert res["status"] == "succeeded" and res["verified"]
    assert executor.HANDLERS["control"](None, {"payload": {"op": "isolate_release"}})["status"] == "succeeded"
    assert executor.HANDLERS["control"](None, {"payload": {"op": "isolate", "keep_ssh_from": ["x"]}})["status"] == "failed"


# ------------------------------------------------------------------ isolamento (servidor): proposta → aprovação → aplicação


def test_isolation_control_requires_approval_agent_and_can_be_released(app, tenant, enroll_token):
    ag, a = _agent(app, tenant, enroll_token)
    bare = make_asset(tenant, "semagente", software=(), ip="10.0.0.99")
    c = controls.propose_isolation(tenant, a, ttl_minutes=60, keep_ssh_from=["192.0.2.1"])
    db.session.commit()
    assert c.status == "proposed" and c.action == "isolate_host" and c.category == "isolation" and "Isolamento preventivo" in c.artifact
    with pytest.raises(ValueError):
        controls.apply(c, tenant)                                                                                      # sem aprovação não aplica
    controls.approve(c, None)
    controls.apply(c, tenant)
    db.session.commit()
    t = Task.query.filter_by(type="control").one()
    assert t.payload_data["op"] == "isolate" and t.payload_data["ttl_minutes"] == 60 and t.payload_data["keep_ssh_from"] == ["192.0.2.1"]
    c2 = controls.propose_isolation(tenant, bare)
    controls.approve(c2, None)
    with pytest.raises(ValueError, match="agente"):
        controls.apply(c2, tenant)
    c.status = "applied"
    rel = controls.release_isolation(c, tenant)
    db.session.commit()
    assert rel.payload_data["op"] == "isolate_release" and rel.payload_data["revert"]
    with pytest.raises(ValueError):
        controls.release_isolation(ControlAction(action="block_port", asset_id=a.id), tenant)


def test_isolation_pages_and_rbac(app, tenant, enroll_token):
    ag, a = _agent(app, tenant, enroll_token)
    admin = login_as(app, "admin@alpha.example")
    assert "Propor isolamento" in admin.get(f"/assets/{a.id}").get_data(as_text=True)
    r = admin.post(f"/assets/{a.id}/isolate", {"ttl": "30", "keep_ssh_from": "192.0.2.1, 192.0.2.2"})
    assert r.status_code == 302 and "/controls/" in r.headers["Location"]
    c = ControlAction.query.filter_by(action="isolate_host").one()
    assert c.status == "proposed" and c.params_data["keep_ssh_from"] == ["192.0.2.1", "192.0.2.2"] and c.params_data["ttl_minutes"] == 30
    assert login_as(app, "auditor@alpha.example").post(f"/assets/{a.id}/isolate", {}).status_code == 403
    assert login_as(app, "admin@beta.example").post(f"/assets/{a.id}/isolate", {}).status_code == 404
    c.status = "applied"
    db.session.commit()
    assert "Libertar isolamento" in admin.get(f"/controls/{c.id}").get_data(as_text=True)
    admin.post(f"/controls/{c.id}/release", {})
    assert Task.query.filter_by(type="control").filter(Task.payload.contains("isolate_release")).count() == 1


# ------------------------------------------------------------------ linha de base (gold images)


def _done_plan_item(tenant, asset, kind, **kw):
    plan = OperationPlan(tenant_id=tenant.id, name="p", mode="by_asset", status="completed")
    db.session.add(plan)
    db.session.flush()
    it = PlanItem(tenant_id=tenant.id, plan_id=plan.id, asset_id=asset.id, kind=kind, status="succeeded", **kw)
    db.session.add(it)
    db.session.flush()
    return it


def test_successful_remediations_feed_the_baseline_and_drift(app, tenant):
    a = make_asset(tenant, "srv1", software=(("openssl", "3.0.1"),))
    b = make_asset(tenant, "srv2", software=(("openssl", "3.0.13"),), ip="10.0.0.6")
    p = Patch(tenant_id=tenant.id, patch_uid="apt:openssl=3.0.13", installer="apt", package_name="openssl", version_fixed="3.0.13", os_family="linux", cves='["CVE-2026-1"]', status="approved")
    p2 = Patch(tenant_id=tenant.id, patch_uid="apt:openssl=3.0.15", installer="apt", package_name="openssl", version_fixed="3.0.15", os_family="linux", cves='["CVE-2026-2"]', status="approved")
    db.session.add_all([p, p2])
    db.session.flush()
    baseline.capture(_done_plan_item(tenant, b, "patch", patch_id=p.id))
    baseline.capture(_done_plan_item(tenant, b, "patch", patch_id=p2.id))
    row = BaselineItem.query.filter_by(kind="patch", name="openssl").one()
    assert row.min_version == "3.0.15" and sorted(row.cve_list) == ["CVE-2026-1", "CVE-2026-2"] and row.scope == "linux"      # sobe sempre
    baseline.capture(_done_plan_item(tenant, a, "practice", practice="tls_protocols", params='{"tls13": "auto"}'))
    prac = BaselineItem.query.filter_by(kind="practice").one()
    assert prac.name == "tls_protocols" and prac.params_data == {"tls13": "auto"}
    d = {x["asset"].name: x["gaps"] for x in baseline.drift(tenant)}
    assert {g["name"] for g in d["srv1"]} >= {"openssl"} and d["srv1"][0] == {"kind": "patch", "name": "openssl", "have": "3.0.1", "need": "3.0.15"}
    assert d["srv2"][0]["have"] == "3.0.13"                                                                            # também abaixo da mínima
    s = baseline.export_shell(tenant, "linux")
    assert "apt-get install -y --only-upgrade openssl" in s and "dpkg --compare-versions" in s and "3.0.15" in s and s.startswith("#!/bin/sh")
    y = baseline.export_ansible(tenant, "linux")
    assert "ansible.builtin.apt:" in y and "name: openssl" in y and "tls_protocols" in y and "CVE-2026-1" in y
    j = json.loads(baseline.export_json(tenant, "linux"))
    assert j["patches"][0]["min_version"] == "3.0.15" and j["practices"][0]["id"] == "tls_protocols"
    assert "omxpatch-baseline.sh" in baseline.export_packer(tenant, "linux")
    sh = baseline.export_shell(tenant, "linux").replace(";", "")
    assert baseline.export_shell(tenant, "windows").count("apt-get") == 0                                              # âmbito próprio


def test_baseline_fed_by_real_task_completion_and_pages(app, tenant, enroll_token):
    ag, a = _agent(app, tenant, enroll_token)
    plan = plans.create(tenant, "TLS", "by_asset", [a.id], [], [{"id": "hide_version", "params": {}}])
    db.session.commit()
    plans.simulate(plan, tenant)
    db.session.commit()
    _answer_sims(ag)
    db.session.refresh(plan)
    plans.approve(plan, None, None, all_ok=True)
    plans.execute(plan, tenant)
    plans.release(tenant, utcnow())
    db.session.commit()
    (t,) = [x for x in ag.poll() if x["type"] == "practice_apply"]
    ag.c.post(f"/agent/v1/tasks/{t['id']}/start", headers=ag.h, json={})
    assert BaselineItem.query.count() == 0
    ag.result(t["id"], {"status": "succeeded", "output": "ok"})
    db.session.expire_all()
    row = BaselineItem.query.one()
    assert row.kind == "practice" and row.name == "hide_version" and row.scope == "linux" and row.source_plan_id == plan.id
    admin = login_as(app, "admin@alpha.example")
    html = admin.get("/baseline").get_data(as_text=True)
    assert "Linha de base" in html and "hide_version" in html and "Exportar linux" in html
    r = admin.get("/baseline/export?scope=linux&format=ansible")
    assert r.status_code == 200 and "attachment" in r.headers["Content-Disposition"] and "hide_version" in r.get_data(as_text=True)
    assert admin.get("/baseline/export?scope=linux&format=x").status_code == 400
    admin.post("/baseline/add", {"scope": "windows", "kind": "patch", "name": "KB5031234", "min_version": "", "installer": "wua"})
    assert BaselineItem.query.filter_by(name="KB5031234").one().note == "manual"
    admin.post("/baseline/add", {"scope": "solaris", "kind": "patch", "name": "x"})
    assert BaselineItem.query.count() == 2
    admin.post(f"/baseline/{row.id}/remove", {})
    assert baseline.items(tenant, "linux") == []
    aud = login_as(app, "auditor@alpha.example")
    assert aud.get("/baseline").status_code == 200 and aud.post("/baseline/add", {"scope": "linux", "kind": "patch", "name": "y"}).status_code == 403
    assert login_as(app, "admin@beta.example").post(f"/baseline/{row.id}/remove", {}).status_code == 404
    from tests.test_web import _api_token
    api = app.test_client().get("/api/v1/baseline", headers={"Authorization": "Bearer " + _api_token(admin)}).get_json()
    assert [i["name"] for i in api["items"]] == ["KB5031234"]


# ------------------------------------------------------------------ ITSM: desativado por omissão; ativado exige a change


def _plan_ready(app, tenant, enroll_token, name="web1"):
    ag, a = _agent(app, tenant, enroll_token, name)
    plan = plans.create(tenant, "TLS", "by_asset", [a.id], [], [{"id": "tls_protocols", "params": {}}])
    db.session.commit()
    plans.simulate(plan, tenant)
    db.session.commit()
    _answer_sims(ag)
    db.session.refresh(plan)
    assert plans.approve(plan, None, None, all_ok=True)["approved"] == 1
    return ag, plan


def _snow(tenant, change_management="false", **opts):
    store.save(tenant.id, "servicenow", "https://acme.service-now.com", "svc", {"password": "pw"}, {"change_management": change_management, **opts}, True)
    db.session.commit()


def test_itsm_is_disabled_by_default_and_approval_is_entirely_in_the_solution(app, tenant, enroll_token, http):
    ag, plan = _plan_ready(app, tenant, enroll_token)
    assert not itsm.enabled(tenant) and itsm.gate(plan, tenant) == (True, "")                                           # sem integração: tudo na solução
    from omxpatch.connectors.catalog import KINDS
    assert all(KINDS[k]["options"]["change_management"] == "false" for k in ("servicenow", "jira", "freshservice"))     # por omissão desligado
    _snow(tenant)                                                                                                       # integração existe, mas change_management=false
    assert not itsm.enabled(tenant) and itsm.gate(plan, tenant) == (True, "")
    assert plans.execute(plan, tenant)["queued"] == 1 and not any(c["method"] == "POST" for c in http.calls)            # nunca contacta o ITSM
    with pytest.raises(itsm.ChangeError, match="desativada|não está ativada"):
        itsm.request_change_for_plan(plan, tenant)
    admin = login_as(app, "admin@alpha.example")
    html = admin.get(f"/plans/{plan.id}").get_data(as_text=True)
    assert "desativada" in html and "Pedir change" not in html


def test_itsm_enabled_blocks_execution_until_change_is_approved(app, tenant, enroll_token, http):
    ag, plan = _plan_ready(app, tenant, enroll_token)
    _snow(tenant, "true", assignment_group="Change Advisory")
    assert itsm.enabled(tenant)
    ok, why = itsm.gate(plan, tenant)
    assert not ok and "peça a change" in why
    res = plans.execute(plan, tenant)
    assert res["queued"] == 0 and "peça a change" in res["blocked_by_itsm"] and Task.query.filter_by(type="practice_apply").count() == 0
    http.routes[("POST", "/api/now/table/change_request")] = Resp({"result": {"number": "CHG0030012", "sys_id": "abc123"}}, 201)
    out = itsm.request_change_for_plan(plan, tenant)
    db.session.commit()
    body = [c for c in http.calls if c["method"] == "POST"][0]
    assert body["json"]["type"] == "normal" and body["json"]["assignment_group"] == "Change Advisory" and "OMXPatch #" in body["json"]["short_description"]
    assert "web1" in body["json"]["description"] and "nada foi aplicado" in body["json"]["description"].lower()
    assert out["ref"] == "CHG0030012" and plan.change_state == "requested" and "abc123" in plan.change_url
    assert itsm.request_change_for_plan(plan, tenant)["duplicate"]                                                      # não duplica
    http.routes[("GET", "/api/now/table/change_request/abc123")] = Resp({"result": {"state": "-4", "approval": "requested"}})
    ok, why = itsm.gate(plan, tenant)
    assert not ok and "CHG0030012" in why and plans.execute(plan, tenant)["queued"] == 0
    http.routes[("GET", "/api/now/table/change_request/abc123")] = Resp({"result": {"state": "-2", "approval": "approved"}})
    assert itsm.gate(plan, tenant) == (True, "") and plan.change_state == "approved"
    assert plans.execute(plan, tenant)["queued"] == 1                                                                   # aprovada: só agora executa


def test_itsm_never_approves_on_failure_or_rejection(app, tenant, enroll_token, http):
    ag, plan = _plan_ready(app, tenant, enroll_token)
    _snow(tenant, "true")
    http.routes[("POST", "/api/now/table/change_request")] = Resp({"result": {"number": "CHG1", "sys_id": "s1"}}, 201)
    itsm.request_change_for_plan(plan, tenant)

    def boom():
        raise requests.ConnectionError("ITSM em baixo")
    http.routes[("GET", "/api/now/table/change_request/s1")] = boom
    ok, why = itsm.gate(plan, tenant)
    assert not ok and plan.change_state == "requested" and "inacessível" in plan.change_detail                          # falha de comunicação: continua bloqueado
    http.routes[("GET", "/api/now/table/change_request/s1")] = Resp({"result": {"state": "-2", "approval": "rejected"}})
    assert not itsm.gate(plan, tenant)[0] and plan.change_state == "rejected"
    http.routes[("GET", "/api/now/table/change_request/s1")] = Resp({"result": {"state": "-2", "approval": "approved"}})
    assert not itsm.gate(plan, tenant)[0]                                                                               # rejeitada é final: não reabre
    http.routes[("POST", "/api/now/table/change_request")] = Resp({}, 500)
    ag2, plan2 = _plan_ready(app, tenant, enroll_token, "web2")
    with pytest.raises(itsm.ChangeError, match="Não foi possível"):
        itsm.request_change_for_plan(plan2, tenant)
    assert plan2.change_ref == ""


def test_itsm_result_is_written_back_when_plan_completes(app, tenant, enroll_token, http):
    ag, plan = _plan_ready(app, tenant, enroll_token)
    _snow(tenant, "true")
    http.routes[("POST", "/api/now/table/change_request")] = Resp({"result": {"number": "CHG2", "sys_id": "s2"}}, 201)
    http.routes[("GET", "/api/now/table/change_request/s2")] = Resp({"result": {"state": "-1", "approval": "approved"}})
    http.routes[("PATCH", "/api/now/table/change_request/s2")] = Resp({"result": {}})
    itsm.request_change_for_plan(plan, tenant)
    assert plans.execute(plan, tenant)["queued"] == 1
    plans.release(tenant, utcnow())
    db.session.commit()
    (t,) = [x for x in ag.poll() if x["type"] == "practice_apply"]
    ag.c.post(f"/agent/v1/tasks/{t['id']}/start", headers=ag.h, json={})
    ag.result(t["id"], {"status": "succeeded", "output": "ok"})
    db.session.expire_all()
    plan = db.session.get(OperationPlan, plan.id)
    assert plan.status == "completed"
    itsm.tick(tenant)
    db.session.commit()
    patch = [c for c in http.calls if c["method"] == "PATCH"][0]
    assert patch["json"]["state"] == "0" and patch["json"]["close_code"] == "successful" and "1/1" in patch["json"]["close_notes"]
    assert plan.change_state == "implemented"
    n = len([c for c in http.calls if c["method"] == "PATCH"])
    itsm.tick(tenant)
    assert len([c for c in http.calls if c["method"] == "PATCH"]) == n                                                  # escreve uma só vez


def test_itsm_jira_and_freshservice_state_mapping(app, tenant, http):
    store.save(tenant.id, "jira", "https://acme.atlassian.net", "me@x", {"password": "t"}, {"change_management": "true", "project": "CHG"}, True)
    db.session.commit()
    c = itsm.connector(tenant)
    http.routes[("POST", "/rest/api/3/issue")] = Resp({"key": "CHG-7"}, 201)
    res = itsm.create(c, "t", "d")
    assert res == {"ref": "CHG-7", "id": "CHG-7", "url": "https://acme.atlassian.net/browse/CHG-7"} and http.calls[0]["json"]["fields"]["issuetype"]["name"] == "Change"
    for name, want in (("Approved", "approved"), ("In Progress", "approved"), ("Rejected", "rejected"), ("Done", "closed"), ("Open", "requested")):
        http.routes[("GET", "/rest/api/3/issue/CHG-7")] = Resp({"fields": {"status": {"name": name}}})
        assert itsm.read_state(c, "CHG-7")[0] == want, name
    itsm.write_result(c, "CHG-7", True, "ok")
    assert http.calls[-1]["url"].endswith("/rest/api/3/issue/CHG-7/comment") and "[OMXPatch]" in json.dumps(http.calls[-1]["json"])
    store.save(tenant.id, "jira", "https://acme.atlassian.net", "me@x", {"password": "t"}, {"change_management": "false"}, True)
    store.save(tenant.id, "freshservice", "https://acme.freshservice.com", "k", {"password": "p"}, {"change_management": "true"}, True)
    db.session.commit()
    c = itsm.connector(tenant)
    assert c.kind == "freshservice"
    http.routes[("POST", "/api/v2/changes")] = Resp({"change": {"id": 55}}, 201)
    assert itsm.create(c, "t", "d")["ref"] == "CHG-55"
    for sid, want in (("4", "approved"), ("6", "rejected"), ("1", "requested")):
        http.routes[("GET", "/api/v2/changes/55")] = Resp({"change": {"status": sid}})
        assert itsm.read_state(c, "55")[0] == want


def test_itsm_gates_controls_only_when_enabled(app, tenant, enroll_token, http):
    ag, a = _agent(app, tenant, enroll_token)
    c = controls.propose_isolation(tenant, a)
    controls.approve(c, None)
    db.session.commit()
    controls.apply(c, tenant)                                                                                           # desativado: aplica sem change
    assert Task.query.filter_by(type="control").count() == 1
    c2 = controls.propose_isolation(tenant, a)
    controls.approve(c2, None)
    _snow(tenant, "true")
    with pytest.raises(ValueError, match="peça a change"):
        controls.apply(c2, tenant)
    http.routes[("POST", "/api/now/table/change_request")] = Resp({"result": {"number": "CHG9", "sys_id": "s9"}}, 201)
    assert itsm.request_change_for_control(c2, tenant)["ref"] == "CHG9"
    http.routes[("GET", "/api/now/table/change_request/s9")] = Resp({"result": {"state": "-5", "approval": "requested"}})
    with pytest.raises(ValueError, match="ainda não aprovada"):
        controls.apply(c2, tenant)
    http.routes[("GET", "/api/now/table/change_request/s9")] = Resp({"result": {"state": "-1", "approval": "approved"}})
    controls.apply(c2, tenant)
    assert Task.query.filter_by(type="control").count() == 2


def test_itsm_pages_and_api(app, tenant, enroll_token, http):
    from tests.test_web import _api_token
    ag, plan = _plan_ready(app, tenant, enroll_token)
    admin = login_as(app, "admin@alpha.example")
    h = {"Authorization": "Bearer " + _api_token(admin)}
    c = app.test_client()
    assert c.post(f"/api/v1/plans/{plan.id}/change", headers=h).status_code == 409                                      # desativado por omissão
    assert c.get(f"/api/v1/plans/{plan.id}/change", headers=h).get_json()["itsm_enabled"] is False
    _snow(tenant, "true")
    http.routes[("POST", "/api/now/table/change_request")] = Resp({"result": {"number": "CHG5", "sys_id": "s5"}}, 201)
    http.routes[("GET", "/api/now/table/change_request/s5")] = Resp({"result": {"state": "-5", "approval": "requested"}})
    html = admin.get(f"/plans/{plan.id}").get_data(as_text=True)
    assert "Pedir change no ITSM" in html and "ativa" in html
    admin.post(f"/plans/{plan.id}/request_change", {})
    db.session.expire_all()
    assert db.session.get(OperationPlan, plan.id).change_ref == "CHG5"
    admin.post(f"/plans/{plan.id}/execute", {})
    assert Task.query.filter_by(type="practice_apply").count() == 0                                                    # bloqueado pela change
    assert "CHG5" in admin.get(f"/plans/{plan.id}").get_data(as_text=True)
    assert login_as(app, "auditor@alpha.example").post(f"/plans/{plan.id}/request_change", {}).status_code == 403
    assert c.get(f"/api/v1/plans/{plan.id}/change", headers=h).get_json()["ref"] == "CHG5"


# ------------------------------------------------------------------ endurecimento do SO (SSH e Windows)


@pytest.fixture()
def sshd(tmp_path, monkeypatch):
    main, dropin = tmp_path / "sshd_config", tmp_path / "99-omxpatch.conf"
    main.write_text("Include " + str(tmp_path) + "/sshd_config.d/*.conf\n".replace(str(tmp_path), "/etc/ssh").replace("/etc/ssh/", "/etc/ssh/", 1) + "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n")
    monkeypatch.setattr(oshardening, "SSHD_MAIN", str(main))
    monkeypatch.setattr(oshardening, "DROPIN", str(dropin))
    monkeypatch.setattr(common, "backup_root", lambda: tmp_path / "bk")
    monkeypatch.setattr(oshardening.shutil, "which", lambda n: "/usr/sbin/" + n)
    monkeypatch.setattr(oshardening.os, "geteuid", lambda: 0)
    monkeypatch.setattr(oshardening, "platform_family", lambda: "linux")
    state = {"t_ok": True, "keys": True, "calls": []}
    monkeypatch.setattr(oshardening, "authorized_keys_present", lambda: state["keys"])

    def run(cmd, timeout=60, **k):
        state["calls"].append(cmd)
        if cmd[:2] == ["sshd", "-T"]:                                  # «configuração efetiva» = ficheiros por ordem (1.ª ocorrência vence)
            out = {}
            for f in (main, dropin):
                if f.exists():
                    for line in f.read_text().splitlines():
                        p = line.split(None, 1)
                        if len(p) == 2 and not p[0].startswith(("#", "Include")):
                            out.setdefault(p[0].lower(), p[1].lower())
            if dropin.exists():                                         # o drop-in é lido primeiro (Include no topo)
                for line in dropin.read_text().splitlines():
                    p = line.split(None, 1)
                    if len(p) == 2 and not p[0].startswith("#"):
                        out[p[0].lower()] = p[1].lower()
            return Result(0, "\n".join(f"{k} {v}" for k, v in out.items()))
        if cmd[:2] == ["sshd", "-t"]:
            return Result(0 if state["t_ok"] else 255, "" if state["t_ok"] else "bad config")
        return Result(0, "")
    monkeypatch.setattr(oshardening, "run", run)
    state.update(main=main, dropin=dropin)
    monkeypatch.setattr(oshardening, "_has_include", lambda: True)
    return state


def test_ssh_hardening_simulates_applies_verifies_and_rolls_back(sshd):
    sim = oshardening.simulate("ssh_hardening", {})
    assert sim["predicted"]["noop"] is False and sim["actions"][0]["kind"] == "criar ficheiro" and "PermitRootLogin no" in sim["actions"][0]["diff"]
    assert not sshd["dropin"].exists()                                                                                   # simular não altera
    r = oshardening.apply("ssh_hardening", {}, "item-1")
    assert r["status"] == "succeeded" and sshd["dropin"].read_text().count("PermitRootLogin no") == 1 and r["verification"]["ok"]
    assert ["sshd", "-t"] in sshd["calls"] and any(c[:2] == ["systemctl", "reload"] for c in sshd["calls"])
    assert oshardening.apply("ssh_hardening", {}, "item-2")["output"].startswith("Já em conformidade")                    # idempotente
    assert oshardening.rollback("ssh_hardening", "item-1")["status"] == "succeeded" and not sshd["dropin"].exists()


def test_ssh_hardening_refuses_lockout_and_reverts_on_failed_test(sshd):
    sshd["keys"] = False
    sim = oshardening.simulate("ssh_hardening", {"disable_password": True})
    assert any(c["id"] == "keys" and c["status"] == "block" for c in sim["checks"])
    r = oshardening.apply("ssh_hardening", {"disable_password": True}, "item-3")
    assert r["status"] == "failed" and "inacessível" in r["output"] and not sshd["dropin"].exists()                       # sem chaves: não desativa a palavra-passe
    sshd["keys"], sshd["t_ok"] = True, False
    r = oshardening.apply("ssh_hardening", {"disable_password": True}, "item-4")
    assert r["status"] == "failed" and r["rolled_back"] and "sshd -t falhou" in r["output"] and not sshd["dropin"].exists()  # teste falhou: revertido
    sshd["t_ok"] = True
    r = oshardening.apply("ssh_hardening", {"disable_password": True}, "item-5")
    assert r["status"] == "succeeded" and "PasswordAuthentication no" in sshd["dropin"].read_text()


class WinPS:
    def __init__(self, smb1=True, nla=False, rdp=True, fail=None):
        self.st, self.fail, self.scripts = {"smb1": smb1, "nla": nla, "rdp": rdp}, fail, []

    def __call__(self, script, timeout=60):
        if "Get-SmbServerConfiguration).EnableSMB1Protocol; nla" in script:
            return Result(0, json.dumps(self.st))
        self.scripts.append(script)
        if self.fail and self.fail in script:
            return Result(1, "acesso negado")
        if "EnableSMB1Protocol $false" in script:
            self.st["smb1"] = False
        elif "EnableSMB1Protocol $true" in script:
            self.st["smb1"] = True
        elif "UserAuthentication -Value 1" in script:
            self.st["nla"] = True
        elif "UserAuthentication -Value 0" in script:
            self.st["nla"] = False
        return Result(0, "")


def test_windows_hardening_smb1_and_nla(tmp_path, monkeypatch):
    monkeypatch.setattr(common, "backup_root", lambda: tmp_path)
    monkeypatch.setattr(oshardening, "platform_family", lambda: "windows")
    ps = WinPS()
    monkeypatch.setattr(oshardening, "powershell", ps)
    sim = oshardening.simulate("windows_hardening", {})
    assert [a["summary"] for a in sim["actions"]] == ["SMBv1: ativo → desativado", "RDP: autenticação ao nível da rede (NLA) desativada → ativada"] and any(c["status"] == "warn" for c in sim["checks"])
    assert ps.scripts == []
    r = oshardening.apply("windows_hardening", {}, "item-w1")
    assert r["status"] == "succeeded" and ps.st == {"smb1": False, "nla": True, "rdp": True}
    assert oshardening.apply("windows_hardening", {}, "item-w2")["output"].startswith("Já em conformidade")
    assert oshardening.rollback("windows_hardening", "item-w1")["status"] == "succeeded" and ps.st["smb1"] is True and ps.st["nla"] is False
    ps2 = WinPS(fail="UserAuthentication -Value 1")
    monkeypatch.setattr(oshardening, "powershell", ps2)
    r = oshardening.apply("windows_hardening", {}, "item-w3")
    assert r["status"] == "failed" and r["rolled_back"] and ps2.st["smb1"] is True                                       # falhou a 2.ª: a 1.ª foi revertida
    monkeypatch.setattr(oshardening, "platform_family", lambda: "linux")
    assert oshardening.simulate("windows_hardening", {})["checks"][0]["status"] == "block"


def test_os_practices_in_catalog_and_applicability(app, tenant):
    from omxpatch.engine import practices as pr
    assert {"ssh_hardening", "windows_hardening"} <= set(pr.PRACTICES)
    lin, win = make_asset(tenant, "l1", software=(), ip="10.0.0.1"), make_asset(tenant, "w1", software=(), os_family="windows", ip="10.0.0.2")
    assert pr.applicable(lin, "ssh_hardening")[0] and not pr.applicable(win, "ssh_hardening")[0]
    assert pr.applicable(win, "windows_hardening")[0] and not pr.applicable(lin, "windows_hardening")[0]
    assert pr.clean_params("ssh_hardening", {"disable_password": "true"}) == {"disable_password": True}
    plan = plans.create(tenant, "x", "by_asset", [lin.id, win.id], [], [{"id": "ssh_hardening", "params": {}}])
    st = {i.asset.name: i.sim_outcome for i in plan.items}
    assert st["w1"] == "blocked" and st["l1"] != "blocked"
    from tests.test_practices import agent_pr
    assert set(pr.PRACTICES) == set(agent_pr.PRACTICES)
