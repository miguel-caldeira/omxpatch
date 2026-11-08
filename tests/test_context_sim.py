"""Contexto do ativo (agente leve) → simulação de exposição e prioridade por impacto (servidor) → postura e movimento lateral."""
import json
import os
import time

import pytest

from omxpatch.engine import exposure_sim, inventory, priority
from omxpatch.extensions import db
from omxpatch.models import Asset, ControlAction, CveIntel, Exposure
from omxpatch_agent import context as actx
from tests.conftest import login_as, make_asset, make_cve
from tests.test_flow import FakeAgent, enroll_token  # noqa: F401


# ------------------------------------------------------------------ agente: recolha leve e analisadores

PROC_NET = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0 100 0 0 10 0
   1: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   120        0 2222 1 0 100 0 0 10 0
   2: 0501A8C0:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3333 1 0 100 0 0 10 0
   3: 0100007F:9C40 0100007F:0016 01 00000000:00000000 00:00000000 00000000  1000        0 4444 1 0 100 0 0 10 0
"""


def test_parse_proc_net_listeners_and_scope():
    ls = actx.parse_proc_net(PROC_NET)
    assert [(l["port"], l["address"], l["scope"], l["inode"]) for l in ls] == [(22, "0.0.0.0", "all", "1111"), (3306, "127.0.0.1", "loopback", "2222"), (443, "192.168.1.5", "lan", "3333")]
    assert actx.scope_of("::1") == "loopback" and actx.scope_of("::") == "all" and actx.scope_of("10.0.0.4") == "lan" and actx.scope_of("*") == "all"


def test_parse_firewalls_ssh_windows_macos():
    ufw = actx.parse_ufw("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\nTo  Action From\n22/tcp  ALLOW IN  Anywhere\n443  ALLOW IN  Anywhere\n")
    assert ufw == {"engine": "ufw", "enabled": True, "default_in": "deny", "default_out": "allow", "allow_in_ports": [22, 443]}
    assert actx.parse_ufw("Status: inactive")["enabled"] is False
    ipt = actx.parse_iptables_s("-P INPUT DROP\n-P OUTPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT\n")
    assert ipt["enabled"] and ipt["default_in"] == "drop" and ipt["allow_in_ports"] == [22, 8080] and ipt["rules"] == 2
    assert actx.parse_iptables_s("-P INPUT ACCEPT\n-P OUTPUT ACCEPT\n")["enabled"] is False
    assert actx.parse_firewalld("public (active)\n  services: ssh dhcpv6-client\n  ports: 8443/tcp 53/udp\n")["allow_in_ports"] == [8443]
    ssh = actx.parse_sshd("port 2222\npermitrootlogin yes\npasswordauthentication yes\npermitemptypasswords no\n")
    assert ssh == {"permit_root_login": "yes", "password_auth": "yes", "port": 2222, "pubkey_auth": "", "permit_empty": "no"}
    win = actx.parse_windows(json.dumps({"processes": ["svchost", "sqlservr"], "listeners": [{"port": 1433, "address": "0.0.0.0", "pid": 4, "process": "sqlservr"}, {"port": 5985, "address": "127.0.0.1", "pid": 5, "process": "System"}],
                                         "firewall": [{"name": "Domain", "enabled": True, "inbound": "Block", "outbound": "Allow"}], "admins": ["CORP\\Domain Admins"], "rdp_enabled": True,
                                         "rdp_nla": False, "uac": True, "smb1": True, "defender": {"realtime": False, "av": True}, "services": ["MSSQLSERVER"]}))
    assert win["firewall"]["enabled"] and win["firewall"]["default_in"] == "block" and win["access"]["smb1"] and not win["access"]["rdp_nla"] and not win["security"]["defender_realtime"]
    assert [(l["port"], l["scope"], l["process"]) for l in win["listeners"]] == [(1433, "all", "sqlservr"), (5985, "loopback", "System")]
    lsof = actx.parse_lsof_listen("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nsshd 101 root 3u IPv4 0x1 0t0 TCP *:22 (LISTEN)\ncupsd 202 root 4u IPv4 0x2 0t0 TCP 127.0.0.1:631 (LISTEN)\n")
    assert [(l["port"], l["scope"], l["process"]) for l in lsof] == [(22, "all", "sshd"), (631, "loopback", "cupsd")]


def test_context_collection_is_light_and_never_raises(monkeypatch):
    t = time.time()
    c = actx.collect_context(budget_s=10)
    assert time.time() - t < 8 and c["collect_ms"] < 8000 and c["platform"] == "linux" and isinstance(c["errors"], list)
    assert len(c["processes"]) <= actx.MAX_PROCESSES and len(c["listeners"]) <= actx.MAX_LISTENERS and all(p.get("name") for p in c["processes"])
    monkeypatch.setattr(actx, "_linux_firewall", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    c2 = actx.collect_context(budget_s=5)
    assert any("firewall" in e and "boom" in e for e in c2["errors"]) and c2["processes"]                            # uma sonda a falhar não impede as outras
    if hasattr(os, "nice"):
        before = os.nice(0)
        actx._lower_priority()
        assert os.nice(0) >= before                                                                                  # corre com prioridade mais baixa
    assert actx.collect_context(budget_s=0.0001)["processes"] is not None                                           # orçamento esgotado: devolve o que tiver


# ------------------------------------------------------------------ servidor: contexto recebido e saneado


def _ctx(**over):
    base = {"collected_at": int(time.time()), "collect_ms": 40, "platform": "linux",
            "processes": [{"pid": 10, "name": "nginx", "uid": "0", "exe": "/usr/sbin/nginx"}, {"pid": 11, "name": "sshd"}],
            "services": [{"name": "nginx", "state": "running"}],
            "listeners": [{"port": 443, "address": "0.0.0.0", "scope": "all", "proto": "tcp", "process": "nginx", "pid": 10}, {"port": 3306, "address": "127.0.0.1", "scope": "loopback", "process": "mysqld"},
                          {"port": 22, "address": "0.0.0.0", "scope": "all", "process": "sshd"}],
            "firewall": {"engine": "ufw", "enabled": True, "default_in": "deny", "default_out": "allow", "allow_in_ports": [22, 443]},
            "access": {"admins": ["alice"], "ssh": {"permit_root_login": "yes", "password_auth": "yes", "port": 22}}, "security": {}, "errors": []}
    base.update(over)
    return base


def test_inventory_stores_context_and_sanitizes_hostile_input(app, tenant, enroll_token):
    ag = FakeAgent(app, enroll_token, "web1")
    evil = _ctx(processes=[{"pid": i, "name": "p" * 5000} for i in range(1000)] + ["lixo", None], listeners=[{"port": "abc"}, {"port": 80, "scope": "all"}] * 300,
                firewall={"engine": "x" * 500, "enabled": 1, "allow_in_ports": list(range(1000)) + ["a"]}, access={"admins": ["a" * 500] * 500, "evil": 1})
    r = ag.c.post("/agent/v1/inventory", headers=ag.h, json={"software": [], "hardware": {}, "context": evil})
    assert r.status_code == 200
    ctx = Asset.query.filter_by(name="web1").one().hw["context"]
    assert len(ctx["processes"]) == 300 and len(ctx["processes"][0]["name"]) == 200 and len(ctx["listeners"]) <= 200 and all(isinstance(l["port"], int) for l in ctx["listeners"])
    assert len(ctx["firewall"]["engine"]) == 24 and len(ctx["firewall"]["allow_in_ports"]) == 200 and len(ctx["access"]["admins"]) == 100 and "evil" not in ctx["access"]
    ag.c.post("/agent/v1/inventory", headers=ag.h, json={"software": [], "context": _ctx()})
    assert Asset.query.filter_by(name="web1").one().hw["context"]["listeners"][0]["port"] == 443


# ------------------------------------------------------------------ simulação de exposição (matriz de vereditos)


def _setup(tenant, ctx, software="nginx", port=443, vector="AV:N/AC:L/PR:N", kev=True, epss=0.4, maturity="none", **assetkw):
    cve = make_cve("CVE-2026-7001", kev=kev, epss=epss, maturity=maturity)
    cve.cvss_vector = f"CVSS:3.1/{vector}/UI:N/S:U/C:H/I:H/A:H"
    a = make_asset(tenant, "w1", software=((software, "1.0"),), ip="10.0.0.5", **assetkw)
    a.hardware = json.dumps({"context": ctx} if ctx is not None else {})
    ex = Exposure(tenant_id=tenant.id, asset_id=a.id, cve_id=cve.cve_id, software_name=software, installed_version="1.0", fixed_version="2.0", port=port, status="open")
    db.session.add(ex)
    db.session.commit()
    return a, ex, cve


def _sim(ex, cve=None, controls=()):
    cve = cve or CveIntel.query.filter_by(cve_id=ex.cve_id).first()
    return exposure_sim.simulate(ex, cve, ex.asset, list(controls), {})


def test_verdict_confirmed_when_running_listening_open_and_exploited(app, tenant):
    a, ex, cve = _setup(tenant, _ctx())
    r = _sim(ex)
    ids = {s["id"]: s["status"] for s in r["steps"]}
    assert r["verdict"] == "confirmed" and ids["running"] == "ok" and ids["listening"] == "ok" and ids["firewall"] == "ok" and ids["exploit"] == "ok" and r["confidence"] >= 0.7
    assert r["weight"] == 1.0 and "confirmada" in r["label"].lower()


def test_verdict_unreachable_when_loopback_only_stopped_or_firewalled(app, tenant):
    a, ex, cve = _setup(tenant, _ctx(), software="mysqld", port=3306)
    r = _sim(ex)
    assert r["verdict"] == "unreachable" and [s for s in r["steps"] if s["id"] == "listening"][0]["status"] == "fail" and "loopback" in r["summary"]
    a.hardware = json.dumps({"context": _ctx(processes=[{"pid": 1, "name": "sshd"}], services=[], listeners=[])})
    ex.software_name, ex.port = "redis-server", None
    db.session.commit()
    r = _sim(ex)
    assert r["verdict"] == "unreachable" and [s for s in r["steps"] if s["id"] == "running"][0]["status"] == "fail"
    a.hardware = json.dumps({"context": _ctx(firewall={"engine": "ufw", "enabled": True, "default_in": "deny", "default_out": "allow", "allow_in_ports": [22]})})
    ex.software_name, ex.port = "nginx", 443
    db.session.commit()
    r = _sim(ex)
    assert r["verdict"] == "unreachable" and "firewall" in r["summary"].lower()                                      # a firewall bloqueia a 443


def test_verdict_unknown_without_context_unlikely_with_controls_and_local_vector(app, tenant):
    a, ex, cve = _setup(tenant, None)
    r = _sim(ex)
    assert r["verdict"] == "unknown" and r["weight"] == 0.5 and r["confidence"] < 0.8
    a.hardware = json.dumps({"context": _ctx()})
    db.session.commit()
    c = ControlAction(tenant_id=tenant.id, cve_id=ex.cve_id, asset_id=a.id, category="firewall", action="block_port", params="{}", status="applied")
    db.session.add(c)
    db.session.commit()
    r = _sim(ex, controls=[c])
    assert r["verdict"] == "unlikely" and [s for s in r["steps"] if s["id"] == "controls"][0]["status"] == "fail"
    cve.cvss_vector = "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
    db.session.commit()
    assert _sim(ex)["verdict"] == "unlikely"                                                                         # local + privilégios altos
    cve.cvss_vector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    db.session.commit()
    assert _sim(ex)["verdict"] == "likely"                                                                           # local com administradores no ativo


def test_library_components_are_unknown_running_not_false_negatives(app, tenant):
    a, ex, cve = _setup(tenant, _ctx(), software="OpenSSL", port=None)
    r = _sim(ex)
    run = [s for s in r["steps"] if s["id"] == "running"][0]
    assert run["status"] == "unknown" and r["verdict"] != "unreachable"                                              # uma biblioteca nunca é «não está a correr»


def test_refresh_persists_simulation_and_updates_when_context_arrives(app, tenant, enroll_token):
    from omxpatch.engine import correlate
    ag = FakeAgent(app, enroll_token, "w1", software=(("nginx", "1.0"),))
    ag.inventory()
    a = Asset.query.filter_by(name="w1").one()
    make_cve("CVE-2026-7002", kev=True, epss=0.4, product="nginx", vendor="f5", end_excl="2.0", advisories=[{"vendor": "F5", "product": "nginx", "fixed_version": "2.0", "os_family": "linux", "package": "nginx", "installer": "apt"}])
    db.session.commit()
    correlate.correlate_asset(tenant, a)
    db.session.commit()
    ex = Exposure.query.one()
    assert ex.exploitability == "unknown" and ex.sim_at is not None
    ag.c.post("/agent/v1/inventory", headers=ag.h, json={"software": [{"name": "nginx", "version": "1.0"}], "context": _ctx(listeners=[], processes=[{"pid": 1, "name": "sshd"}], services=[])})
    db.session.expire_all()
    ex = Exposure.query.one()
    assert ex.exploitability == "unreachable" and ex.sim_data["steps"] and ex.expected_loss == pytest.approx(360.0)   # nginx não corre: 0,5 × 0,03 × 24 000
    ag.c.post("/agent/v1/inventory", headers=ag.h, json={"software": [{"name": "nginx", "version": "1.0"}], "context": _ctx()})
    db.session.expire_all()
    ex = Exposure.query.one()
    assert ex.exploitability in ("confirmed", "likely") and ex.expected_loss > 5000                                  # ~ 0,5 × (0,6–1) × 24 000


# ------------------------------------------------------------------ prioridade por impacto


def test_expected_loss_combines_probability_simulation_and_asset_impact(app, tenant):
    a, ex, cve = _setup(tenant, _ctx(), criticality="critical", business_value=100)
    ex.exploitability = "confirmed"
    res = priority.score(ex, cve, a, [])
    imp = res["impact"]
    assert imp["cost_per_hour"] == 20000 and imp["hours"] == 24 and imp["business_factor"] == 1.5 and imp["amount"] == 720000.0
    assert res["base_probability"] == pytest.approx(0.5) and res["probability"] == pytest.approx(0.5) and res["expected_loss"] == pytest.approx(360000.0)
    ex.exploitability = "unreachable"
    assert priority.score(ex, cve, a, [])["expected_loss"] == pytest.approx(0.5 * 0.03 * 720000, rel=1e-3)
    ex.exploitability = "confirmed"
    c = ControlAction(tenant_id=tenant.id, cve_id=ex.cve_id, asset_id=a.id, category="firewall", action="block_port", params="{}", status="verified")
    assert priority.score(ex, cve, a, [c])["control_factor"] == 0.4
    a.cost_per_hour = 500                                                                                             # valor próprio do ativo
    assert priority.asset_impact(a)["amount"] == 500 * 24 * 1.5 and priority.asset_impact(a)["own_value"]
    app.config.update(IMPACT_OUTAGE_HOURS=8, IMPACT_COST_LOW=7)
    a.cost_per_hour, a.criticality, a.business_value = None, "low", 0
    assert priority.asset_impact(a)["amount"] == 7 * 8 * 0.5
    assert "EPSS" in priority.base_probability(cve)[1] and priority.base_probability(None)[0] == 0.05


def test_priority_ranks_by_loss_not_by_cvss(app, tenant, enroll_token):
    from omxpatch.engine import correlate
    # CVE «A» tem CVSS maior mas está num ativo irrelevante; CVE «B» tem CVSS menor mas num ativo crítico e alcançável
    cA = make_cve("CVE-2026-8001", cvss=9.9, kev=False, epss=0.9)
    cB = make_cve("CVE-2026-8002", cvss=6.0, kev=True, epss=0.5)
    low = make_asset(tenant, "lab", software=(), criticality="low", business_value=10)
    crit = make_asset(tenant, "erp", software=(), criticality="critical", business_value=100)
    for a in (low, crit):
        a.hardware = json.dumps({"context": _ctx(processes=[{"pid": 1, "name": "app"}], listeners=[{"port": 443, "address": "0.0.0.0", "scope": "all", "process": "app"}])})
    db.session.add_all([Exposure(tenant_id=tenant.id, asset_id=low.id, cve_id=cA.cve_id, software_name="app", installed_version="1", fixed_version="2", port=443, status="open"),
                        Exposure(tenant_id=tenant.id, asset_id=crit.id, cve_id=cB.cve_id, software_name="app", installed_version="1", fixed_version="2", port=443, status="open")])
    db.session.commit()
    for e in Exposure.query:
        correlate.refresh(e, tenant)
    db.session.commit()
    ea, eb = Exposure.query.filter_by(cve_id="CVE-2026-8001").one(), Exposure.query.filter_by(cve_id="CVE-2026-8002").one()
    assert ea.expected_loss < eb.expected_loss                                                                       # o ativo crítico domina apesar do CVSS menor
    admin = login_as(app, "admin@alpha.example")
    html = admin.get("/exposures?sort=loss").get_data(as_text=True)
    assert html.index("CVE-2026-8002") < html.index("CVE-2026-8001") and "Perda esperada" in html
    from omxpatch.models import User
    h = {"Authorization": "Bearer " + __import__("tests.test_web", fromlist=["x"])._api_token(admin)}
    rows = app.test_client().get("/api/v1/priority", headers=h).get_json()
    assert [r["cve"] for r in rows][:2] == ["CVE-2026-8002", "CVE-2026-8001"] and rows[0]["expected_loss"] > rows[1]["expected_loss"]
    ex = app.test_client().get("/api/v1/exposures", headers=h).get_json()[0]
    assert "exploitability" in ex and "expected_loss" in ex and "simulation" in ex
    page = admin.get(f"/exposures/{eb.id}").get_data(as_text=True)
    assert "Simulação de exposição" in page and "Perda esperada" in page and "Componente em execução" in page


def test_command_center_shows_simulation_and_impact(app, tenant):
    a, ex, cve = _setup(tenant, _ctx(), criticality="high")
    from omxpatch.engine import correlate
    correlate.refresh(ex, tenant)
    db.session.commit()
    html = login_as(app, "admin@alpha.example").get("/").get_data(as_text=True)
    assert "Simulação de exposição e impacto" in html and "Perda esperada total" in html and "perda esperada = probabilidade" in html


# ------------------------------------------------------------------ postura: configurações incorretas e movimento lateral


def test_misconfigurations_and_lateral_paths(app, tenant):
    bad = _ctx(firewall={"engine": "ufw", "enabled": False, "default_in": "accept", "default_out": "accept", "allow_in_ports": []},
               access={"admins": ["a"], "ssh": {"permit_root_login": "yes", "password_auth": "yes", "port": 22, "permit_empty": "yes"}, "smb1": True, "rdp_enabled": True, "rdp_nla": False, "uac": False},
               security={"selinux": "disabled", "defender_av": False},
               listeners=[{"port": 22, "scope": "all", "process": "sshd"}, {"port": 445, "scope": "lan", "process": "smbd"}, {"port": 6379, "scope": "all", "process": "redis"}, {"port": 3389, "scope": "loopback"}])
    a = make_asset(tenant, "srv", software=())
    a.hardware = json.dumps({"context": bad})
    db.session.commit()
    ids = {m["id"]: m for m in exposure_sim.misconfigurations(a)}
    assert {"firewall_off", "ssh_root", "ssh_password", "ssh_empty", "smb1", "rdp_nla", "uac_off", "av_off", "selinux_off", "db_open_6379"} <= set(ids)
    assert ids["ssh_root"]["fix"] == {"type": "practice", "practice": "ssh_hardening"} and ids["smb1"]["fix"]["practice"] == "windows_hardening" and ids["db_open_6379"]["fix"]["type"] == "control"
    assert [(l["service"], l["port"]) for l in exposure_sim.lateral_paths(a)] == [("SSH", 22), ("SMB", 445)]            # RDP em loopback não conta
    clean = make_asset(tenant, "ok", software=(), ip="10.0.0.9")
    clean.hardware = json.dumps({"context": _ctx(access={"admins": [], "ssh": {"permit_root_login": "no", "password_auth": "no"}})})
    assert exposure_sim.misconfigurations(clean) == [] and exposure_sim.misconfigurations(make_asset(tenant, "nada", software=(), ip="10.0.0.10")) == []
    admin = login_as(app, "admin@alpha.example")
    html = admin.get(f"/assets/{a.id}").get_data(as_text=True)
    assert "Postura do ativo" in html and "SSH permite início de sessão como root" in html and "Vetores de movimento lateral" in html
    from tests.test_web import _api_token
    api = app.test_client().get(f"/api/v1/assets/{a.id}/posture", headers={"Authorization": "Bearer " + _api_token(admin)}).get_json()
    assert api["context_collected"] and len(api["misconfigurations"]) >= 9 and len(api["lateral_paths"]) == 2
