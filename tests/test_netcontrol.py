"""V1 — controlos compensatórios nas firewalls de perímetro: FortiGate, Palo Alto e Check Point simulados (HTTPS, com estado)."""
from __future__ import annotations

import pytest

from omxpatch.connectors import store
from omxpatch.engine import controls, netcontrol
from omxpatch.extensions import db
from omxpatch.models import AnsibleCredential, Asset, ControlAction, utcnow
from tests.fake_fw import Fake


def fw_asset(tenant, name, platform, fake, **opts):
    c = AnsibleCredential(tenant_id=tenant.id, name=f"tok-{name}", kind="api_token",
                          secret=store.encrypt_json({"api_token": fake.token, "opts": {"validate_certs": False, **opts}}))
    db.session.add(c)
    db.session.flush()
    a = Asset(tenant_id=tenant.id, uid=name, name=name, connection="ansible", managed=True, platform=platform, ip="127.0.0.1", ansible_port=fake.port,
              credential_id=c.id, fw_enforce=True, kind="network")
    db.session.add(a)
    db.session.flush()
    return a


def ctl(tenant, action="fw_block_ip", cidr="203.0.113.9", asset=None, **params):
    c = controls.make(tenant, None, action, {"cidr": cidr, **params} if action == "fw_block_ip" else params, cve_id="CVE-2026-9999", asset=asset)
    db.session.flush()
    controls.approve(c)
    return c


@pytest.fixture()
def netcfg(app):
    app.config["NETCONTROL_ENABLED"] = True


def test_target_validation_protects_critical_addresses(app, tenant, tmp_path, netcfg):
    with app.app_context():
        f = Fake("forti", tmp_path)
        fw_asset(tenant, "fgt", "fortios", f)
        app.config["AGENT_SERVER_IP"] = "10.0.0.5"
        app.config["NETCONTROL_PROTECTED"] = "192.168.50.0/24"
        v = lambda t, **k: netcontrol.validate_target(tenant, t, **k)  # noqa: E731
        assert str(v("203.0.113.9")) == "203.0.113.9/32" and str(v("198.51.100.0/24")) == "198.51.100.0/24"
        for bad, why in (("127.0.0.1", "loopback"), ("224.0.0.1", "multicast"), ("0.0.0.0/0", "larga"), ("10.0.0.0/8", "larga"), ("203.0.113.0/20", "larga"),
                         ("10.0.0.5", "protegido"), ("192.168.50.7", "protegido"), ("nada", "inválido")):
            with pytest.raises(ValueError, match=why):
                v(bad)
        with pytest.raises(ValueError, match="único"):
            v("203.0.113.0/24", isolate=True)
        f.stop()


def test_fortigate_full_flow_simulate_apply_verify_revert(app, tenant, tmp_path, netcfg):
    with app.app_context():
        f = Fake("forti", tmp_path, groups=())
        fw = fw_asset(tenant, "fgt", "fortios", f)
        c = ctl(tenant)
        app.config["NETCONTROL_ENABLED"] = False
        with pytest.raises(ValueError, match="desativados"):
            netcontrol.simulate(c, tenant)
        app.config["NETCONTROL_ENABLED"] = True
        res = netcontrol.simulate(c, tenant)
        assert not res["ok"] and "não existe" in res["firewalls"][0]["detail"]                       # sem o grupo pré-criado: não avança
        with pytest.raises(ValueError, match="simulação"):
            controls.apply(c, tenant)
        f.groups["OMX-BLOCK"] = ["existente"]
        res = netcontrol.simulate(c, tenant)
        assert res["ok"] and "acrescentar 203.0.113.9/32" in res["firewalls"][0]["actions"][0]
        controls.apply(c, tenant)
        assert c.status == "verified" and c.via == "firewall" and "expires_at" in c.params_data and c.params_data["applied_on"] == [fw.id]
        assert f.groups["OMX-BLOCK"] == ["existente", "OMX-203.0.113.9_32"] and f.addr["OMX-203.0.113.9_32"]["subnet"] == "203.0.113.9 255.255.255.255"
        netcontrol.revert(c, tenant)
        assert c.status == "reverted" and f.groups["OMX-BLOCK"] == ["existente"] and "OMX-203.0.113.9_32" not in f.addr          # só retira o que pôs
        f.stop()


def test_ttl_expiry_reverts_automatically(app, tenant, tmp_path, netcfg):
    with app.app_context():
        f = Fake("forti", tmp_path)
        fw_asset(tenant, "fgt", "fortios", f)
        c = ctl(tenant, ttl_minutes=30)
        netcontrol.simulate(c, tenant)
        controls.apply(c, tenant)
        assert c.params_data["ttl_minutes"] == 30
        assert netcontrol.expire(tenant) == 0 and c.status == "verified"
        p = c.params_data
        p["expires_at"] = (utcnow().replace(year=utcnow().year - 1)).isoformat()
        import json
        c.params = json.dumps(p)
        assert netcontrol.expire(tenant) == 1 and c.status == "reverted" and f.groups["OMX-BLOCK"] == []
        f.stop()


def test_paloalto_uses_tags_with_native_timeout_and_rejects_networks(app, tenant, tmp_path, netcfg):
    with app.app_context():
        f = Fake("pan", tmp_path)
        fw_asset(tenant, "pa", "panos", f)
        c = ctl(tenant, ttl_minutes=60)
        res = netcontrol.simulate(c, tenant)
        assert res["ok"] and "omx-block" in res["firewalls"][0]["detail"]
        controls.apply(c, tenant)
        assert c.status == "verified" and f.tags["203.0.113.9"] == {"omx-block"} and f.last_timeout == "3600"        # validade nativa na própria firewall
        netcontrol.revert(c, tenant)
        assert c.status == "reverted" and not f.tags["203.0.113.9"]
        net = ctl(tenant, cidr="198.51.100.0/24")
        netcontrol.simulate(net, tenant)
        controls.apply(net, tenant)
        assert net.status == "failed" and "endereços individuais" in net.detail
        f.groups.clear()
        assert "não existe" in netcontrol.simulate(ctl(tenant, cidr="203.0.113.77"), tenant)["firewalls"][0]["detail"]
        f.stop()


def test_checkpoint_publishes_and_installs_the_policy(app, tenant, tmp_path, netcfg):
    with app.app_context():
        f = Fake("cp", tmp_path)
        fw_asset(tenant, "cp", "checkpoint", f, cp_package="Standard", cp_targets="gw1, gw2")
        c = ctl(tenant, cidr="198.51.100.0/24")
        res = netcontrol.simulate(c, tenant)
        assert res["ok"] and any("instalar a política «Standard»" in a for a in res["firewalls"][0]["actions"])
        controls.apply(c, tenant)
        assert c.status == "verified" and f.groups["OMX-BLOCK"] == ["OMX-198.51.100.0_24"] and f.installed == ("Standard", ["gw1", "gw2"])
        cmds = [p.rsplit("/", 1)[-1] for _, p, _ in f.calls]
        assert cmds.index("add-network") < cmds.index("set-group") < cmds.index("publish") < cmds.index("install-policy") and cmds[-1] == "logout"
        assert f.addr["OMX-198.51.100.0_24"]["mask-length"] == 24
        netcontrol.revert(c, tenant)
        assert c.status == "reverted" and f.groups["OMX-BLOCK"] == []
        # sem pacote/gateways na credencial: a simulação diz o que falta
        f2 = Fake("cp", tmp_path / "x") if (tmp_path / "x").mkdir() is None else None
        fw_asset(tenant, "cp2", "checkpoint", f2)
        for a in Asset.query.filter(Asset.name == "cp"):
            a.fw_enforce = False
        assert "cp_package" in netcontrol.simulate(ctl(tenant, cidr="203.0.113.50"), tenant)["firewalls"][0]["detail"]
        f.stop()
        f2.stop()


def test_all_or_nothing_across_firewalls(app, tenant, tmp_path, netcfg):
    with app.app_context():
        good, bad = Fake("forti", tmp_path), Fake("forti", tmp_path / "b") if (tmp_path / "b").mkdir() is None else None
        fw_asset(tenant, "fgt-ok", "fortios", good)
        fw_asset(tenant, "fgt-bad", "fortios", bad)
        c = ctl(tenant)
        assert netcontrol.simulate(c, tenant)["ok"]
        bad.fail = {"PUT OMX-BLOCK": True}                                                           # a 2.ª firewall falha ao escrever no grupo
        controls.apply(c, tenant)
        assert c.status == "failed" and "fgt-bad" in c.detail and good.groups["OMX-BLOCK"] == []      # a 1.ª foi desfeita
        good.stop()
        bad.stop()


def test_isolate_uses_the_asset_address_and_ui_flow(app, tenant, alpha_admin, tmp_path, netcfg):
    with app.app_context():
        f = Fake("forti", tmp_path)
        fw_asset(tenant, "fgt", "fortios", f)
        srv = Asset(tenant_id=tenant.id, uid="srv-vuln", name="srv-vuln", ip="10.20.30.40", os_family="linux")
        db.session.add(srv)
        db.session.flush()
        c = controls.make(tenant, None, "fw_isolate", {}, cve_id="CVE-2026-1", asset=srv)
        db.session.commit()
        cid = c.id
    page = alpha_admin.get(f"/controls/{cid}").data.decode()
    assert "Simulação nas firewalls" in page and "Isolar o ativo na firewall de perímetro" in page
    alpha_admin.post(f"/controls/{cid}/approve")
    alpha_admin.post(f"/controls/{cid}/apply")                                                         # sem simulação: recusado
    assert f.groups["OMX-ISOLATE"] == []
    alpha_admin.post(f"/controls/{cid}/simulate")
    alpha_admin.post(f"/controls/{cid}/apply")
    assert f.groups["OMX-ISOLATE"] == ["OMX-10.20.30.40_32"]
    alpha_admin.post(f"/controls/{cid}/revert")
    assert f.groups["OMX-ISOLATE"] == []
    with app.app_context():
        assert db.session.get(ControlAction, cid).status == "reverted"
    f.stop()
