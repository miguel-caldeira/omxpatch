"""Conectores: sinais multi-vendor, OMXVuln, OMXGRC, descoberta, SIEM/SOAR/ITSM."""
import json

import pytest

from omxpatch.connectors import discovery, omxgrc, omxvuln, outbound, signals, store, sync
from omxpatch.connectors.store import ConnectorError
from omxpatch.extensions import db
from omxpatch.models import Asset, Connector, ControlAction, CveIntel, Exposure, Signal, Validation
from tests.conftest import make_asset, make_cve


class Resp:
    def __init__(self, data=None, status=200):
        self._d, self.status_code = data, status

    def json(self):
        return self._d

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(str(self.status_code))


@pytest.fixture()
def http(monkeypatch):
    calls = []
    routes = {}

    def fake(method, url, **kw):
        calls.append({"method": method, "url": url, "json": kw.get("json"), "headers": kw.get("headers"), "auth": kw.get("auth"),
                      "params": kw.get("params")})
        for (m, suffix), resp in routes.items():
            if m == method and url.endswith(suffix):
                return resp() if callable(resp) else resp
        return Resp([] if method == "GET" else {}, 200)

    monkeypatch.setattr("omxpatch.connectors.http.requests.request", fake)
    monkeypatch.setattr("omxpatch.connectors.http.check_outbound_url", lambda u, **k: u)
    fake.calls, fake.routes = calls, routes
    return fake


# ------------------------------------------------------------------ sinais


def test_signal_normalizers_per_vendor():
    d = signals.normalize("defender", {"value": [{"cveId": "CVE-2026-1", "computerDnsName": "pc1.corp", "productName": "chrome"}]})
    assert d == [{"source": "defender", "kind": "vuln", "cve": "CVE-2026-1", "asset": "pc1.corp", "value": "chrome"}]
    cs = signals.normalize("crowdstrike", {"resources": [{"cve": {"id": "CVE-2026-2", "exploit_status": 90}, "host_info": {"hostname": "h"}}]})
    assert {s["kind"] for s in cs} == {"vuln", "active_exploit"}
    assert signals.normalize("crowdstrike", {"resources": [{"cve": {"id": "CVE-2026-2", "exploit_status": 30}, "host_info": {"hostname": "h"}}]})[0]["kind"] == "vuln"
    tn = signals.normalize("tenable", {"vulnerabilities": [{"plugin": {"cve": ["CVE-2026-0003", "CVE-2026-0004"]}, "asset": {"hostname": "x"}}]})
    assert [s["cve"] for s in tn] == ["CVE-2026-0003", "CVE-2026-0004"]
    fw = signals.normalize("paloalto", [{"cve": "CVE-2026-0005", "dest": "10.0.0.5", "action": "deny", "dest_port": 8443}])
    assert fw[0]["kind"] == "fw_blocked" and fw[0]["value"] == "8443"
    assert signals.normalize("fortinet", [{"cve": "CVE-2026-0005", "dst": "10.0.0.5", "action": "accept"}])[0]["kind"] == "fw_allowed"
    assert signals.normalize("sentinelone", [{"cveId": "CVE-2026-0006", "hostname": "h", "disposition": "missed"}])[0]["kind"] == "edr_missed"
    assert signals.normalize("wiz", [{"kind": "vuln", "vulnerability": "see CVE-2026-0007 and CVE-2026-0008", "asset": "vm1"}])[0]["cve"] == "CVE-2026-0007"
    assert signals.normalize("generic", [{"kind": "vuln"}]) == []                      # vuln sem CVE é descartada
    rows = signals.parse_body("cve,asset,kind\nCVE-2026-0009,h1,ioc\n", "text/csv")
    assert rows[0]["asset"] == "h1"


def test_signals_store_deduplicates_and_resolves_assets(app, tenant):
    make_asset(tenant, "Web01", ip="10.0.0.5")
    db.session.commit()
    r1 = signals.ingest(tenant, "paloalto", json.dumps([{"cve": "CVE-2026-5", "dest": "10.0.0.5", "action": "deny"},
                                                         {"cve": "CVE-2026-5", "dest": "ghost", "action": "deny"}]))
    assert r1["new"] == 2 and r1["unknown_assets"] == 1
    assert signals.ingest(tenant, "paloalto", json.dumps([{"cve": "CVE-2026-5", "dest": "10.0.0.5", "action": "deny"}]))["new"] == 0
    assert Signal.query.filter(Signal.asset_id.isnot(None)).count() == 1
    assert signals.ingest(tenant, "x", "cve,asset,action\nCVE-2026-6,web01,allow\n", "text/csv")["new"] == 1


def test_signal_pull_requires_path_and_uses_configured_auth(app, tenant, http):
    store.save(tenant.id, "defender", "https://api.securitycenter.microsoft.com", "", {"token": "T0K"}, {}, True)
    db.session.commit()
    c = Connector.query.filter_by(kind="defender").one()
    with pytest.raises(ConnectorError, match="caminho"):
        signals.pull(c, tenant)
    store.save(tenant.id, "defender", c.base_url, "", {}, {"vuln_path": "/api/vulnerabilities/machinesVulnerabilities"}, True)
    http.routes[("GET", "/machinesVulnerabilities")] = Resp({"value": [{"cveId": "CVE-2026-1", "computerDnsName": "pc1"}]})
    res = signals.pull(Connector.query.filter_by(kind="defender").one(), tenant)
    assert res["new"] == 1
    assert http.calls[-1]["headers"]["Authorization"] == "Bearer T0K"


# ------------------------------------------------------------------ OMXVuln


FINDINGS = [
    {"id": 11, "title": "OpenSSL < 1.1.1w", "severity": "high", "cvss_score": 7.5, "cves": ["CVE-2026-0001"], "host": "10.0.0.5", "port": 443,
     "status": "open", "kev": True, "component": "OpenSSL", "installed_version": "1.1.1k", "fixed_version": "1.1.1w",
     "risk": {"epss": 0.6, "ransomware": True}},
    {"id": 12, "title": "sem CVE", "cves": [], "host": "10.0.0.6", "status": "open"},
    {"id": 13, "title": "fechada", "cves": ["CVE-2026-0002"], "host": "10.0.0.7", "status": "closed"},
    {"id": 14, "title": "Apache", "severity": "critical", "cves": ["CVE-2026-0003"], "host": "web.corp", "port": "8443", "status": "assigned",
     "component": "Apache httpd", "installed_version": "2.4.50", "fixed_version": "2.4.58"},
]


def test_omxvuln_ingest_creates_assets_exposures_and_intel(app, tenant):
    res = omxvuln.ingest_findings(tenant, FINDINGS)
    db.session.commit()
    assert (res["new_assets"], res["new_exposures"], res["skipped"]) == (2, 2, 2)
    ex = Exposure.query.filter_by(cve_id="CVE-2026-0001").one()
    assert ex.omxvuln_finding_id == 11 and ex.port == 443 and ex.fixed_version == "1.1.1w" and ex.source == "omxvuln"
    intel_row = CveIntel.query.filter_by(cve_id="CVE-2026-0001").one()
    assert intel_row.kev and intel_row.ransomware and intel_row.epss == pytest.approx(0.6)
    assert ex.risk_score > 0 and Asset.query.filter_by(uid="10.0.0.5").one().open_ports == "443"
    assert Exposure.query.filter_by(cve_id="CVE-2026-0003").one().asset.fqdn == "web.corp"
    assert omxvuln.ingest_findings(tenant, FINDINGS)["new_exposures"] == 0           # idempotente


def test_omxvuln_pull_headers_pagination_and_upstream_closure(app, tenant, http):
    store.save(tenant.id, "omxvuln", "https://omxvuln.example", "", {"token": "TK"}, {"tenant_id": "5"}, True)
    db.session.commit()
    http.routes[("GET", "/api/v1/findings")] = Resp(FINDINGS)
    res = omxvuln.pull_findings(tenant)
    h = http.calls[0]["headers"]
    assert h["Authorization"] == "Bearer TK" and h["X-Tenant-ID"] == "5"
    assert res["new_exposures"] == 2 and res["closed_upstream"] == 0
    # o OMXVuln deixa de listar a primeira → remediada, com validação pedida
    http.routes[("GET", "/api/v1/findings")] = Resp([FINDINGS[3]])
    res = omxvuln.pull_findings(tenant)
    assert res["closed_upstream"] == 1
    ex = Exposure.query.filter_by(cve_id="CVE-2026-0001").one()
    assert ex.status == "remediated" and Validation.query.filter_by(exposure_id=ex.id).count() == 1


def test_omxvuln_global_config_fallback_and_missing(app, tenant, http):
    with pytest.raises(ConnectorError):
        omxvuln.pull_findings(tenant)
    app.config.update(OMXVULN_URL="https://global.example", OMXVULN_TOKEN="G", OMXVULN_TENANT_ID=9)
    http.routes[("GET", "/api/v1/findings")] = Resp([])
    omxvuln.pull_findings(tenant)
    assert http.calls[0]["url"].startswith("https://global.example") and http.calls[0]["headers"]["X-Tenant-ID"] == "9"


def test_omxvuln_push_status_and_rescan(app, tenant, http):
    store.save(tenant.id, "omxvuln", "https://omxvuln.example", "", {"token": "TK"}, {}, True)
    a = make_asset(tenant, ip="10.0.0.5")
    ex = Exposure(tenant_id=tenant.id, asset_id=a.id, cve_id="CVE-2026-0001", omxvuln_finding_id=11, status="closed")
    db.session.add(ex)
    db.session.commit()
    http.routes[("GET", "/api/v1/targets")] = Resp([{"id": 4, "value": ["10.0.0.5"]}, {"id": 5, "value": ["10.9.9.9"]}])
    assert omxvuln.push_status(tenant, ex) is True
    posts = [c for c in http.calls if c["method"] == "POST"]
    assert posts[0]["url"].endswith("/findings/11/status") and posts[1]["url"].endswith("/api/v1/scans") and posts[1]["json"]["target_id"] == 4
    # sem finding associado ou com push desativado: não envia
    ex2 = Exposure(tenant_id=tenant.id, asset_id=a.id, cve_id="CVE-2026-0002", status="closed")
    db.session.add(ex2)
    assert omxvuln.push_status(tenant, ex2) is False


# ------------------------------------------------------------------ OMXGRC


def test_omxgrc_payload_and_push(app, tenant, http):
    a = make_asset(tenant)
    make_cve()
    db.session.commit()
    p = omxgrc.metrics_payload(tenant)
    assert p["source"] == "omxpatch" and set(p["frameworks"]) == {"nis2", "iso27001", "dora", "pci", "cis"}
    assert all(r["status"] in ("compliant", "partial", "gap") for fw in p["frameworks"].values() for r in fw["requirements"])
    assert omxgrc.push_metrics(tenant) is False                       # sem configuração
    store.save(tenant.id, "omxgrc", "https://omxgrc.example", "", {"token": "G"}, {"metrics_path": "/x/metrics"}, True)
    db.session.commit()
    assert omxgrc.push_metrics(tenant) is True
    assert http.calls[-1]["url"] == "https://omxgrc.example/x/metrics" and http.calls[-1]["json"]["tenant"] == "alpha"


# ------------------------------------------------------------------ descoberta


def test_discovery_parsers():
    ad = discovery.parse_ad([{"name": "SRV1", "dNSHostName": "srv1.corp.local", "operatingSystem": "Windows Server 2022", "operatingSystemVersion": "10.0",
                              "managedBy": "CN=Ana"}])[0]
    assert ad["os_family"] == "windows" and ad["kind"] == "server" and ad["uid"] == "srv1.corp.local" and ad["managed"] is False
    en = discovery.parse_entra({"value": [{"displayName": "LAP1", "deviceId": "ABC", "operatingSystem": "MacOS", "operatingSystemVersion": "14.1"}]})[0]
    assert en["os_family"] == "macos" and en["uid"] == "abc"
    vm = discovery.parse_vmware([{"vm": "vm-1", "name": "db1", "cpu_count": 4, "memory_size_MiB": 8192}],
                                {"vm-1": {"ip_address": "10.0.0.8", "full_name": {"default_message": "Ubuntu Linux (64-bit)"}}})[0]
    assert vm["ip"] == "10.0.0.8" and vm["os_family"] == "linux" and vm["hardware"]["ram_gb"] == 8.0
    hv = discovery.parse_hyperv({"vms": [{"VMId": "x", "Name": "vm", "ProcessorCount": 2, "MemoryAssigned": 4 * 2**30,
                                           "NetworkAdapters": [{"MacAddress": "00155D010203", "IPAddresses": ["fe80::1", "10.0.0.9"]}]}]})[0]
    assert hv["ip"] == "10.0.0.9" and hv["hardware"]["ram_gb"] == 4.0
    aws = discovery.parse_aws([{"Instances": [{"InstanceId": "i-1", "PrivateIpAddress": "10.1.0.1", "PublicIpAddress": "3.3.3.3",
                                               "Tags": [{"Key": "Name", "Value": "api"}, {"Key": "Owner", "Value": "ana"}], "InstanceType": "t3.micro"}]}], "eu-west-1")[0]
    assert aws["name"] == "api" and aws["internet_exposed"] == "yes" and aws["owner"] == "ana" and aws["kind"] == "cloud_vm"
    az = discovery.parse_azure({"value": [{"id": "/subscriptions/s/vm1", "name": "vm1", "location": "westeurope",
                                           "properties": {"storageProfile": {"osDisk": {"osType": "Windows"}}, "hardwareProfile": {"vmSize": "D2"}}}]})[0]
    assert az["os_family"] == "windows" and az["cloud_provider"] == "azure"
    gc = discovery.parse_gcp({"items": {"zones/a": {"instances": [{"id": 1, "name": "g1", "networkInterfaces": [
        {"networkIP": "10.2.0.1", "accessConfigs": [{"natIP": "4.4.4.4"}]}], "disks": [{"licenses": ["x/windows-server"]}]}]}}})[0]
    assert gc["internet_exposed"] == "yes" and gc["os_family"] == "windows"
    assets, sw = discovery.parse_k8s(
        {"items": [{"metadata": {"name": "n1"}, "status": {"nodeInfo": {"osImage": "Ubuntu 22.04", "kernelVersion": "5.15", "kubeletVersion": "v1.29.1",
                                                                       "containerRuntimeVersion": "containerd://1.7.2"},
                                                           "addresses": [{"type": "InternalIP", "address": "10.3.0.1"}]}}]},
        {"items": [{"metadata": {"namespace": "prod"}, "spec": {"containers": [{"image": "docker.io/library/nginx:1.25.3"},
                                                                                 {"image": "registry/app:v2.0.1"}]}}]}, "main")
    kinds = {a["uid"]: a["kind"] for a in assets}
    assert kinds["k8s:main:node:n1"] == "k8s_node" and kinds["k8s:main:ns:prod"] == "k8s_workload"
    images = {s["name"]: s["version"] for s in sw["k8s:main:ns:prod"]}
    assert images == {"nginx": "1.25.3", "app": "2.0.1"} and sw["k8s:main:node:n1"][0]["version"] == "1.29.1"


def test_discovery_run_marks_shadow_it_and_stores_software(app, tenant, http):
    store.save(tenant.id, "k8s", "https://k8s.example:6443", "", {"token": "t"}, {"cluster": "main"}, True)
    db.session.commit()
    http.routes[("GET", "/api/v1/nodes")] = Resp({"items": [{"metadata": {"name": "n1"}, "status": {"nodeInfo": {"osImage": "Ubuntu", "kubeletVersion": "v1.29.1"},
                                                                                                    "addresses": []}}]})
    http.routes[("GET", "/api/v1/pods")] = Resp({"items": [{"metadata": {"namespace": "p"}, "spec": {"containers": [{"image": "nginx:1.25.3"}]}}]})
    res = discovery.run(Connector.query.filter_by(kind="k8s").one(), tenant)
    assert res == {"found": 2, "new": 2}
    ns = Asset.query.filter_by(uid="k8s:main:ns:p").one()
    assert ns.shadow_it and [s.name for s in ns.software] == ["nginx"]


# ------------------------------------------------------------------ SIEM / SOAR / ITSM / EDR


def test_emit_events_to_siem_and_soar(app, tenant, http):
    store.save(tenant.id, "splunk", "https://splunk.example:8088", "", {"token": "HEC"}, {"index": "sec"}, True)
    store.save(tenant.id, "tines", "https://tines.example/webhook/abc", "", {}, {}, True)
    store.save(tenant.id, "elastic", "https://es.example:9200", "", {"api_key": "KEY"}, {"index": "omx"}, True)
    db.session.commit()
    assert outbound.emit(tenant, "exposure_closed", {"cve": "CVE-2026-1"}) == 3
    by = {c["url"]: c for c in http.calls}
    sp = by["https://splunk.example:8088/services/collector/event"]
    assert sp["headers"]["Authorization"] == "Splunk HEC" and sp["json"]["event"]["cve"] == "CVE-2026-1" and sp["json"]["index"] == "sec"
    assert by["https://es.example:9200/omx/_doc"]["headers"]["Authorization"] == "ApiKey KEY"
    assert by["https://tines.example/webhook/abc"]["json"]["type"] == "exposure_closed"


def test_itsm_tickets_servicenow_jira_freshservice(app, tenant, http):
    store.save(tenant.id, "servicenow", "https://sn.example", "svc", {"password": "pw"}, {}, True)
    http.routes[("POST", "/api/now/table/incident")] = Resp({"result": {"number": "INC0012345"}})
    assert outbound.open_ticket(tenant, "titulo", "desc", "high") == "INC0012345"
    c = http.calls[-1]
    assert c["auth"] == ("svc", "pw") and c["json"]["urgency"] == "1" and c["json"]["category"] == "Security"
    Connector.query.filter_by(kind="servicenow").delete()
    store.save(tenant.id, "jira", "https://j.example", "a@b.pt", {"password": "tok"}, {"project": "SEC"}, True)
    http.routes[("POST", "/rest/api/3/issue")] = Resp({"key": "SEC-9"})
    assert outbound.open_ticket(tenant, "t", "d") == "SEC-9" and http.calls[-1]["json"]["fields"]["project"]["key"] == "SEC"
    Connector.query.filter_by(kind="jira").delete()
    store.save(tenant.id, "freshservice", "https://f.example", "KEYX", {"password": "X"}, {}, True)
    http.routes[("POST", "/api/v2/tickets")] = Resp({"ticket": {"id": 77}})
    assert outbound.open_ticket(tenant, "t", "d") == "77"


def test_apply_control_edr_ioc_and_delegation(app, tenant, http):
    a = make_asset(tenant)
    ctl = ControlAction(tenant_id=tenant.id, cve_id="CVE-2026-1", asset_id=a.id, category="firewall", action="block_ioc",
                        params=json.dumps({"ioc": "198.51.100.7"}), artifact="regra")
    db.session.add(ctl)
    db.session.commit()
    ok, detail = outbound.apply_control(tenant, ctl)
    assert not ok and "Sem conector" in detail
    store.save(tenant.id, "crowdstrike", "https://api.cs.example", "", {"token": "T"}, {}, True)
    db.session.commit()
    ok, detail = outbound.apply_control(tenant, ctl)
    body = http.calls[-1]["json"]["indicators"][0]
    assert ok and body == {**body, "type": "ipv4", "value": "198.51.100.7", "action": "prevent"} and "crowdstrike" in detail
    # regra de deteção (sem API segura) → delegada no SOAR
    rule = ControlAction(tenant_id=tenant.id, cve_id="CVE-2026-1", asset_id=a.id, category="edr", action="edr_detection", params="{}", artifact="sigma")
    db.session.add(rule)
    store.save(tenant.id, "tines", "https://tines.example/w", "", {}, {}, True)
    db.session.commit()
    ok, detail = outbound.apply_control(tenant, rule)
    assert not ok and "SOAR" in detail and http.calls[-1]["json"]["artifact"] == "sigma"


def test_connector_key_never_in_db_and_wrong_key_fails_cleanly(app, tenant, monkeypatch):
    c = store.save(tenant.id, "splunk", "https://s.example", "", {"token": "UNICO"}, {}, True)
    db.session.commit()
    assert "UNICO" not in c.secret and store.get_secrets(c) == {"token": "UNICO"}
    store.set_secrets(c, {"token": ""})                      # vazio mantém
    assert store.get_secrets(c)["token"] == "UNICO"
    from cryptography.fernet import Fernet
    monkeypatch.setenv("OMXPATCH_CONNECTORS_KEY", Fernet.generate_key().decode())
    with pytest.raises(ConnectorError):
        store.get_secrets(c)


# ------------------------------------------------------------------ OMXVuln: ativos + simulação da importação

ASSETS = [
    {"id": "a1", "hostname": "db01.corp", "ip_address": "10.0.1.10", "os": "Ubuntu 22.04", "criticality": "very_high", "tags": ["prod", {"name": "db"}],
     "owner": "dba@corp", "software": [{"name": "PostgreSQL", "version": "14.2"}]},
    {"name": "10.0.1.11", "type": "vm", "os_name": "Windows Server 2019", "os_family": "windows"},
    {"id": "x", "tags": ["sem-nome"]},
]


def _omxvuln_setup(tenant, http, assets=ASSETS, findings=FINDINGS, **opts):
    store.save(tenant.id, "omxvuln", "https://omxvuln.example", "", {"token": "TK"}, opts, True)
    db.session.commit()
    http.routes[("GET", "/api/v1/assets")] = Resp({"items": assets})
    http.routes[("GET", "/api/v1/findings")] = Resp(findings)


def test_omxvuln_asset_record_normalizes_aliases():
    r = omxvuln.asset_record(ASSETS[0])
    assert r["uid"] == "db01.corp" and r["ip"] == "10.0.1.10" and r["fqdn"] == "db01.corp" and r["criticality"] == "critical"
    assert r["tags"] == "prod,db" and r["_software"][0]["name"] == "PostgreSQL" and r["managed"] is False
    r2 = omxvuln.asset_record(ASSETS[1])
    assert r2["ip"] == "10.0.1.11" and r2["fqdn"] == "" and r2["os_family"] == "windows" and r2["kind"] == "server"
    assert omxvuln.asset_record(ASSETS[2]) is None


def test_omxvuln_sync_assets_and_findings_and_idempotency(app, tenant, http):
    _omxvuln_setup(tenant, http)
    res = omxvuln.sync(tenant, "both")
    assert res["new_assets"] >= 2 and res["skipped_assets"] == 1 and res["new_exposures"] == 2 and res["software_added"] == 1
    a = Asset.query.filter_by(uid="db01.corp").one()
    assert a.criticality == "critical" and a.owner == "dba@corp" and not a.managed and a.cmdb_ref == "omxvuln:a1"
    assert [s.name for s in a.software] == ["PostgreSQL"]
    again = omxvuln.sync(tenant, "both")
    assert again["new_assets"] == 0 and again["new_exposures"] == 0 and again["software_added"] == 0


def test_omxvuln_dry_run_writes_nothing(app, tenant, http):
    _omxvuln_setup(tenant, http)
    before = (Asset.query.count(), Exposure.query.count(), CveIntel.query.count())
    res = omxvuln.sync(tenant, "both", dry_run=True)
    assert res["dry_run"] and res["new_assets"] >= 2 and res["new_exposures"] == 2 and "db01.corp" in res["samples"]["assets"]
    assert (Asset.query.count(), Exposure.query.count(), CveIntel.query.count()) == before
    real = omxvuln.sync(tenant, "both")
    assert real["new_assets"] == res["new_assets"] and real["new_exposures"] == res["new_exposures"]       # a simulação é fiel


def test_omxvuln_managed_assets_are_only_completed_not_overwritten(app, tenant, http):
    a = make_asset(tenant, "db01.corp", software=(), ip="10.9.9.9", os_name="Debian 12", criticality="low")
    a.managed, a.source = True, "agent"
    db.session.commit()
    _omxvuln_setup(tenant, http, findings=[])
    omxvuln.sync(tenant, "assets")
    db.session.refresh(a)
    assert a.ip == "10.9.9.9" and a.os_name == "Debian 12" and a.criticality == "low" and a.managed        # nada sobrescrito
    assert a.owner == "dba@corp" and "prod" in a.tags                                                       # campos vazios completados


def test_omxvuln_assets_fallback_to_targets_and_min_severity(app, tenant, http):
    _omxvuln_setup(tenant, http, min_severity="critical")
    http.routes[("GET", "/api/v1/assets")] = Resp({}, 404)
    http.routes[("GET", "/api/v1/targets")] = Resp([{"id": 1, "value": ["web.corp"]}])
    res = omxvuln.sync(tenant, "both")
    assert Asset.query.filter_by(uid="web.corp").count() == 1
    assert res["new_exposures"] == 1 and Exposure.query.one().cve_id == "CVE-2026-0003"                      # só a crítica
    http.routes[("GET", "/api/v1/targets")] = Resp({}, 404)
    with pytest.raises(ConnectorError):
        omxvuln.sync(tenant, "assets")
    with pytest.raises(ConnectorError):
        omxvuln.sync(tenant, "tudo")


def test_omxvuln_import_page_and_api(app, tenant, http):
    from tests.conftest import login_as
    from tests.test_web import _api_token
    _omxvuln_setup(tenant, http)
    admin = login_as(app, "admin@alpha.example")
    assert admin.get("/integrations/omxvuln/import").status_code == 200
    r = admin.post("/integrations/omxvuln/import", {"what": "both", "mode": "simulate"})
    assert r.status_code == 200 and b"nada foi gravado" in r.data and Asset.query.count() == 0
    admin.post("/integrations/omxvuln/import", {"what": "both", "mode": "apply"})                      # sem OK
    assert Asset.query.count() == 0
    admin.post("/integrations/omxvuln/import", {"what": "both", "mode": "apply", "confirm_ok": "1"})
    assert Asset.query.filter_by(uid="db01.corp").count() == 1 and Exposure.query.count() == 2
    h = {"Authorization": f"Bearer {_api_token(admin)}"}
    c = app.test_client()
    r = c.post("/api/v1/sync/omxvuln", headers=h, json={"what": "assets", "dry_run": True})
    assert r.status_code == 200 and r.get_json()["dry_run"] and "findings" not in r.get_json()
    assert c.post("/api/v1/sync/omxvuln", headers=h, json={"what": "x"}).status_code == 409
    aud = login_as(app, "auditor@alpha.example")
    assert aud.get("/integrations/omxvuln/import").status_code == 403
