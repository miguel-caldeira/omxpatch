"""Motores: risco, versões, inteligência, correlação, patches, controlos, IA, validação, simulação."""
import json
from datetime import timedelta

import pytest

from omxpatch.engine import (advisor, correlate, controls, intel, inventory, patches, risk, simulation, validation)
from omxpatch.engine.versions import compare, in_range
from omxpatch.extensions import db
from omxpatch.models import (Agent, Asset, ControlAction, CveIntel, Exposure, Patch, Signal, Task, Validation, utcnow)
from tests.conftest import make_asset, make_cve


def test_versions():
    assert compare("1.1.1w", "1.1.1") > 0 and compare("3.0.2", "3.0.10") < 0 and compare("1.0", "1.0.0") == 0
    assert compare("1.0rc1", "1.0") < 0 and compare("8.0.351", "8.0.361") < 0
    assert in_range("1.1.1k", end_excl="1.1.1w") and not in_range("1.1.1w", end_excl="1.1.1w")
    assert in_range("2.4.50", start="2.4.0", end="2.4.55") and not in_range("2.3.9", start="2.4.0")
    assert not in_range("", end_excl="2")


def test_risk_score_factors_and_categories(app, tenant):
    cve = make_cve(cvss=10.0, kev=True, epss=0.9, maturity="weaponized", ransomware=True)
    a = make_asset(tenant, criticality="critical", business_value=100, ip="8.8.4.10")
    res = risk.score_exposure(cve, a, evidence_observed=True)
    assert sum(f["max"] for f in res["factors"]) == 100
    assert res["score"] == 100 and res["category"] == "emergency"
    low = risk.score_exposure(make_cve("CVE-2026-0002", cvss=2.0), make_asset(tenant, "x", ip="10.1.1.1", criticality="low", business_value=0))
    assert low["category"] == "low" and low["score"] < 25
    assert [risk.category_for(s) for s in (0, 24, 25, 49, 50, 69, 70, 84, 85, 100)] == \
        ["low", "low", "medium", "medium", "high", "high", "critical", "critical", "emergency", "emergency"]
    assert risk.asset_risk([50, 50]) == 75 and risk.asset_risk([]) == 0


def test_residual_risk_with_controls(app, tenant):
    cve = make_cve(cvss=9.0, kev=True, epss=0.6)
    a = make_asset(tenant, ip="8.8.4.7")
    ctl = ControlAction(tenant_id=tenant.id, cve_id=cve.cve_id, category="firewall", action="block_port", status="verified")
    res = risk.score_exposure(cve, a, False, [ctl])
    assert res["residual"] < res["score"]
    proposed = ControlAction(tenant_id=tenant.id, cve_id=cve.cve_id, category="firewall", action="block_port", status="proposed")
    assert risk.score_exposure(cve, a, False, [proposed])["residual"] == res["score"]


def test_multivendor_verdict_critical_combo(app, tenant):
    cve = make_cve(kev=True)
    a = make_asset(tenant, ip="8.8.4.9")
    ex = Exposure(tenant_id=tenant.id, asset_id=a.id, cve_id=cve.cve_id, status="open", patch_available=False)
    db.session.add(ex)
    db.session.flush()
    sigs = [Signal(tenant_id=tenant.id, source="crowdstrike", kind="active_exploit", cve_id=cve.cve_id),
            Signal(tenant_id=tenant.id, source="paloalto", kind="fw_allowed", asset_id=a.id),
            Signal(tenant_id=tenant.id, source="defender", kind="edr_missed", asset_id=a.id)]
    v = risk.exposure_verdict(ex, cve, a, sigs, [])
    assert v["critical"] and v["floor"] == "emergency"
    assert "Firewall não bloqueia" in [c["text"] for c in v["conclusions"]]
    # com patch disponível deixa de ser o caso crítico
    ex.patch_available = True
    assert not risk.exposure_verdict(ex, cve, a, sigs, [])["critical"]
    ex.patch_available = False
    sigs.append(Signal(tenant_id=tenant.id, source="paloalto", kind="fw_blocked", asset_id=a.id,
                       observed_at=utcnow() + timedelta(minutes=1)))
    assert not risk.exposure_verdict(ex, cve, a, sigs, [])["critical"]


KEV = {"vulnerabilities": [{"cveID": "CVE-2026-1111", "vulnerabilityName": "X RCE", "dateAdded": "2026-01-02",
                            "dueDate": "2026-01-23", "knownRansomwareCampaignUse": "Known", "vendorProject": "Acme",
                            "product": "Widget"}]}
NVD = {"vulnerabilities": [{"cve": {"id": "CVE-2026-1111", "published": "2026-01-01T00:00:00.000",
       "descriptions": [{"lang": "en", "value": "Widget RCE"}],
       "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N"}}]},
       "weaknesses": [{"description": [{"value": "CWE-78"}]}],
       "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                                                    "versionEndExcluding": "2.5.0"}]}]}],
       "references": [{"url": "https://x/exp", "tags": ["Exploit"]}, {"url": "https://x/fix", "tags": ["Patch"]}]}}]}


def test_intel_parsers_and_merge(app):
    assert intel.apply_kev(intel.parse_kev(KEV)) == 1
    intel.apply_nvd(intel.parse_nvd(NVD))
    intel.apply_epss(intel.parse_epss({"data": [{"cve": "CVE-2026-1111", "epss": "0.71", "percentile": "0.98"}]}))
    intel.apply_threat_feed(intel.parse_threat_feed([{"cve": "CVE-2026-1111", "malware": ["LockBit"], "exploit": "weaponized"}]))
    intel.apply_advisories(intel.parse_advisories({"advisories": [{"cve": "CVE-2026-1111", "vendor": "Acme", "product": "Widget",
                                                                    "fixed_version": "2.5.0", "url": "https://acme/adv"}]}))
    db.session.commit()
    c = CveIntel.query.filter_by(cve_id="CVE-2026-1111").one()
    assert c.kev and c.ransomware and c.cvss == 9.8 and c.epss == pytest.approx(0.71)
    assert c.exploit_maturity == "weaponized" and "LockBit" in c.malware_list and c.cwe == "CWE-78"
    assert {"kev", "nvd", "epss", "threat-feed", "vendor"} <= set(c.sources.split(","))
    assert any(a.get("end_excl") == "2.5.0" for a in c.affected_list)
    assert intel.parse_mitre({"cveMetadata": {"cveId": "CVE-2026-2"}, "containers": {"cna": {"descriptions": [
        {"lang": "en", "value": "d"}], "affected": [{"vendor": "V", "product": "P", "versions": [
            {"version": "1.0", "status": "affected", "lessThan": "1.5"}]}]}}})["affected"][0]["fixed"] == "1.5"
    assert intel.import_file(json.dumps(KEV))["kind"] == "kev"


def test_correlation_asset_software_version_cve_patch(app, tenant):
    make_cve(kev=True, epss=0.4, advisories=[{"vendor": "OpenSSL", "product": "openssl", "fixed_version": "1.1.1w",
                                               "os_family": "linux", "package": "openssl", "installer": "apt"}])
    a = make_asset(tenant, software=(("OpenSSL", "1.1.1k"), ("nginx", "1.25.0")))
    res = correlate.correlate_asset(tenant, a)
    db.session.commit()
    assert res["new"] == 1
    ex = Exposure.query.one()
    assert ex.cve_id == "CVE-2026-0001" and ex.installed_version == "1.1.1k" and ex.fixed_version == "1.1.1w"
    assert ex.patch_available and ex.patch.installer == "apt" and ex.risk_score > 40
    assert ex.due_date is not None and ex.verdict_data["active_exploitation_known"]
    # versão corrigida: não correlaciona
    b = make_asset(tenant, "ok", software=(("OpenSSL", "1.1.1w"),), ip="10.0.0.6")
    assert correlate.correlate_asset(tenant, b)["new"] == 0


def test_correlation_remediated_when_software_updated_schedules_validation(app, tenant):
    make_cve()
    a = make_asset(tenant)
    correlate.correlate_asset(tenant, a)
    ex = Exposure.query.one()
    sw = a.software.first()
    sw.version = "1.1.1w"
    db.session.flush()
    r = correlate.correlate_asset(tenant, a)
    assert r["remediated"] == 1 and ex.status == "remediated"
    v = Validation.query.filter_by(exposure_id=ex.id).one()
    assert v.status == "pending" and Task.query.filter_by(type="validate", asset_id=a.id).count() == 1


def test_windows_kb_correlation(app, tenant):
    make_cve("CVE-2026-0100", product="x", advisories=[{"vendor": "Microsoft", "product": "Windows 11", "kb": "KB5031234",
                                                         "os_family": "windows"}])
    a = make_asset(tenant, "pc1", software=(), os_family="windows", os_name="Windows 11", os_version="23H2", ip="10.0.0.9")
    a.hardware = json.dumps({"hotfixes": ["KB1"]})
    correlate.correlate_asset(tenant, a)
    ex = Exposure.query.filter_by(cve_id="CVE-2026-0100").one()
    assert ex.fixed_version == "KB5031234" and ex.patch.installer == "wua" and ex.patch.patch_uid == "KB5031234"
    a.hardware = json.dumps({"hotfixes": ["KB5031234"]})
    assert correlate.correlate_asset(tenant, a)["remediated"] == 1


def test_patch_intelligence_levels(app, tenant):
    p = Patch(tenant_id=tenant.id, patch_uid="KB1", status="approved")
    db.session.add(p)
    db.session.flush()
    assert patches.intelligence(p)["level"] == "caution"          # sem histórico → começar no Ring 0
    p.community_reports, p.community_success_rate = 500, 99.0
    assert patches.intelligence(p)["level"] == "go"
    p.vendor_known_issues = json.dumps([{"title": "BSOD em Hyper-V", "severity": "high"}])
    i = patches.intelligence(p)
    assert i["level"] == "hold" and "BSOD" in " ".join(i["reasons"])
    p.vendor_known_issues = "[]"
    for _ in range(3):
        patches.record_telemetry(tenant.id, p.id, None, "rolled_back")
    db.session.flush()
    assert patches.intelligence(p)["level"] == "hold"
    p2 = Patch(tenant_id=tenant.id, patch_uid="KB2")
    db.session.add(p2)
    db.session.flush()
    p2.community_reports, p2.community_success_rate = 100, 70.0
    assert patches.intelligence(p2)["level"] == "hold"


def test_patch_repository_integrity(app, tenant):
    p = Patch(tenant_id=tenant.id, patch_uid="pkg1", sha256="0" * 64, installer="msi")
    db.session.add(p)
    db.session.flush()
    with pytest.raises(ValueError, match="SHA-256"):
        patches.store_file(p, tenant, b"conteudo", "x.msi")
    import hashlib
    p.sha256 = hashlib.sha256(b"conteudo").hexdigest()
    patches.store_file(p, tenant, b"conteudo", "../../x.msi")
    assert p.status == "downloaded" and patches.local_path(p, tenant).read_bytes() == b"conteudo"
    assert ".." not in p.local_file


def test_controls_suggest_artifacts_and_lifecycle(app, tenant):
    cve = make_cve(kev=True, cwe="CWE-22", maturity="weaponized")
    a = make_asset(tenant, software=(("Apache httpd", "2.4.50"),), ip="8.8.4.5", open_ports="8443")
    ex = Exposure(tenant_id=tenant.id, asset_id=a.id, cve_id=cve.cve_id, software_name="Apache httpd", port=8443, status="open",
                  risk_score=80, risk_category="critical")
    db.session.add(ex)
    db.session.flush()
    created = controls.propose_for(tenant, ex)
    actions = {c.action for c in created}
    assert {"block_port", "edr_detection", "siem_rule", "virtual_patch"} <= actions
    assert controls.propose_for(tenant, ex) == []                        # sem duplicados
    by = {c.action: c for c in created}
    assert "dport 8443" in by["block_port"].artifact and "SecRule" in by["virtual_patch"].artifact
    assert "CVE-2026-0001" in by["siem_rule"].artifact
    c = by["block_port"]
    with pytest.raises(ValueError):
        controls.apply(c, tenant)                                         # exige aprovação
    controls.approve(c)
    controls.apply(c, tenant)
    t = Task.query.filter_by(type="control").one()
    assert t.payload_data["op"] == "firewall_block_port" and t.payload_data["port"] == 8443
    controls.on_report(t, {"status": "succeeded", "verified": True})
    assert c.status == "verified"
    correlate.refresh(ex, tenant, cve)
    assert ex.status == "mitigated" and ex.residual_score < ex.risk_score
    # patch aplicado: controlo temporário é revertido
    ex.status = "closed"
    controls.retire_for(ex)
    assert Task.query.filter_by(type="control").count() == 2 and by["edr_detection"].status == "rejected"


def test_advisor_reaches_target_with_minimum_steps(app, tenant):
    cve1 = make_cve("CVE-2026-0001", kev=True, epss=0.9, maturity="weaponized", ransomware=True)
    cve2 = make_cve("CVE-2026-0002", cvss=8.0, epss=0.3, product="apache", vendor="apache", end_excl="2.4.58")
    a = make_asset(tenant, software=(("OpenSSL", "1.1.1k"), ("Apache httpd", "2.4.50")), ip="8.8.4.5", criticality="critical")
    correlate.correlate_asset(tenant, a)
    db.session.commit()
    exs = Exposure.query.filter_by(asset_id=a.id).all()
    assert len(exs) == 2
    p = advisor.plan(tenant, exs, target=20)
    assert p["before"] > 60 and p["after"] < 20 and p["reached"]
    assert p["steps"] == sorted(p["steps"], key=lambda s: s["effort"])
    assert all(s["reduction"] > 0 for s in p["steps"])
    assert advisor.parse_target("Como reduzir o risco para menos de 35 pontos?") == 35
    assert advisor.parse_target("reduzir risco") == 20
    row = advisor.ask(tenant, "Como reduzir o risco para menos de 20 pontos?", a)
    assert row.after_score < 20 and "→" not in row.narrative or row.narrative
    assert "Para reduzir o risco" in row.narrative
    res = advisor.apply_plan(tenant, row)
    assert row.status == "applied" and (res["controls"] or res["patches_to_approve"] or res["campaigns"])


def test_validation_closed_loop_closes_and_fails(app, tenant):
    make_cve()
    a = make_asset(tenant)
    correlate.correlate_asset(tenant, a)
    ex = Exposure.query.one()
    ex.status, ex.patched_at = "remediated", utcnow()
    v = validation.schedule(ex, tenant)
    # 1.ª tentativa: o software continua vulnerável → repete
    validation.evaluate(v, {"patch_installed": True, "service_restarted": True,
                            "software": [{"name": "OpenSSL", "version": "1.1.1k"}]})
    assert v.status == "pending" and v.check_data["cve_gone"] is False
    assert Task.query.filter_by(type="validate").count() == 2
    # CVE desaparece
    validation.evaluate(v, {"patch_installed": True, "service_restarted": True,
                            "software": [{"name": "OpenSSL", "version": "1.1.1w"}], "full_inventory": True})
    assert v.status == "passed" and ex.status == "closed" and ex.closed_at
    assert v.check_data["cve_gone"] and v.check_data["exposure_eliminated"] and "compliance" in v.check_data
    assert db.session.get(Asset, a.id).cmdb_synced_at is not None


def test_validation_gives_up_after_three_attempts(app, tenant):
    make_cve()
    a = make_asset(tenant)
    correlate.correlate_asset(tenant, a)
    ex = Exposure.query.one()
    ex.status = "remediated"
    v = validation.schedule(ex, tenant)
    for _ in range(3):
        validation.evaluate(v, {"patch_installed": False, "software": [{"name": "OpenSSL", "version": "1.1.1k"}]})
    assert v.status == "failed" and ex.status == "open"


def test_simulation_outcomes_and_comparison(app, tenant):
    a = make_asset(tenant)
    db.session.add(Agent(tenant_id=tenant.id, asset_id=a.id, key_hash="h" * 64, key_prefix="p", hostname="srv1"))
    db.session.flush()
    db.session.refresh(a)
    s1 = simulation.start(tenant, a, "ransomware")
    t1 = db.session.get(Task, s1.task_id)
    assert t1.type == "bas" and set(t1.payload_data["steps"]) == set(simulation.SCENARIOS["ransomware"]["steps"])
    simulation.on_report(t1, {"status": "succeeded", "steps": [{"id": "canary_encrypt", "passed": False, "detail": "cifrou"},
                                                               {"id": "edr_service", "passed": True},
                                                               {"id": "shadow_copy_protection", "passed": None}]})
    assert s1.outcome == "partial" and s1.status == "done"
    s2 = simulation.start(tenant, a, "ransomware", phase="after_fix", baseline=s1)
    simulation.on_report(db.session.get(Task, s2.task_id), {"status": "succeeded", "steps": [
        {"id": i, "passed": True} for i in simulation.SCENARIOS["ransomware"]["steps"]]})
    cmp = simulation.compare(s2)
    assert s2.outcome == "blocked" and cmp["improved"] and cmp["validated"]
    nag = make_asset(tenant, "noagent", ip="10.0.0.77")
    assert simulation.start(tenant, nag, "credential_theft").outcome == "error"


def test_inventory_upsert_history_and_shadow_it(app, tenant):
    a, created = inventory.upsert_asset(tenant, {"name": "Host1", "ip": "10.0.0.1", "owner": "ana"}, source="agentless")
    assert created and not a.managed
    a.shadow_it = True
    a2, created2 = inventory.upsert_asset(tenant, {"name": "Host1", "owner": "rui", "ip": "999.1.1.1", "managed": True}, source="agent")
    db.session.commit()
    assert a2.id == a.id and not created2 and a.owner == "rui" and a.ip == "10.0.0.1" and not a.shadow_it
    from omxpatch.models import CmdbChange
    assert CmdbChange.query.filter_by(asset_id=a.id, field="owner").count() == 1
    r = inventory.set_software(a, [{"name": "A", "version": "1"}, {"name": "B", "version": "2"}])
    assert r == {"added": 2, "removed": 0}
    assert inventory.set_software(a, [{"name": "A", "version": "1"}]) == {"added": 0, "removed": 1}


def test_sweep_classifies_and_marks_shadow_it(app, tenant):
    fake = lambda host, ports, timeout: {"10.9.0.1": [22], "10.9.0.2": [3389, 445], "10.9.0.3": [502]}.get(host, [])  # noqa: E731
    res = inventory.sweep(tenant, "10.9.0.0/29", prober=fake)
    assert res["found"] == 3 and res["shadow_it"] == 3
    kinds = {a.ip: (a.kind, a.os_family) for a in Asset.query.filter_by(tenant_id=tenant.id)}
    assert kinds["10.9.0.1"] == ("server", "linux") and kinds["10.9.0.2"] == ("workstation", "windows") and kinds["10.9.0.3"][0] == "ot"
    with pytest.raises(ValueError):
        inventory.sweep(tenant, "10.0.0.0/8", prober=fake)
    with pytest.raises(ValueError):
        inventory.parse_targets("não-é-ip")


def test_management_ports_are_protected_from_accidental_block(app, tenant):
    a = make_asset(tenant)
    c = ControlAction(tenant_id=tenant.id, cve_id="CVE-2026-0001", asset_id=a.id, category="firewall", action="block_port",
                      params=json.dumps({"port": 22}), status="approved")
    db.session.add(c)
    db.session.flush()
    with pytest.raises(ValueError, match="gestão"):
        controls.apply(c, tenant)
    c.params = json.dumps({"port": 22, "allow_management_port": True})
    controls.apply(c, tenant)
    assert Task.query.filter_by(type="control").count() == 1
