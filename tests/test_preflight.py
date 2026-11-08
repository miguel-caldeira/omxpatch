"""Origens de atualização no Windows (via agente) e simulação prévia (pré-voo) antes da instalação real."""
import hashlib
import json
import platform
from datetime import timedelta

import pytest

from omxpatch.engine import deploy, patches, preflight, rings, sources
from omxpatch.extensions import db
from omxpatch.models import Agent, Asset, Campaign, Exposure, Patch, Preflight, Task, utcnow
from omxpatch.worker import Worker
from omxpatch_agent import preflight as agent_pf, sources as agent_sources, staging
from omxpatch_agent.patchers import PatchError, linux as plinux, windows as pwin
from omxpatch_agent.runner import Result
from tests.conftest import make_asset, make_cve
from tests.test_flow import FakeAgent, enroll_token, setup_vuln  # noqa: F401


def win_caps(**over):
    base = {"os": "windows", "context": {"system": True, "admin": True}, "sources": {
        "wua": {"available": True, "detail": "Microsoft Update"}, "winget": {"available": True, "detail": "C:\\winget.exe"},
        "choco": {"available": False, "detail": "Chocolatey não instalado"}, "msi": {"available": True, "detail": "msiexec"},
        "exe": {"available": True, "detail": ""}, "msu": {"available": True, "detail": ""}, "cab": {"available": True, "detail": ""},
        "office_c2r": {"available": False, "detail": "Office não instalado"}}}
    base["sources"].update(over)
    return base


# ------------------------------------------------------------------ capacidades (agente)


def test_windows_capability_parsing_system_wsus_and_missing_tools():
    d = {"system": True, "admin": True, "ps": "5.1.22621.1", "user": "NT AUTHORITY\\SYSTEM", "wuauserv": {"exists": True, "status": "Running", "start": "Manual"},
         "wsus": "http://wsus.corp:8530", "use_wsus": 1, "winget": "C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_1.22_x64__8wekyb3d8bbwe\\winget.exe",
         "choco": None, "c2r": "C:\\...\\OfficeC2RClient.exe", "c2r_version": "16.0.17126.20132", "msiexec": True, "wusa": True, "dism": True, "free_gb": 80.5}
    c = agent_sources.build_windows(d)
    s = c["sources"]
    assert s["wua"]["available"] and "WSUS: http://wsus.corp:8530" in s["wua"]["detail"] and c["context"]["wsus"] == "http://wsus.corp:8530"
    assert s["winget"]["available"] and not s["choco"]["available"] and "não instalado" in s["choco"]["detail"]
    assert s["office_c2r"]["available"] and "16.0.17126" in s["office_c2r"]["detail"]
    d2 = {**d, "system": False, "admin": False, "wuauserv": {"exists": True, "status": "Stopped", "start": "Disabled"}, "winget": None}
    s2 = agent_sources.build_windows(d2)["sources"]
    assert not s2["wua"]["available"] and not s2["winget"]["available"] and not s2["msi"]["available"] and not s2["exe"]["available"]


def test_posix_capabilities(monkeypatch):
    monkeypatch.setattr(agent_sources, "_which", lambda n: "/usr/bin/" + n if n in ("apt-get", "snap") else None)
    monkeypatch.setattr(agent_sources.os, "geteuid", lambda: 0)
    s = agent_sources.build_posix("linux")["sources"]
    assert s["apt"]["available"] and not s["dnf"]["available"] and "não encontrado" in s["dnf"]["detail"]
    monkeypatch.setattr(agent_sources.os, "geteuid", lambda: 1000)
    assert not agent_sources.build_posix("linux")["sources"]["apt"]["available"]          # sem root


def test_probe_failure_is_reported_not_raised(monkeypatch):
    monkeypatch.setattr(agent_sources, "platform_family", lambda: "windows")
    monkeypatch.setattr(agent_sources, "powershell", lambda *a, **k: Result(1, "erro"))
    assert "falhou" in agent_sources.capabilities()["error"]


# ------------------------------------------------------------------ instaladores Windows (comandos e códigos de saída)


def test_file_installer_commands_and_validation():
    p = {"silent_args": "/qn /norestart ALLUSERS=1"}
    assert pwin.file_command("msi", "C:\\t\\a.msi", p) == ["msiexec", "/i", "C:\\t\\a.msi", "/qn", "/norestart", "ALLUSERS=1"]
    assert pwin.file_command("msp", "C:\\t\\a.msp", {})[:3] == ["msiexec", "/p", "C:\\t\\a.msp"]
    assert pwin.file_command("exe", "C:\\t\\a.exe", {"silent_args": "/quiet"}) == ["C:\\t\\a.exe", "/quiet"]
    assert pwin.file_command("msu", "C:\\t\\a.msu", {}) == ["wusa.exe", "C:\\t\\a.msu", "/quiet", "/norestart"]
    assert pwin.file_command("cab", "C:\\t\\a.cab", {})[:3] == ["dism.exe", "/online", "/add-package"]
    for bad in ("/S & calc", "/S; rm", "$(id)", "/S | more", "`x`"):
        with pytest.raises(PatchError):
            pwin.file_command("exe", "x.exe", {"silent_args": bad})
    with pytest.raises(PatchError):
        pwin.file_command("zip", "x", {})


def run_script(monkeypatch, rc=0, out="", ps_out=None):
    calls = []
    monkeypatch.setattr(pwin, "run", lambda cmd, timeout=3600, **k: (calls.append(cmd), Result(rc, out))[1])
    monkeypatch.setattr(pwin, "powershell", lambda s, timeout=3600: (calls.append(["powershell", s[:40]]), Result(rc if ps_out is None else 0, ps_out if ps_out is not None else out))[1])
    monkeypatch.setattr(pwin.sources, "find_winget", lambda: "C:\\winget.exe")
    monkeypatch.setattr(pwin.sources, "find_choco", lambda: "C:\\choco.exe")
    return calls


def test_windows_apply_exit_codes_per_source(monkeypatch):
    dl = lambda suffix: "C:\\tmp\\pkg" + suffix  # noqa: E731
    calls = run_script(monkeypatch, 3010)
    r = pwin.apply({"installer": "msi", "reboot_policy": "none"}, dl)
    assert r["status"] == "succeeded" and r["reboot_pending"] is True and calls[0][:2] == ["msiexec", "/i"]
    run_script(monkeypatch, 1638)
    assert pwin.apply({"installer": "msi", "reboot_policy": "none"}, dl)["status"] == "succeeded"       # já instalado
    run_script(monkeypatch, 1603)
    assert pwin.apply({"installer": "msi", "reboot_policy": "none"}, dl)["status"] == "failed"
    run_script(monkeypatch, 2359302)
    assert pwin.apply({"installer": "msu", "reboot_policy": "none"}, dl)["status"] == "succeeded"
    c = run_script(monkeypatch, -1979842517)
    assert pwin.apply({"installer": "winget", "package": "Mozilla.Firefox"}, dl)["status"] == "succeeded"
    assert c[0][0] == "C:\\winget.exe" and "--scope" in c[0] and "machine" in c[0] and c[0][1:3] == ["upgrade", "--id"]
    c = run_script(monkeypatch, 3010)
    r = pwin.apply({"installer": "choco", "package": "firefox", "reboot_policy": "none"}, dl)
    assert r["reboot_pending"] and c[0][:3] == ["C:\\choco.exe", "upgrade", "firefox"]
    run_script(monkeypatch, 0, "RESULT_CODE=2 REBOOT=True")
    r = pwin.apply({"installer": "wua", "uid": "KB5031234", "reboot_policy": "none"}, dl)
    assert r["status"] == "succeeded" and r["reboot_pending"]
    run_script(monkeypatch, 0, "NOT_APPLICABLE: KB5031234")
    assert pwin.apply({"installer": "wua", "uid": "KB5031234", "reboot_policy": "none"}, dl)["status"] == "succeeded"
    c = run_script(monkeypatch, 0)
    pwin.apply({"installer": "office_c2r", "reboot_policy": "none"}, dl)
    assert "/update" in c[0] and "user" in c[0]
    with pytest.raises(PatchError):
        pwin.apply({"installer": "wua", "uid": "KB1; calc"}, dl)
    with pytest.raises(PatchError):
        pwin.apply({"installer": "winget", "package": "x; calc"}, dl)
    with pytest.raises(PatchError):
        pwin.apply({"installer": "rpm"}, dl)


# ------------------------------------------------------------------ parsers da simulação


def test_parsers_winget_choco_marker_apt():
    winget = ("Name           Id                  Version   Available Source\n------------------------------------------------------\n"
              "Mozilla Firefox Mozilla.Firefox     128.0.1   129.0     winget\n1 upgrades available.\n")
    assert pwin.parse_winget_upgrade(winget, "Mozilla.Firefox") == {"installed": "128.0.1", "available": "129.0"}
    assert pwin.parse_winget_upgrade("Nenhum pacote instalado corresponde.", "Mozilla.Firefox") == {}
    assert pwin.parse_choco_outdated("firefox|128.0|129.0|false\nvlc|3.0|3.1|true\n", "vlc") == {"installed": "3.0", "available": "3.1", "pinned": True}
    assert pwin.parse_choco_outdated("firefox|1|2|false", "git") == {}
    assert pwin.parse_marker('x\nOMXPATCH_SIM={"a": 1}\nOMXPATCH_SIM={"a": 2}\n') == {"a": 2} and pwin.parse_marker("nada") is None
    apt = ("Inst libssl3 [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.15 Ubuntu:22.04/jammy-updates [amd64])\n"
           "Inst openssl [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.15 Ubuntu:22.04/jammy-updates [amd64])\nRemv oldlib [1.0]\nConf openssl (x)\n")
    d = plinux.parse_apt_sim(apt, "openssl")
    assert d["target"] == {"old": "3.0.2-0ubuntu1.10", "new": "3.0.2-0ubuntu1.15"} and d["others"] == ["libssl3"] and d["removed"] == ["oldlib"]


# ------------------------------------------------------------------ simulação (dry-run) por instalador


def test_windows_simulate_wua_cases(monkeypatch):
    stage = lambda s: (_ for _ in ()).throw(AssertionError("wua não usa staging"))  # noqa: E731
    sim = lambda d: monkeypatch.setattr(pwin, "powershell", lambda s, timeout=0: Result(0, "OMXPATCH_SIM=" + json.dumps(d)))  # noqa: E731
    sim({"applicable": True, "installed": False, "title": "2024-10 Cumulative Update (KB5031234)", "size_mb": 612.4, "reboot": True, "downloaded": False, "eula": True})
    r = pwin.simulate({"installer": "wua", "uid": "KB5031234"}, stage)
    assert r["checks"][0]["status"] == "ok" and r["predicted"]["reboot"] and r["predicted"]["download_mb"] == 612.4
    sim({"applicable": False, "installed": True})
    r = pwin.simulate({"installer": "wua", "uid": "KB5031234"}, stage)
    assert r["predicted"]["noop"] and "já está instalada" in r["checks"][0]["detail"]
    sim({"applicable": False, "installed": False})
    r = pwin.simulate({"installer": "wua", "uid": "KB5031234"}, stage)
    assert r["predicted"]["noop"] and r["checks"][0]["status"] == "warn" and "WSUS" in r["checks"][0]["detail"]
    monkeypatch.setattr(pwin, "powershell", lambda s, timeout=0: Result(1, "Access denied"))
    assert pwin.simulate({"installer": "wua", "uid": "KB5031234"}, stage)["checks"][0]["status"] == "block"
    with pytest.raises(PatchError):
        pwin.simulate({"installer": "wua", "uid": "5031234"}, stage)


def test_windows_simulate_winget_choco_file_and_office(monkeypatch, tmp_path):
    winget = "Name Id Version Available Source\nMozilla Firefox Mozilla.Firefox 128.0.1 129.0 winget\n"
    monkeypatch.setattr(pwin, "run", lambda cmd, timeout=0, **k: Result(0, winget))
    monkeypatch.setattr(pwin.sources, "find_winget", lambda: "winget")
    r = pwin.simulate({"installer": "winget", "package": "Mozilla.Firefox"}, None)
    assert r["predicted"]["version_before"] == "128.0.1" and r["predicted"]["version_after"] == "129.0" and "noop" not in r["predicted"]
    monkeypatch.setattr(pwin, "run", lambda cmd, timeout=0, **k: Result(0, ""))
    assert pwin.simulate({"installer": "winget", "package": "Mozilla.Firefox"}, None)["predicted"]["noop"]
    monkeypatch.setattr(pwin.sources, "find_choco", lambda: "choco")
    monkeypatch.setattr(pwin, "run", lambda cmd, timeout=0, **k: Result(0, "vlc|3.0|3.1|true"))
    r = pwin.simulate({"installer": "choco", "package": "vlc"}, None)
    assert r["checks"][0]["status"] == "block" and "fixado" in r["checks"][0]["detail"]
    # MSI: staging + assinatura + propriedades
    f = tmp_path / "a.msi"; f.write_bytes(b"msi")
    outs = iter(['OMXPATCH_SIM={"status": "Valid", "signer": "CN=Mozilla"}', 'OMXPATCH_SIM={"ProductName": "Firefox", "ProductVersion": "129.0", "Manufacturer": "Mozilla"}'])
    monkeypatch.setattr(pwin, "powershell", lambda s, timeout=0: Result(0, next(outs)))
    r = pwin.simulate({"installer": "msi", "uid": "x", "silent_args": "/qn"}, lambda suffix: str(f))
    ids = {c["id"]: c for c in r["checks"]}
    assert ids["signature"]["status"] == "ok" and r["predicted"]["version_after"] == "129.0" and ids["package"]["status"] == "ok"
    monkeypatch.setattr(pwin, "powershell", lambda s, timeout=0: Result(0, 'OMXPATCH_SIM={"status": "HashMismatch", "signer": ""}'))
    assert {c["id"]: c for c in pwin.simulate({"installer": "exe"}, lambda s: str(f))["checks"]}["signature"]["status"] == "block"
    monkeypatch.setattr(pwin, "powershell", lambda s, timeout=0: Result(0, 'OMXPATCH_SIM={"status": "NotSigned"}'))
    assert {c["id"]: c for c in pwin.simulate({"installer": "exe"}, lambda s: str(f))["checks"]}["signature"]["status"] == "warn"
    # argumentos perigosos são rejeitados na simulação, não na instalação
    with pytest.raises(PatchError):
        pwin.simulate({"installer": "exe", "silent_args": "/S & calc"}, lambda s: str(f))
    # Office C2R
    monkeypatch.setattr(pwin.sources, "office_c2r_path", lambda: str(f))
    monkeypatch.setattr(pwin, "powershell", lambda s, timeout=0: Result(0, "16.0.17126.20132\n"))
    assert pwin.simulate({"installer": "office_c2r", "version_fixed": "16.0.17000.0"}, None)["predicted"]["noop"]
    assert "noop" not in pwin.simulate({"installer": "office_c2r", "version_fixed": "16.0.18000.0"}, None)["predicted"]
    monkeypatch.setattr(pwin.sources, "office_c2r_path", lambda: str(tmp_path / "nao-existe.exe"))
    assert pwin.simulate({"installer": "office_c2r"}, None)["checks"][0]["status"] == "block"


def test_linux_simulate_apt_dnf(monkeypatch):
    monkeypatch.setattr(plinux, "_manager", lambda: "apt-get")
    monkeypatch.setattr(plinux, "installed_version", lambda p: "3.0.2-0ubuntu1.10")
    apt = "Inst openssl [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.15 Ubuntu [amd64])\nInst libssl3 [a] (b Ubuntu [amd64])\n"
    monkeypatch.setattr(plinux, "run", lambda cmd, timeout=0, **k: Result(0, apt))
    r = plinux.simulate({"installer": "apt", "package": "openssl"}, None)
    assert r["predicted"]["version_after"] == "3.0.2-0ubuntu1.15" and r["predicted"]["changes"] == ["libssl3"] and r["predicted"]["reboot"] is True
    monkeypatch.setattr(plinux, "run", lambda cmd, timeout=0, **k: Result(0, "0 upgraded, 0 newly installed\n"))
    assert plinux.simulate({"installer": "apt", "package": "openssl"}, None)["predicted"]["noop"]
    monkeypatch.setattr(plinux, "run", lambda cmd, timeout=0, **k: Result(0, "Inst openssl [1] (2 x)\nRemv libfoo [1]\n"))
    assert any(c["id"] == "removals" and c["status"] == "block" for c in plinux.simulate({"installer": "apt", "package": "openssl"}, None)["checks"])
    monkeypatch.setattr(plinux, "run", lambda cmd, timeout=0, **k: Result(100, "openssl.x86_64  3.0.7-27.el9  baseos\n"))
    monkeypatch.setattr(plinux, "_manager", lambda: "dnf")
    assert plinux.simulate({"installer": "dnf", "package": "openssl"}, None)["predicted"]["version_after"] == "3.0.7-27.el9"
    monkeypatch.setattr(plinux, "installed_version", lambda p: "")
    assert plinux.simulate({"installer": "dnf", "package": "openssl"}, None)["predicted"]["noop"]


def test_common_checks_disk_privileges_and_failure_isolation(monkeypatch):
    class U:
        free = 200 * 1024 * 1024
    monkeypatch.setattr(agent_pf.shutil, "disk_usage", lambda p: U)
    monkeypatch.setattr(agent_pf, "os_simulate", lambda p, st: {"checks": [{"id": "applicability", "label": "x", "status": "ok", "detail": ""}], "predicted": {"reboot": True}})
    monkeypatch.setattr(agent_pf, "privileges", lambda: {"id": "privileges", "label": "p", "status": "block", "detail": "sem root"})
    monkeypatch.setattr(agent_pf, "pending_reboot", lambda: {"id": "pending_reboot", "label": "r", "status": "warn", "detail": ""})
    monkeypatch.setattr(agent_pf.health, "failed_units", lambda: 0)
    r = agent_pf.run_simulation(None, {"installer": "apt", "package": "openssl", "size_bytes": 50 * 1024 * 1024, "reboot_policy": "none"})
    st = {c["id"]: c["status"] for c in r["checks"]}
    assert st["disk_space"] == "block" and st["privileges"] == "block" and st["reboot_prediction"] == "warn" and r["status"] == "succeeded"
    # falhas do simulador não rebentam: viram bloqueio
    monkeypatch.setattr(agent_pf, "os_simulate", lambda p, st: (_ for _ in ()).throw(RuntimeError("sem rede")))
    r = agent_pf.run_simulation(None, {"installer": "msi", "patch_id": 1})
    assert any(c["id"] == "applicability" and c["status"] == "block" and "sem rede" in c["detail"] for c in r["checks"])


# ------------------------------------------------------------------ servidor: origens, classificação, portão da campanha


def test_server_source_checks(app, tenant):
    w = make_asset(tenant, "pc1", software=(), os_family="windows", ip="10.0.0.9")
    w.hardware = json.dumps({"capabilities": win_caps()})
    assert sources.check(w, "winget")[0] and sources.check(w, "wua")[0]
    ok, why = sources.check(w, "choco")
    assert not ok and "Chocolatey" in why
    assert not sources.check(w, "office_c2r")[0] and not sources.check(w, "apt")[0]       # apt não existe em Windows
    assert sources.check(make_asset(tenant, "pc2", software=(), os_family="windows", ip="10.0.0.10"), "choco") == (True, "capacidades do equipamento ainda desconhecidas")
    m = {x["id"]: x for x in sources.matrix([w])}
    assert m["winget"]["available"] == 1 and m["choco"]["available"] == 0 and m["wua"]["known"] == 1
    assert {a["app"] for a in sources.APP_CATALOG} >= {"Google Chrome", "Mozilla Firefox", "Zoom", "SAP GUI"}


def test_classification_and_blocks_without_agent(app, tenant):
    c = lambda s: [{"id": "x", "label": "x", "status": s, "detail": ""}]  # noqa: E731
    assert preflight.classify(c("ok"), {}) == "ready" and preflight.classify(c("warn"), {}) == "warning"
    assert preflight.classify(c("warn") + c("block"), {}) == "blocked" and preflight.classify(c("ok"), {"noop": True}) == "noop"
    w = make_asset(tenant, "pc1", software=(), os_family="windows", ip="10.0.0.9")
    w.hardware = json.dumps({"capabilities": win_caps()})
    p = Patch(tenant_id=tenant.id, patch_uid="firefox-msi", installer="msi", status="approved")        # sem ficheiro no repositório
    db.session.add(p)
    db.session.flush()
    pf = preflight.start(tenant, p, w)
    assert pf.outcome == "blocked" and Task.query.filter_by(type="simulate").count() == 0
    assert any(x["id"] == "repository_file" and x["status"] == "block" for x in pf.check_list)
    p2 = Patch(tenant_id=tenant.id, patch_uid="choco-x", installer="choco", package_name="vlc", status="approved")
    db.session.add(p2); db.session.flush()
    assert preflight.start(tenant, p2, w).outcome == "blocked"                        # origem indisponível (sem Chocolatey)
    p3 = Patch(tenant_id=tenant.id, patch_uid="wi", installer="winget", package_name="Mozilla.Firefox", status="approved")
    db.session.add(p3); db.session.flush()
    nag = preflight.start(tenant, p3, w)
    assert nag.outcome == "blocked" and any(x["id"] == "agent" for x in nag.check_list)  # sem agente nem Ansible


def agent_asset(app, token, name, caps=None, os_family="windows"):
    ag = FakeAgent(app, token, name, os_family=os_family, software=())
    ag.inventory()
    a = Asset.query.filter_by(name=name).one()
    if caps:
        a.hardware = json.dumps({**a.hw, "capabilities": caps})
    db.session.commit()
    return ag, a


def test_simulation_roundtrip_outcomes(app, tenant, enroll_token):
    ag, a = agent_asset(app, enroll_token, "pc1", win_caps())
    p = Patch(tenant_id=tenant.id, patch_uid="KB5031234", installer="wua", status="approved", cves='["CVE-2026-0001"]')
    db.session.add(p); db.session.commit()
    pf = preflight.start(tenant, p, a)
    db.session.commit()
    assert pf.outcome == "pending" and Task.query.filter_by(type="simulate").count() == 1
    task = db.session.get(Task, pf.task_id)
    assert task.payload_data["installer"] == "wua" and task.payload_data["preflight_id"] == pf.id
    (t,) = ag.poll()
    assert t["type"] == "simulate"
    ag.result(t["id"], {"status": "succeeded", "checks": [{"id": "applicability", "label": "WUA", "status": "ok", "detail": "KB5031234"},
                                                         {"id": "pending_reboot", "label": "Reinício", "status": "warn", "detail": "pendente"}],
                        "predicted": {"reboot": True, "download_mb": 600}})
    db.session.expire_all()
    pf = db.session.get(Preflight, pf.id)
    assert pf.outcome == "warning" and pf.finished_at and pf.predicted_data["download_mb"] == 600
    assert {c["id"] for c in pf.check_list} >= {"source", "patch_intelligence", "applicability", "pending_reboot"}
    # agente falha por completo → erro
    pf2 = preflight.start(tenant, p, a); db.session.commit()
    (t2,) = ag.poll()
    ag.result(t2["id"], {"status": "failed", "output": "boom"})
    db.session.expire_all()
    assert db.session.get(Preflight, pf2.id).outcome == "error"
    assert preflight.latest(p.id, a.id).id == pf2.id


def test_campaign_requires_preflight_blocked_and_noop_are_skipped(app, tenant, enroll_token):
    setup_vuln(tenant)
    good = FakeAgent(app, enroll_token, "good1"); bad = FakeAgent(app, enroll_token, "bad1"); done = FakeAgent(app, enroll_token, "done1")
    for ag in (good, bad, done):
        ag.inventory()
    Asset.query.filter(Asset.name.in_(["good1", "bad1", "done1"])).update({"ring": 4}, synchronize_session=False)
    patch = Exposure.query.first().patch
    patch.status = "approved"
    db.session.commit()
    c = deploy.create_campaign(tenant, patch, "pf", {"cve_id": "CVE-2026-0001"}, use_rings=False, require_preflight=True)
    db.session.commit()
    w = Worker(app); w.tick(); db.session.commit()
    tasks = {t.asset.name: t for t in Task.query.filter_by(campaign_id=c.id, type="patch")}
    assert {t.status for t in tasks.values()} == {"pending"} and Task.query.filter_by(type="simulate").count() == 3
    # o agente executa as simulações: good → ok; bad → bloqueio; done → nada a instalar
    for ag, checks, pred in ((good, [{"id": "applicability", "label": "a", "status": "ok", "detail": ""}], {"version_after": "1.1.1w"}),
                             (bad, [{"id": "disk_space", "label": "Espaço em disco", "status": "block", "detail": "Livre 0.1 GB"}], {}),
                             (done, [{"id": "applicability", "label": "a", "status": "info", "detail": "já"}], {"noop": True})):
        pend = [t for t in Task.query.filter_by(type="simulate", asset_id=Agent.query.filter_by(hostname=ag_host(ag)).one().asset_id)]
        for t in pend:
            if t.status in ("queued", "sent"):
                t.status = "sent"
                db.session.commit()
                ag.result(t.id, {"status": "succeeded", "checks": checks, "predicted": pred})
    db.session.expire_all()
    w.tick(); db.session.commit()
    tasks = {t.asset.name: t for t in Task.query.filter_by(campaign_id=c.id, type="patch")}
    assert tasks["good1"].status == "queued"
    assert tasks["bad1"].status == "skipped" and tasks["bad1"].output.startswith("Bloqueado pela simulação prévia") and "Espaço em disco" in tasks["bad1"].output
    assert tasks["done1"].status == "skipped" and "Já aplicado" in tasks["done1"].output
    assert bad.poll() == []                                                                       # só o ativo aprovado recebe a instalação
    assert preflight.summary(c.id) == {"pending": 0, "ready": 0, "warning": 1, "blocked": 1, "noop": 1, "error": 0}
    # o patch só instala nos ativos que passaram; o Ring avalia só esses
    good.work()
    w.tick(); db.session.commit()
    assert c.status == "completed"


def ag_host(ag):
    return next(a.hostname for a in Agent.query.all() if a.key_hash == hashlib.sha256(ag.key.encode()).hexdigest())


def test_ring_with_only_noop_promotes_but_all_blocked_holds(app, tenant, enroll_token):
    setup_vuln(tenant)
    lab = FakeAgent(app, enroll_token, "lab1"); prod = FakeAgent(app, enroll_token, "prod1")
    Asset.query.filter_by(name="lab1").one().ring = 0
    lab.inventory(); prod.inventory()
    patch = Exposure.query.first().patch; patch.status = "approved"; db.session.commit()
    c = deploy.create_campaign(tenant, patch, "x", {"cve_id": "CVE-2026-0001"}, require_preflight=True); db.session.commit()
    w = Worker(app); w.tick(); db.session.commit()
    lab_asset = Asset.query.filter_by(name="lab1").one()
    pf = Preflight.query.filter_by(asset_id=lab_asset.id).one()
    t = db.session.get(Task, pf.task_id); t.status = "sent"; db.session.commit()
    lab.result(t.id, {"status": "succeeded", "checks": [{"id": "d", "label": "Disco", "status": "block", "detail": "cheio"}], "predicted": {}})
    w.tick(); db.session.commit()
    assert c.status == "paused" and "bloqueados pela simulação prévia" in json.dumps(c.rings_state, ensure_ascii=False)
    assert prod.poll() == [] or all(x["type"] == "simulate" for x in prod.poll())             # nada chega à produção


# ------------------------------------------------------------------ staging e execução real no agente (Linux)


def test_staging_downloads_once_verifies_hash_and_is_reused_by_install(app, tenant, enroll_token, tmp_path, monkeypatch):
    monkeypatch.setenv("OMXPATCH_AGENT_DIR", str(tmp_path / "ag"))
    ag = FakeAgent(app, enroll_token, "pc1")
    a = Asset.query.filter_by(name="pc1").one()
    data = b"MSI-CONTENT" * 1000
    p = Patch(tenant_id=tenant.id, patch_uid="app-msi", installer="msi", status="approved", sha256=hashlib.sha256(data).hexdigest())
    db.session.add(p); db.session.flush()
    patches.store_file(p, tenant, data, "app.msi")
    t = Task(tenant_id=tenant.id, type="simulate", asset_id=a.id, patch_id=p.id, status="sent", payload="{}")
    db.session.add(t); db.session.commit()

    class S:                      # sessão do cliente do agente → servidor Flask real
        def __init__(self, c, h): self.c, self.h = c, h

        def download(self, url, dest, headers=None, bandwidth_kbps=0, timeout=0):
            r = self.c.get("/" + url.split("//", 1)[1].split("/", 1)[1], headers=self.h)
            if r.status_code != 200:
                return r.status_code, ""
            open(dest, "wb").write(r.data)
            return 200, hashlib.sha256(r.data).hexdigest()

    from omxpatch_agent.client import Client
    cl = Client({"server_url": "https://x"}, session=S(ag.c, ag.h))
    pp = {"patch_id": p.id, "sha256": p.sha256, "has_file": True}
    f = staging.stage(cl, pp, ".msi")
    assert open(f, "rb").read() == data and staging.valid_staged(pp, ".msi")
    calls = []
    cl.s.download = lambda *a, **k: calls.append(a) or (200, "")                               # 2.ª vez: não descarrega
    assert staging.stage(cl, pp, ".msi") == f and calls == []
    open(f, "ab").write(b"adulterado")
    assert staging.valid_staged(pp, ".msi") is None                                             # adulterado: rejeitado
    with pytest.raises(RuntimeError):
        staging.stage(cl, {**pp, "has_file": False}, ".msi")
    bad = Client({"server_url": "https://x"}, session=S(ag.c, {"Authorization": "Bearer omxa_x"}))
    with pytest.raises(Exception):
        staging.stage(bad, {"patch_id": p.id, "sha256": "0" * 64, "has_file": True}, ".exe")


@pytest.mark.skipif(platform.system() != "Linux", reason="usa o apt/dnf deste Linux")
def test_real_agent_simulation_on_this_linux_host(app, tenant, enroll_token, tmp_path, monkeypatch):
    """Simulação real (apt-get -s / dnf check-update) do pacote openssl, executada pelo agente através do servidor."""
    import shutil
    if not (shutil.which("dpkg-query") and shutil.which("apt-get")):
        pytest.skip("requer Debian/Ubuntu")
    monkeypatch.setenv("OMXPATCH_AGENT_DIR", str(tmp_path / "ag"))
    from omxpatch_agent import cli as agent_cli, executor
    from omxpatch_agent.client import Client
    from tests.test_agent import FlaskSession
    sess = FlaskSession(app)
    cfg = {"server_url": "https://x"}
    from omxpatch.web.api import new_enrollment_token
    raw, _ = new_enrollment_token(tenant, "t"); db.session.commit()
    data = Client(cfg, session=sess).enroll(raw, {"hostname": "real1", "os_family": "linux", "machine_id": "m-real"})
    cl = Client({**cfg, "agent_key": data["agent_key"]}, session=sess)
    a = Asset.query.filter_by(name="real1").one()
    p = Patch(tenant_id=tenant.id, patch_uid="apt:openssl", installer="apt", package_name="openssl", status="approved")
    db.session.add(p); db.session.flush()
    pf = preflight.start(tenant, p, a); db.session.commit()
    agent_cli.cycle(cl, {"last_inventory": 9e12})
    db.session.expire_all()
    pf = db.session.get(Preflight, pf.id)
    ids = {c["id"]: c for c in pf.check_list}
    assert pf.outcome in ("ready", "warning", "noop", "blocked") and pf.outcome != "pending"
    assert {"privileges", "disk_space", "health", "applicability"} <= set(ids), list(ids)
    assert "Simulação (apt-get -s)" in ids["applicability"]["label"] or "instalado" in ids["applicability"]["label"].lower()


# ------------------------------------------------------------------ interface e API


def test_ui_and_api_for_simulation_and_sources(app, tenant, enroll_token):
    from tests.conftest import login_as
    setup_vuln(tenant)
    ag = FakeAgent(app, enroll_token, "web01"); ag.inventory()
    a = Asset.query.filter_by(name="web01").one()
    a.os_family = "windows"
    a.hardware = json.dumps({"capabilities": win_caps()})
    patch = Exposure.query.first().patch
    db.session.commit()
    c = login_as(app, "admin@alpha.example")
    r = c.post(f"/patches/{patch.id}/simulate", {"cve_id": "CVE-2026-0001"})
    assert r.status_code == 302 and Preflight.query.count() >= 0
    for url in ("/preflights", "/sources", f"/patches/{patch.id}", f"/assets/{a.id}"):
        assert c.get(url).status_code == 200, url
    html = c.get("/sources").get_data(as_text=True)
    assert "Windows Update / WSUS" in html and "Google Chrome" in html and "Chocolatey" in html
    assert "Origens de atualização" in c.get(f"/assets/{a.id}").get_data(as_text=True)
    pf = Preflight.query.first()
    if pf:
        assert c.get(f"/preflights/{pf.id}").status_code == 200
        assert c.post(f"/preflights/{pf.id}/rerun").status_code == 302
    assert "Simulação prévia" in c.get(f"/patches/{patch.id}").get_data(as_text=True)
    assert "Exigir simulação prévia" in c.get(f"/campaigns/new?patch_id={patch.id}").get_data(as_text=True)
    from tests.test_web import _api_token
    h = {"Authorization": f"Bearer {_api_token(c)}"}
    cl = app.test_client()
    assert cl.get("/api/v1/sources", headers=h).get_json()["windows"][0]["id"] == "wua"
    r = cl.post(f"/api/v1/patches/{patch.id}/simulate", headers=h, json={"scope": {"asset_ids": [a.id], "os_family": "windows"}})
    assert r.status_code == 202 and r.get_json()
    assert cl.get("/api/v1/preflights", headers=h).get_json()[0]["checks"]
    # perfis e isolamento
    assert login_as(app, "auditor@alpha.example").post(f"/patches/{patch.id}/simulate", {}).status_code == 403
    beta = login_as(app, "admin@beta.example")
    assert beta.get(f"/preflights/{Preflight.query.first().id}").status_code == 404
