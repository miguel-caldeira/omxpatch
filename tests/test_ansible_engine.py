"""Motor Ansible sem agente: atualização completa, CyberArk (ordem e pré-condições) e avaliação de rede."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from omxpatch.engine import ansible_engine as eng, ansible_runner, netassess
from omxpatch.extensions import db
from omxpatch.models import AnsibleCredential, Asset, AvailableUpdate, NetBaseline, NetworkAssessment, Task, Tenant, utcnow

ANS = Path(__file__).resolve().parents[1] / "ansible"


def mk(tenant, name, **kw):
    a = Asset(tenant_id=tenant.id, uid=name.lower(), name=name, connection="ansible", managed=True, **kw)
    db.session.add(a)
    db.session.flush()
    return a


# --------------------------------------------------------------------------- inventário e credenciais


def test_inventory_groups_and_credentials(app, tenant):
    from omxpatch.connectors import store
    with app.app_context():
        c1 = AnsibleCredential(tenant_id=tenant.id, name="ssh", kind="ssh_key", username="ops", secret=store.encrypt_json({"ssh_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"}))
        c2 = AnsibleCredential(tenant_id=tenant.id, name="fgt", kind="api_token", secret=store.encrypt_json({"api_token": "tok-123"}))
        c3 = AnsibleCredential(tenant_id=tenant.id, name="win", kind="password", username="svc", secret=store.encrypt_json({"password": "pw"}))
        db.session.add_all([c1, c2, c3])
        db.session.flush()
        assets = [mk(tenant, "lin1", os_family="linux", ip="10.0.0.1", credential_id=c1.id), mk(tenant, "fw1", platform="fortios", ip="10.0.0.2", credential_id=c2.id),
                  mk(tenant, "sw1", platform="cisco_ios", ip="10.0.0.3"), mk(tenant, "vault1", os_family="windows", cyberark_role="vault", ip="10.0.0.4", credential_id=c3.id),
                  mk(tenant, "psmp1", os_family="linux", cyberark_role="psmp", ip="10.0.0.5")]
        inv = eng.build_inventory(assets)
        h = inv["all"]["hosts"]
        assert "__ssh_key__" in h[f"asset{assets[0].id}"] and h[f"asset{assets[0].id}"]["ansible_user"] == "ops"
        assert h[f"asset{assets[1].id}"]["omx_api_token"] == "tok-123" and h[f"asset{assets[1].id}"]["ansible_connection"] == "local"
        assert h[f"asset{assets[2].id}"]["ansible_network_os"] == "cisco.ios.ios"
        assert h[f"asset{assets[3].id}"]["ansible_password"] == "pw" and h[f"asset{assets[3].id}"]["ansible_connection"] == "winrm"
        assert h[f"asset{assets[3].id}"]["omx_component"] == "vault"
        assert set(inv) >= {"net_fortios", "net_cisco_ios", "cyberark_vault", "cyberark_psmp", "linux", "windows"}
        # credencial de outro tenant nunca é usada
        other = Tenant.query.filter(Tenant.id != tenant.id).first()
        foreign = AnsibleCredential(tenant_id=other.id, name="x", kind="password", secret=store.encrypt_json({"password": "z"}))
        db.session.add(foreign)
        db.session.flush()
        bad = mk(tenant, "lin2", os_family="linux", credential_id=foreign.id)
        with pytest.raises(eng.EngineError):
            eng.build_inventory([bad])


def test_ssh_key_goes_to_0600_file_not_command_line(tmp_path):
    inv = {"all": {"hosts": {"asset1": {"__ssh_key__": "-----BEGIN X PRIVATE KEY-----\nk\n-----END X PRIVATE KEY-----"}}}}
    out = ansible_runner._materialize_keys(inv, tmp_path)
    f = Path(out["all"]["hosts"]["asset1"]["ansible_ssh_private_key_file"])
    assert f.read_text().startswith("-----BEGIN") and oct(f.stat().st_mode & 0o777) == "0o600" and "__ssh_key__" not in out["all"]["hosts"]["asset1"]


# --------------------------------------------------------------------------- fluxo avaliar → OK → aplicar


def test_apply_requires_fresh_assessment_and_ok(app, tenant):
    with app.app_context():
        a = mk(tenant, "srv1", os_family="linux")
        db.session.commit()
        with pytest.raises(eng.EngineError, match="OK explícito"):
            eng.create_job(tenant, None, "os", [a.id], "apply", {})
        with pytest.raises(eng.EngineError, match="avaliação"):
            eng.create_job(tenant, None, "os", [a.id], "apply", {"confirm_ok": True})
        (t,) = eng.create_job(tenant, None, "os", [a.id], "assess", {})
        assert t.type == "os_update" and t.mode == "ansible" and t.payload_data["omx_scope"] == "os"
        t.status, t.finished_at = "succeeded", utcnow()
        db.session.commit()
        (ap,) = eng.create_job(tenant, None, "os", [a.id], "apply", {"confirm_ok": True, "reboot_policy": "never"})
        assert ap.payload_data["mode"] == "apply" and ap.payload_data["reboot_policy"] == "never"
        # avaliação com mais de 24 h já não serve
        t.finished_at = utcnow().replace(year=utcnow().year - 1)
        db.session.commit()
        with pytest.raises(eng.EngineError, match="avaliação"):
            eng.create_job(tenant, None, "os", [a.id], "apply", {"confirm_ok": True})


def test_asset_must_be_ansible_and_right_kind(app, tenant):
    with app.app_context():
        agent_asset = Asset(tenant_id=tenant.id, uid="ag1", name="ag1", connection="agent", os_family="linux")
        db.session.add(agent_asset)
        net = mk(tenant, "fw9", platform="panos")
        lin = mk(tenant, "lin9", os_family="linux")
        db.session.commit()
        with pytest.raises(eng.EngineError):
            eng.create_job(tenant, None, "os", [agent_asset.id], "assess", {})
        with pytest.raises(eng.EngineError):
            eng.create_job(tenant, None, "network", [lin.id], "assess", {})
        with pytest.raises(eng.EngineError):
            eng.create_job(tenant, None, "os", [net.id], "assess", {})
        with pytest.raises(eng.EngineError, match="só admitem avaliação"):
            eng.create_job(tenant, None, "network", [net.id], "apply", {"confirm_ok": True})


def test_cyberark_order_confirmation_and_stages(app, tenant):
    with app.app_context():
        ids = {r: mk(tenant, f"cy-{r}", os_family="linux" if r == "psmp" else "windows", cyberark_role=r).id for r in ("psmp", "cpm", "vault", "psm")}
        db.session.commit()
        for r, i in ids.items():                                              # avaliação prévia de cada componente
            (t,) = eng.create_job(tenant, None, "cyberark", [i], "assess", {})
            t.status, t.finished_at = "succeeded", utcnow()
        db.session.commit()
        opts = {"confirm_ok": True, "target_version": "14.2", "media_src": "/srv/cyber/pkg.zip", "media_sha256": "a" * 64, "upgrade_cmd": "setup.exe /s"}
        with pytest.raises(eng.EngineError, match="ATUALIZAR"):
            eng.create_job(tenant, None, "cyberark", list(ids.values()), "apply", opts)
        with pytest.raises(eng.EngineError, match="SHA-256"):
            eng.create_job(tenant, None, "cyberark", list(ids.values()), "apply", {**opts, "confirm_word": "ATUALIZAR", "media_sha256": "zz"})
        with pytest.raises(eng.EngineError, match="caminho"):
            eng.create_job(tenant, None, "cyberark", list(ids.values()), "apply", {**opts, "confirm_word": "ATUALIZAR", "media_src": "../x"})
        tasks = eng.create_job(tenant, None, "cyberark", list(ids.values()), "apply", {**opts, "confirm_word": "ATUALIZAR"})
        order = [db.session.get(Asset, t.asset_id).cyberark_role for t in tasks]
        assert order == ["vault", "cpm", "psm", "psmp"]                       # ordem do fabricante, independentemente da seleção
        assert [t.status for t in tasks] == ["queued", "waiting_dep", "waiting_dep", "waiting_dep"]
        assert tasks[1].payload_data["after"] == [tasks[0].id] and tasks[2].payload_data["after"] == [tasks[1].id]
        db.session.commit()
        assert eng.release_stages(tenant) == 0
        tasks[0].status = "succeeded"
        assert eng.release_stages(tenant) == 1 and tasks[1].status == "queued"
        tasks[1].status = "failed"
        eng.release_stages(tenant)
        assert tasks[2].status == "cancelled" and "falhou" in tasks[2].output
        eng.release_stages(tenant)
        assert tasks[3].status == "waiting_dep" or tasks[3].status == "cancelled"


def test_os_assess_result_feeds_available_updates(app, tenant):
    with app.app_context():
        a = mk(tenant, "srv2", os_family="linux")
        (t,) = eng.create_job(tenant, None, "all", [a.id], "assess", {})
        report = {"status": "succeeded", "pending": [{"name": "openssl", "current_version": "3.0.1", "new_version": "3.0.13", "source": "apt", "security": True},
                                                      {"name": "KB5034441", "kb": "KB5034441", "new_version": "x", "source": "wua", "severity": "critical", "reboot": True}]}
        from omxpatch.engine import deploy
        deploy.complete_task(t, report)
        db.session.commit()
        rows = {u.uid: u for u in AvailableUpdate.query.filter_by(asset_id=a.id)}
        assert set(rows) == {"openssl", "KB5034441"} and rows["openssl"].category == "security" and rows["KB5034441"].severity == "critical"


# --------------------------------------------------------------------------- avaliação de rede


FGT_STATUS = json.dumps({"http_method": "GET", "results": {"model_name": "FortiGate", "model_number": "60F", "model": "FGT", "hostname": "fgt-hq"}, "version": "v7.2.5", "serial": "FGT60FTK1"})
FGT_FW = json.dumps({"results": {"current": {"version": "v7.2.5"}, "available": [{"version": "v7.2.8"}, {"version": "v7.4.3"}, {"version": "v7.0.14"}]}})
PAN_INFO = "<response status='success'><result><system><hostname>pa-1</hostname><model>PA-440</model><serial>0123</serial><sw-version>10.2.4-h4</sw-version></system></result></response>"
PAN_SW = ("<response status='success'><result><sw-updates><versions><entry><version>10.2.9</version><downloaded>no</downloaded></entry>"
          "<entry><version>10.2.4-h4</version><downloaded>yes</downloaded></entry><entry><version>11.1.2</version><downloaded>no</downloaded></entry></versions></sw-updates></result></response>")
CP = "Product version Check Point Gaia R81.20\nOS build 631\nOS kernel version 3.10.0-1160.15.2cpx86_64\nOS edition 64-bit\n"
IOS = "Cisco IOS XE Software, Version 17.03.05\nsw1 uptime is 3 weeks\nModel Number : C9300-48P\nSystem Serial Number : FCW1234\n"
IOS_OLD = "Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), Version 12.2(55)SE12, RELEASE SOFTWARE (fc1)\ncisco WS-C3750-48P (PowerPC405) processor\n"
NXOS = "Cisco Nexus Operating System (NX-OS) Software\n  NXOS: version 9.3(8)\n  cisco Nexus9000 C93180YC-FX Chassis\n  Device name: n9k\n"
JUNOS = "Hostname: ex1\nModel: ex4300-48t\nJunos: 20.4R3-S2.6\n"
EOS = "Arista DCS-7050TX-64-F\nSerial number: JPE1\nSoftware image version: 4.28.3M\n"


def test_parsers_for_every_platform():
    f = netassess.parse_fortios({"status": FGT_STATUS, "firmware": FGT_FW})
    assert f["version"] == "7.2.5" and f["model"] == "FortiGate 60F" and "7.4.3" in f["available"]
    p = netassess.parse_panos({"info": PAN_INFO, "software": PAN_SW})
    assert p["version"] == "10.2.4-h4" and p["model"] == "PA-440" and p["available"] == ["10.2.9", "10.2.4-h4", "11.1.2"]
    assert netassess.parse_checkpoint({"version": CP})["version"] == "R81.20"
    assert netassess.parse_cisco_ios({"version": IOS})["version"] == "17.03.05" and netassess.parse_cisco_ios({"version": IOS})["model"] == "C9300-48P"
    assert netassess.parse_cisco_ios({"version": IOS_OLD})["version"] == "12.2(55)SE12"
    assert netassess.parse_cisco_nxos({"version": NXOS})["version"] == "9.3(8)"
    assert netassess.parse_junos({"version": JUNOS})["version"] == "20.4R3-S2.6" and netassess.parse_junos({"version": JUNOS})["model"] == "ex4300-48t"
    assert netassess.parse_eos({"version": EOS})["version"] == "4.28.3M"
    assert netassess.parse_panos({"info": "<!DOCTYPE x [<!ENTITY a 'b'>]><r/>"})["version"] == ""          # XML com DOCTYPE/ENTIDADES é recusado
    assert netassess.parse_fortios({"status": "isto não é json"})["version"] == ""
    # o Ansible antigo entrega o JSON já convertido em dicionário: tem de dar o mesmo resultado
    assert netassess.parse_fortios({"status": json.loads(FGT_STATUS), "firmware": json.loads(FGT_FW)}) == f


def test_evaluation_with_vendor_versions_and_policy(app, tenant):
    with app.app_context():
        facts = netassess.parse_fortios({"status": FGT_STATUS, "firmware": FGT_FW})
        ev = netassess.evaluate(tenant.id, "fortios", facts)
        assert ev["verdict"] == "update" and ev["recommended"] == "7.2.8"          # mesma linha primeiro
        db.session.add_all([NetBaseline(tenant_id=tenant.id, platform="fortios", model_glob="FortiGate*", min_version="7.2.6", recommended="7.2.8", eol_below="7.0"),
                            NetBaseline(tenant_id=tenant.id, platform="cisco_ios", model_glob="*", min_version="17.9", eol_below="15.0")])
        db.session.commit()
        assert netassess.evaluate(tenant.id, "fortios", facts)["verdict"] == "below_min"
        old = netassess.parse_cisco_ios({"version": IOS_OLD})
        assert netassess.evaluate(tenant.id, "cisco_ios", old)["verdict"] == "eol"
        new = netassess.parse_cisco_ios({"version": IOS})
        assert netassess.evaluate(tenant.id, "cisco_ios", new)["verdict"] == "below_min"
        assert netassess.evaluate(tenant.id, "junos", netassess.parse_junos({"version": JUNOS}))["verdict"] == "unknown"      # sem política nem versões: indeterminado
        assert netassess.evaluate(tenant.id, "eos", {"version": ""})["verdict"] == "unknown"


def test_network_result_is_stored_and_asset_updated(app, tenant):
    with app.app_context():
        fw = mk(tenant, "fgt1", platform="fortios", ip="10.9.9.9")
        (t,) = eng.create_job(tenant, None, "network", [fw.id], "assess", {})
        from omxpatch.engine import deploy
        deploy.complete_task(t, {"status": "succeeded", "platform": "fortios", "raw": {"status": FGT_STATUS, "firmware": FGT_FW}})
        db.session.commit()
        row = NetworkAssessment.query.filter_by(asset_id=fw.id).one()
        assert row.version == "7.2.5" and row.verdict == "update" and row.recommended == "7.2.8" and db.session.get(Asset, fw.id).os_version == "7.2.5"
        deploy.complete_task(t, {"status": "failed"}) if False else None


# --------------------------------------------------------------------------- consola


def test_console_pages_and_permissions(app, alpha_admin, alpha_user, tenant):
    with app.app_context():
        lin = mk(tenant, "web-lin", os_family="linux")
        db.session.commit()
        lid = lin.id
    assert alpha_admin.get("/ansible").status_code == 200 and alpha_admin.get("/network").status_code == 200
    assert alpha_admin.get("/ansible/credentials").status_code == 200
    assert alpha_user.get("/ansible/credentials").status_code == 403
    r = alpha_admin.post("/ansible/credentials", {"name": "svc", "kind": "password", "username": "u", "password": "S3gredo-Forte!"})
    assert r.status_code == 302
    page = alpha_admin.get("/ansible/credentials").data.decode()
    assert "svc" in page and "S3gredo-Forte!" not in page
    with app.app_context():
        c = AnsibleCredential.query.filter_by(name="svc").one()
        assert "S3gredo" not in c.secret                                     # cifrado em repouso
        from omxpatch.models import AuditLog
        assert not [a for a in AuditLog.query.all() if "S3gredo" in (a.detail or "")]
    assert alpha_admin.post("/ansible/credentials", {"name": "k", "kind": "ssh_key", "ssh_key": "lixo"}).status_code == 302
    assert alpha_admin.post("/ansible/run", {"op": "os", "mode": "assess", "asset_ids": str(lid)}).status_code == 302
    with app.app_context():
        assert Task.query.filter_by(type="os_update", asset_id=lid).count() == 1
    assert alpha_user.post("/ansible/run", {"op": "os", "mode": "apply", "asset_ids": str(lid), "confirm_ok": "on"}).status_code == 403
    tid = None
    with app.app_context():
        tid = Task.query.filter_by(type="os_update", asset_id=lid).one().id
    assert alpha_admin.get(f"/ansible/jobs/{tid}").status_code == 200
    assert alpha_admin.post("/network/baseline", {"platform": "fortios", "model_glob": "*", "min_version": "7.2.6"}).status_code == 302
    assert b"7.2.6" in alpha_admin.get("/network").data
    assert alpha_admin.post("/network/baseline", {"platform": "nope"}).status_code == 400


def test_output_scrubs_secrets():
    assert "hunter2" not in eng._scrub('"ansible_password": "hunter2" api_token=abc123 password: hunter2')


# --------------------------------------------------------------------------- playbooks


PLAYBOOKS = ["update_linux.yml", "update_windows.yml", "update_macos.yml", "cyberark_upgrade.yml", "net_assess.yml"]


@pytest.mark.parametrize("name", PLAYBOOKS + ["tasks/cyberark_windows.yml", "tasks/cyberark_psmp.yml", "group_vars/cyberark.yml"])
def test_playbooks_are_valid_yaml(name):
    assert yaml.safe_load((ANS / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", ["update_linux.yml", "update_windows.yml", "update_macos.yml", "tasks/cyberark_windows.yml", "tasks/cyberark_psmp.yml", "net_assess.yml"])
def test_playbooks_report_a_result_and_keep_secrets_quiet(name):
    text = (ANS / name).read_text(encoding="utf-8")
    assert "OMXPATCH_RESULT=" in text
    if name == "net_assess.yml":
        assert text.count("no_log: true") >= 5                               # chamadas com token nunca vão para o registo


def _stub_collections(tmp: Path) -> str:
    """Módulos de colecções que não estão instaladas (a Galaxy pode estar inacessível): ficheiros vazios chegam ao --syntax-check."""
    import re
    mods = set()
    for f in ANS.rglob("*.yml"):
        mods |= set(re.findall(r"\b((?:ansible\.windows|community\.windows|community\.general|ansible\.netcommon|ansible\.posix)\.\w+)\b", f.read_text(encoding="utf-8")))
    for m in mods:
        ns, coll, name = m.split(".")
        d = tmp / "ansible_collections" / ns / coll / "plugins" / "modules"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{name}.py").write_text("DOCUMENTATION = 'module: %s\\nshort_description: stub\\noptions: {}'\\n" % name)
        for up in (tmp / "ansible_collections" / ns / coll, tmp / "ansible_collections" / ns):
            (up / "__init__.py").touch()
        (tmp / "ansible_collections" / ns / coll / "galaxy.yml").write_text(f"namespace: {ns}\nname: {coll}\nversion: 1.0.0\n")
    return str(tmp)


@pytest.mark.skipif(not (shutil.which("ansible-playbook") or Path("/tmp/venv/bin/ansible-playbook").exists()), reason="ansible-core não instalado")
@pytest.mark.parametrize("name", PLAYBOOKS)
def test_playbooks_syntax_check(name, tmp_path):
    exe = shutil.which("ansible-playbook") or "/tmp/venv/bin/ansible-playbook"
    inv = tmp_path / "inv.ini"
    inv.write_text("[linux]\nl1\n[windows]\nw1\n[macos]\nm1\n[cyberark_vault]\nw1\n[cyberark_cpm]\nw1\n[cyberark_psm]\nw1\n[cyberark_psmp]\nl1\n"
                   "[net_checkpoint]\nn1\n[net_fortios]\nn2\n[net_panos]\nn3\n[net_cisco_ios]\nn4\n[net_cisco_nxos]\nn5\n[net_junos]\nn6\n[net_eos]\nn7\n")
    env = dict(os.environ, ANSIBLE_COLLECTIONS_PATH=_stub_collections(tmp_path / "coll"), ANSIBLE_CONFIG=str(ANS / "ansible.cfg"), ANSIBLE_LOCAL_TEMP=str(tmp_path / "tmp"),
               ANSIBLE_DEPRECATION_WARNINGS="False")
    r = subprocess.run([exe, "-i", str(inv), str(ANS / name), "--syntax-check"], capture_output=True, text=True, env=env, cwd=str(ANS), timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.skipif(not ((shutil.which("ansible-playbook") or Path("/tmp/venv/bin/ansible-playbook").exists()) and shutil.which("apt-get") and os.geteuid() == 0),
                    reason="precisa de ansible, apt e root")
def test_linux_assess_runs_for_real_on_localhost(tmp_path):
    """Avaliação real (só leitura) deste próprio equipamento: o playbook corre, devolve o resultado e o servidor lê-o."""
    exe = shutil.which("ansible-playbook") or "/tmp/venv/bin/ansible-playbook"
    inv = tmp_path / "inv.ini"
    inv.write_text("[linux]\nlocalhost ansible_connection=local\n")
    r = subprocess.run([exe, "-i", str(inv), str(ANS / "update_linux.yml"), "-e", "omx_mode=assess", "-e", "omx_scope=os"], capture_output=True, text=True,
                       env=dict(os.environ, ANSIBLE_CALLBACK_RESULT_FORMAT="json", ANSIBLE_NOCOLOR="1", ANSIBLE_DEPRECATION_WARNINGS="False"), cwd=str(ANS), timeout=280)
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]
    res = ansible_runner.parse_result(r.stdout + r.stderr)
    assert res and res["status"] == "succeeded" and res["mode"] == "assess" and isinstance(res["pending"], list) and res["pending_count"] == len(res["pending"])


def test_asset_form_ignores_foreign_credential_and_invalid_platform(app, alpha_admin, tenant):
    from omxpatch.connectors import store
    with app.app_context():
        other = Tenant.query.filter(Tenant.id != tenant.id).first()
        foreign = AnsibleCredential(tenant_id=other.id, name="alheia", kind="password", secret=store.encrypt_json({"password": "x"}))
        mine = AnsibleCredential(tenant_id=tenant.id, name="minha", kind="password", secret=store.encrypt_json({"password": "y"}))
        db.session.add_all([foreign, mine])
        db.session.commit()
        fid, mid = foreign.id, mine.id
    r = alpha_admin.post("/assets/new", {"name": "fw-form", "uid": "fw-form", "connection": "ansible", "platform": "fortios", "credential_id": str(fid), "cyberark_role": "hack"})
    assert r.status_code == 302, r.data
    r = alpha_admin.post("/assets/new", {"name": "fw-form2", "uid": "fw-form2", "connection": "ansible", "platform": "nope", "credential_id": str(mid), "cyberark_role": "cpm"})
    assert r.status_code == 302
    with app.app_context():
        a, b = Asset.query.filter_by(uid="fw-form").one(), Asset.query.filter_by(uid="fw-form2").one()
        assert a.platform == "fortios" and a.credential_id is None and not a.cyberark_role
        assert not b.platform and b.credential_id == mid and b.cyberark_role == "cpm"
