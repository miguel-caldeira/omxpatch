"""Portas 4434 (consola) / 4444 (agentes), dois certificados, isolamento por tenant dos agentes, scripts de auto-instalação, marca."""
import hashlib
import io
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import zipfile

import pytest
from werkzeug.test import Client as WClient

from omxpatch import installers, tls
from omxpatch.cli import port_guard
from omxpatch.config import load_config
from omxpatch.extensions import db
from omxpatch.models import Agent, Asset, Tenant
from omxpatch.web.api import new_enrollment_token
from tests.conftest import Client, _fresh_g, login_as


def test_defaults_ports_and_names(tmp_path):
    cfg = load_config({"DATA_DIR": str(tmp_path)})
    assert cfg["PORT"] == 4434 and cfg["AGENT_PORT"] == 4444
    assert cfg["TLS_HOSTNAME"] == "omxpatch.oramix.local" and cfg["AGENT_TLS_HOSTNAME"] == "omxpatchcli.oramix.local"
    assert cfg["BASE_URL"] == "https://omxpatch.oramix.local:4434" and cfg["AGENT_BASE_URL"] == "https://omxpatchcli.oramix.local:4444"


def test_two_self_signed_certificates_two_years(tmp_path):
    cfg = load_config({"DATA_DIR": str(tmp_path)})
    c = tls.ensure(cfg, log=lambda m: None, profile="console")
    a = tls.ensure(cfg, log=lambda m: None, profile="agent")
    assert c["dns"][0] == "omxpatch.oramix.local" and a["dns"][0] == "omxpatchcli.oramix.local"
    assert c["sha256"] != a["sha256"] and c["path"].endswith("omxpatch.crt") and a["path"].endswith("omxpatchcli.crt")
    for d in (c, a):
        assert d["self_signed"] and 728 <= d["days_left"] <= 730 and d["managed"]
    assert "omxpatchcli.oramix.local" not in c["dns"] and "omxpatch.oramix.local" not in a["dns"]
    assert os.stat(tmp_path / "tls" / "omxpatchcli.key").st_mode & 0o077 == 0 or sys.platform.startswith("win")
    assert isinstance(tls.context(cfg, "agent"), ssl.SSLContext)
    assert tls.ensure(cfg, log=lambda m: None, profile="agent")["sha256"] == a["sha256"]        # estável


def test_port_guard_isolates_console_and_agents(app):
    console, agents = WClient(port_guard(app, "console")), WClient(port_guard(app, "agent"))
    assert console.get("/login").status_code == 200 and console.post("/agent/v1/poll").status_code == 404
    assert agents.post("/agent/v1/poll").status_code == 401                      # chega ao módulo dos agentes
    assert agents.get("/login").status_code == 404 and agents.get("/").status_code == 404 and agents.get("/static/app.css").status_code == 404
    assert agents.get("/api/v1/me").status_code == 404 and agents.get("/healthz").status_code == 200
    pref = WClient(port_guard(app, "agent", "/omxpatch"))
    assert pref.post("/omxpatch/agent/v1/poll").status_code != 404 and pref.get("/omxpatch/login").status_code == 404


def test_real_servers_on_two_ports_with_two_certs(app, tmp_path):
    """Dois servidores TLS reais: cada porta apresenta o seu certificado e só serve o seu módulo."""
    from cheroot import wsgi
    from cheroot.ssl.builtin import BuiltinSSLAdapter
    import http.client, socket
    cfg = app.config
    servers, ports = [], {}
    for profile, mode in (("console", "console"), ("agent", "agent")):
        tls.ensure(cfg, log=lambda m: None, profile=profile)
        cp, kp, _ = tls.paths(cfg, profile)
        ad = BuiltinSSLAdapter(str(cp), str(kp)); ad.context = tls.context(cfg, profile)
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
        srv = wsgi.Server(("127.0.0.1", port), port_guard(app, mode), numthreads=2); srv.ssl_adapter = ad
        threading.Thread(target=srv.start, daemon=True).start()
        servers.append(srv); ports[profile] = port
    import time; time.sleep(1.0)
    try:
        pins = {}
        for profile, port in ports.items():
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=10); conn.connect()
            pins[profile] = hashlib.sha256(conn.sock.getpeercert(True)).hexdigest()
            conn.request("GET", "/login"); code = conn.getresponse().status
            assert code == (200 if profile == "console" else 404)
        want = {p: tls.info(tls.paths(cfg, p)[0])["sha256"].replace(":", "").lower() for p in ports}
        assert pins == want and pins["console"] != pins["agent"]
        # o agente (stdlib) fala com a porta de agentes pelo pin e recusa a porta errada
        from omxpatch_agent.client import StdSession
        r = StdSession(pin_sha256=want["agent"]).request("POST", f"https://127.0.0.1:{ports['agent']}/agent/v1/poll", json={})
        assert r.status_code == 401
        with pytest.raises(PinError):
            StdSession(pin_sha256=want["console"]).request("POST", f"https://127.0.0.1:{ports['agent']}/agent/v1/poll", json={})
    finally:
        for s in servers:
            s.stop()


from omxpatch_agent.client import PinError  # noqa: E402


def _enroll(app, token, host, mid, status=201):
    r = app.test_client().post("/agent/v1/enroll", json={"token": token, "hostname": host, "os_family": "linux", "machine_id": mid})
    assert r.status_code == status, r.data
    return r.get_json()


def test_machine_reports_to_one_tenant_only(app, tenant):
    beta = Tenant.query.filter_by(slug="beta").one()
    ta, _ = new_enrollment_token(tenant, "a"); tb, _ = new_enrollment_token(beta, "b")
    db.session.commit()
    r = _enroll(app, ta, "pc1", "MID-123")
    assert r["tenant"]["slug"] == "alpha"
    err = _enroll(app, tb, "pc1", "MID-123", status=409)
    assert "outra organização" in err["error"]
    assert Asset.query.filter_by(tenant_id=beta.id).count() == 0
    _enroll(app, ta, "pc1", "MID-123")                    # reinstalação na mesma organização
    _enroll(app, tb, "pc9", "MID-999")                    # outro equipamento (mesmo token beta) é aceite
    # eliminar o agente na organização A liberta o equipamento
    for ag in Agent.query.filter_by(tenant_id=tenant.id):
        db.session.delete(ag)
    db.session.commit()
    assert _enroll(app, tb, "pc1", "MID-123")["tenant"]["slug"] == "beta"


def test_bundle_requires_token_and_is_stdlib_only(app, tenant):
    c = app.test_client()
    assert c.get("/agent/v1/bundle").status_code == 401 and c.get("/agent/v1/bundle", headers={"X-Enrollment-Token": "omxe_x"}).status_code == 401
    raw, tok = new_enrollment_token(tenant, "t"); db.session.commit()
    r = c.get("/agent/v1/bundle", headers={"X-Enrollment-Token": raw})
    assert r.status_code == 200 and r.headers["X-Content-SHA256"] == hashlib.sha256(r.data).hexdigest()
    z = zipfile.ZipFile(io.BytesIO(r.data))
    names = z.namelist()
    assert "omxpatch_agent/cli.py" in names and all(n.startswith("omxpatch_agent/") for n in names)
    src = "\n".join(z.read(n).decode() for n in names if n.endswith(".py"))
    assert not re.search(r"^\s*(import|from)\s+(requests|flask|sqlalchemy|omxpatch\b)", src, re.M)
    tok.revoked = True; db.session.commit()
    assert c.get("/agent/v1/bundle", headers={"X-Enrollment-Token": raw}).status_code == 401


PIN = "AB:" * 31 + "AB"


def test_scripts_embed_tenant_token_pin_and_resist_injection():
    kw = dict(url="https://omxpatchcli.oramix.local:4444", pin=PIN, token="omxe_abcdefghijkl", tenant_name="Empresa X", host="omxpatchcli.oramix.local",
              server_ip="10.0.0.9", when="2026-11-07")
    for kind, ext in (("windows", "ps1"), ("linux", "sh"), ("macos", "sh")):
        name, body = installers.render(kind, **kw)
        assert name == f"omxpatch-install-empresa-x-{kind}.{ext}"
        assert "omxe_abcdefghijkl" in body and "omxpatchcli.oramix.local:4444" in body and ("ab" * 32) in body and "Empresa X" in body
        assert "/agent/v1/bundle" in body and "--install-service" in body and "@@" not in body
    _, ps = installers.render("windows", **kw)
    assert "#Requires -RunAsAdministrator" in ps and "python-3.12" in ps and "\r\n" in ps and "'@ | Set-Content" in ps
    _, lin = installers.render("linux", **kw)
    assert "apt-get" in lin and "/opt/omxpatch-agent" in lin and "PYEOF" in lin
    _, mac = installers.render("macos", **kw)
    assert "/Library/OMXPatchAgent" in mac and "xcode-select" in mac and "apt-get" not in mac
    for bad in ({"token": "omxe_x'; rm -rf /; '"}, {"url": "https://x'$(id)"}, {"host": "a b;c"}, {"pin": "zz"}, {"server_ip": "1.1.1.1; id"}):
        with pytest.raises(ValueError):
            installers.render("linux", **{**kw, **bad})
    with pytest.raises(ValueError):
        installers.render("solaris", **kw)
    name, body = installers.render("linux", **{**kw, "tenant_name": "A'; $(id) `x`"})
    assert "$(id)" not in body.split("\n")[1]                # nome sanitizado
    for kind in ("windows", "linux", "macos"):
        assert "Agente removido" in installers.render_uninstall(kind)[1]


def test_generated_shell_script_is_valid_sh():
    _, body = installers.render("linux", url="https://h.example:4444", pin=PIN, token="omxe_abcdefghijkl", tenant_name="T", host="h.example", server_ip="")
    r = subprocess.run(["sh", "-n"], input=body, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    _, un = installers.render_uninstall("macos")
    assert subprocess.run(["sh", "-n"], input=un, capture_output=True, text=True).returncode == 0
    # o bootstrap embutido é Python válido
    compile(installers.BOOT_PY, "boot", "exec")


def test_script_download_ui_creates_scoped_token(app, tenant):
    c = login_as(app, "admin@alpha.example")
    r = c.post("/agents/script", {"os": "linux", "ring": "1", "days": "3"})
    assert r.status_code == 200 and "attachment" in r.headers["Content-Disposition"] and r.headers["Cache-Control"] == "no-store"
    body = r.get_data(as_text=True)
    token = re.search(r"TOKEN='(omxe_[^']+)'", body).group(1)
    from omxpatch.models import EnrollmentToken
    tok = EnrollmentToken.query.filter_by(token_hash=hashlib.sha256(token.encode()).hexdigest()).one()
    assert tok.tenant_id == tenant.id and tok.ring == 1 and "Alpha" in body
    assert hashlib.sha256 and re.search(r"PIN='[0-9a-f]{64}'", body)
    assert c.post("/agents/script", {"os": "amiga"}).status_code == 400
    assert c.get("/agents/uninstall/windows").status_code == 200 and c.get("/agents/uninstall/x").status_code == 404
    # perfis: o operador não gera scripts; o auditor também não
    for who in ("user@alpha.example", "auditor@alpha.example"):
        assert login_as(app, who).post("/agents/script", {"os": "linux"}).status_code == 403
    html = c.get("/agents").get_data(as_text=True)
    assert "Scripts de auto-instalação" in html and "omxpatchcli.oramix.local:4444" in html


def test_bootstrap_script_really_installs_and_enrolls_against_live_server(app, tenant, tmp_path):
    """Executa o bootstrap embutido (Python do script) contra um servidor TLS real de agentes, com pinning, e regista o agente."""
    from cheroot import wsgi
    from cheroot.ssl.builtin import BuiltinSSLAdapter
    import socket, time
    cfg = app.config
    tls.ensure(cfg, log=lambda m: None, profile="agent")
    cp, kp, _ = tls.paths(cfg, "agent")
    ad = BuiltinSSLAdapter(str(cp), str(kp)); ad.context = tls.context(cfg, "agent")
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    srv = wsgi.Server(("127.0.0.1", port), port_guard(app, "agent"), numthreads=2); srv.ssl_adapter = ad
    threading.Thread(target=srv.start, daemon=True).start(); time.sleep(1)
    raw, _ = new_enrollment_token(tenant, "script", ring=2); db.session.commit()
    pin = tls.info(cp)["sha256"]
    dest = tmp_path / "agent"
    try:
        url = f"https://127.0.0.1:{port}"
        p = subprocess.run([sys.executable, "-c", installers.BOOT_PY, url, pin, raw, str(dest)], capture_output=True, text=True, timeout=60)
        assert p.returncode == 0, p.stderr
        assert (dest / "omxpatch_agent" / "cli.py").is_file()
        bad = subprocess.run([sys.executable, "-c", installers.BOOT_PY, url, "00" * 32, raw, str(tmp_path / "x")], capture_output=True, text=True, timeout=60)
        assert bad.returncode != 0 and "impressão digital" in bad.stderr and not (tmp_path / "x").exists()
        env = {**os.environ, "PYTHONPATH": str(dest), "OMXPATCH_AGENT_DIR": str(tmp_path / "cfg")}
        e = subprocess.run([sys.executable, "-m", "omxpatch_agent", "enroll", "--server", url, "--token", raw, "--pin-sha256", pin],
                           capture_output=True, text=True, env=env, timeout=60, cwd=str(tmp_path))
        assert e.returncode == 0 and "«Alpha»" in e.stdout, (e.stdout, e.stderr)
        again = subprocess.run([sys.executable, "-m", "omxpatch_agent", "enroll", "--server", url, "--token", raw, "--pin-sha256", pin],
                               capture_output=True, text=True, env=env, timeout=60, cwd=str(tmp_path))
        assert again.returncode == 3                                   # já registado: exige --force
        cfgj = json.loads((tmp_path / "cfg" / "agent.json").read_text())
        assert cfgj["tenant"] == "alpha" and cfgj["agent_key"].startswith("omxa_")
        db.session.expire_all()
        assert Asset.query.filter_by(tenant_id=tenant.id, managed=True, ring=2).count() == 1
    finally:
        srv.stop()


def test_branding_oramix_logo_colors_and_tenant_theme(app, tenant):
    c = login_as(app, "admin@alpha.example")
    html = c.get("/").get_data(as_text=True)
    assert '<span class="mark"><b>OMX</b>Patch</span>' in html
    css = open(os.path.join(os.path.dirname(__file__), "..", "omxpatch", "static", "app.css")).read()
    assert "header.top .logo .mark b{color:var(--logo-accent,var(--accent,#ff8000))" in css and ".mark{color:var(--header-fg,#fff)}" in css
    login = Client(app.test_client()).get("/login").get_data(as_text=True)
    assert '<div class="logo"><b>OMX</b>Patch</div>' in login and "Vuln" not in login
    png = b"\x89PNG\r\n\x1a\n" + b"0" * 64
    _fresh_g()
    r = c.c.post("/branding/settings", data={"_csrf": c.csrf(), "brand_header": "#102030", "brand_primary": "#0053ad", "brand_accent": "#ff8000",
                                              "logo": (io.BytesIO(png), "l.png")}, content_type="multipart/form-data")
    assert r.status_code == 302
    t = Tenant.query.filter_by(slug="alpha").one()
    assert t.logo_file.endswith(".png") and t.brand_header == "#102030"
    _fresh_g()
    assert "--header-bg:#102030" in c.get("/branding/theme.css").get_data(as_text=True)
    assert "tenant-logo" in c.get("/").get_data(as_text=True)
    assert c.get(f"/branding/logo/{t.id}").status_code == 200
    beta = login_as(app, "admin@beta.example")
    assert beta.get(f"/branding/logo/{t.id}").status_code == 404                # logótipo isolado por organização
    assert "--header-bg:#102030" not in beta.get("/branding/theme.css").get_data(as_text=True)
    _fresh_g()
    assert c.c.post("/branding/settings", data={"_csrf": c.csrf(), "logo": (io.BytesIO(b"<svg/>"), "x.svg")},
                    content_type="multipart/form-data").status_code == 302 and "Formato não suportado" in c.get("/settings").get_data(as_text=True)
    assert "Identidade visual" in c.get("/settings").get_data(as_text=True)
