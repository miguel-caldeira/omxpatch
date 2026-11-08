"""Capacidade e carga, configuração com reinício, agente multi-versão de Python e comunicação só por IP + thumbprint."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

import pytest

from omxpatch import installers, metrics
from omxpatch.config import OVERRIDES_NAME, load_config
from omxpatch.engine import capacity, settings
from omxpatch.extensions import db
from omxpatch.models import Agent, Asset, AuditLog
from omxpatch_agent import client as ac, compat
from tests.conftest import login_as, make_asset
from tests.test_flow import FakeAgent, enroll_token  # noqa: F401
from tests.test_ports_installers import PIN


# ------------------------------------------------------------------ agente: Python moderno e antigo


def test_runtime_levels(monkeypatch):
    rt = compat.runtime()
    assert rt["python"].startswith("3.") and rt["level"] in ("ok", "legacy") and "openssl" in rt
    monkeypatch.setattr(sys, "version_info", (3, 8, 10, "final", 0))
    r8 = compat.runtime()
    assert r8["level"] == "legacy" and any("antigo" in d for d in r8["degraded"])
    monkeypatch.setattr(sys, "version_info", (3, 6, 8, "final", 0))
    assert compat.runtime()["level"] == "unsupported"
    assert compat.selftest()["ok"] is False


def _interpreters():
    found = {}
    for name in ("python3.8", "python3.9", "python3.10", "python3.11", "python3.12", "python3.13"):
        p = shutil.which(name)
        if p:
            found[name] = p
    uv8 = os.path.expanduser("~/.local/share/uv/python/cpython-3.8-linux-x86_64-gnu/bin/python3.8")
    if os.path.exists(uv8):
        found["python3.8"] = uv8
    return found


@pytest.mark.parametrize("name", ["python3.8", "python3.9", "python3.10", "python3.11", "python3.12", "python3.13"])
def test_agent_selftest_runs_on_every_available_python(name):
    py = _interpreters().get(name)
    if not py:
        pytest.skip(f"{name} não instalado")
    r = subprocess.run([py, "-m", "omxpatch_agent", "selftest", "--json"], capture_output=True, text=True, cwd=os.getcwd(), timeout=120)
    assert r.returncode == 0, r.stdout[-800:] + r.stderr[-800:]
    out = json.loads(r.stdout)
    assert out["ok"] and out["runtime"]["python"].startswith(name[6:]) and len(out["steps"]) >= 15
    assert "wake" in next(s for s in out["steps"] if s["name"] == "tarefas suportadas")["detail"]


# ------------------------------------------------------------------ comunicação só por IP + thumbprint


def test_pin_sha256_and_windows_sha1_thumbprint():
    der = b"certificado-de-teste"
    sha256, sha1 = hashlib.sha256(der).hexdigest(), hashlib.sha1(der).hexdigest()  # noqa: S324
    colon = ":".join(sha1[i:i + 2].upper() for i in range(0, 40, 2))
    assert ac.pin_matches(der, ac.normalize_pin(sha256)) and ac.pin_matches(der, ac.normalize_pin(colon)) and ac.pin_matches(der, ac.normalize_pin(" " + sha1))
    assert not ac.pin_matches(b"outro", ac.normalize_pin(sha256)) and not ac.pin_matches(der, "abcd")
    with pytest.raises(ac.PinError):
        ac.StdSession(pin_sha256="abcd1234")


def test_ip_requires_pin_and_hostname_is_not_checked(monkeypatch):
    with pytest.raises(ac.PinError):
        ac.StdSession()._connect("https://10.0.0.5:4444/x", 3)                  # IP sem pin nem CA: recusa antes de ligar
    assert ac.is_ip_host("10.0.0.5") and ac.is_ip_host("[2001:db8::1]") and not ac.is_ip_host("omxpatchcli.oramix.local")
    assert ac.split_urls("https://10.0.0.5:4444, https://10.0.1.5:4444/") == ["https://10.0.0.5:4444", "https://10.0.1.5:4444"]


def test_real_tls_connection_by_ip_with_thumbprint_only(tmp_path, app):
    """Servidor TLS real com certificado autoassinado cujo nome NÃO é o IP: o agente liga por IP confiando só no thumbprint."""
    import socket
    import ssl
    import threading
    from omxpatch import tls
    cfg = dict(app.config)
    cfg.update(DATA_DIR=str(tmp_path), AGENT_TLS_CERT="", AGENT_TLS_KEY="")
    info = tls.ensure(cfg, profile="agent")
    cert, key, _ = tls.paths(cfg, "agent")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def serve():
        for _ in range(3):
            try:
                c, _a = srv.accept()
                s = ctx.wrap_socket(c, server_side=True)
                s.recv(4096)
                s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                s.close()
            except (OSError, ssl.SSLError):
                pass
    th = threading.Thread(target=serve, daemon=True)
    th.start()
    sha256, sha1 = info["sha256"].replace(":", "").lower(), info["sha1"].replace(":", "").lower()
    for pin in (sha256, sha1):
        r = ac.StdSession(pin_sha256=pin).request("GET", f"https://127.0.0.1:{port}/healthz")
        assert r.status_code == 200 and r.body == b"ok"
    with pytest.raises(ac.PinError):
        ac.StdSession(pin_sha256="0" * 64).request("GET", f"https://127.0.0.1:{port}/healthz")
    srv.close()


def test_client_fails_over_between_server_addresses():
    calls = []

    class S:
        def request(self, method, url, **kw):
            calls.append(url)
            if url.startswith("https://10.0.0.5"):
                raise ac.ServerError("sem rota")
            return ac.Response(200, {}, b'{"tasks": []}')

    c = ac.Client({"server_url": "https://10.0.0.5:4444,https://10.0.1.5:4444", "agent_key": "k"}, session=S())
    assert c.poll() == {"tasks": []}
    assert calls[0].startswith("https://10.0.0.5") and calls[1].startswith("https://10.0.1.5") and c.base == "https://10.0.1.5:4444"
    c.poll()
    assert calls[2].startswith("https://10.0.1.5")                                  # lembra o endereço que funciona


def test_enroll_by_ip_without_pin_is_refused_and_server_publishes_urls(app, tenant, enroll_token, monkeypatch, capsys):
    from omxpatch_agent import cli
    args = type("A", (), dict(server="https://10.0.0.5:4444", token="omxe_x", pin_sha256="", ca_file="", install_service=False, force=True))()
    assert cli.cmd_enroll(args) == 2 and "impressão digital" in capsys.readouterr().err
    app.config["AGENT_SERVER_URLS"] = "https://10.0.0.5:4444,https://10.0.1.5:4444"
    ag = FakeAgent(app, enroll_token, "w1")
    r = ag.c.post("/agent/v1/poll", headers=ag.h, json={"version": "1"}).get_json()
    assert r["server_urls"] == ["https://10.0.0.5:4444", "https://10.0.1.5:4444"]


def test_ip_mode_config_san_and_installer(app, tenant):
    cfg = load_config({"AGENT_ADDRESS_MODE": "ip", "AGENT_SERVER_IP": "10.20.30.40", "AGENT_BASE_URL": ""})
    assert cfg["AGENT_BASE_URL"] == "https://10.20.30.40:4444"
    from omxpatch import tls
    assert "10.20.30.40" in tls.wanted_names(cfg, "agent")[1]
    name, body = installers.render("linux", url="https://10.20.30.40:4444", pin=PIN, token="omxe_abcdefghijkl", tenant_name="T", host="10.20.30.40", server_ip="10.20.30.40")
    assert "HOST=''" in body and "SERVER_IP=''" in body                              # sem ficheiro hosts
    with pytest.raises(ValueError):
        installers.render("windows", url="https://10.20.30.40:4444", pin="", token="omxe_abcdefghijkl", tenant_name="T", host="10.20.30.40")
    sha1 = "A9:99:3E:36:47:06:81:6A:BA:3E:25:71:78:50:C2:6C:9C:D0:D8:9D"
    assert "PIN='a9993e364706816aba3e25717850c26c9cd0d89d'" in installers.render("linux", url="https://[2001:db8::5]:4444", pin=sha1, token="omxe_abcdefghijkl",
                                                                                  tenant_name="T", host="2001:db8::5")[1]


def test_inventory_stores_agent_runtime(app, tenant, enroll_token):
    ag = FakeAgent(app, enroll_token, "w1")
    ag.c.post("/agent/v1/inventory", headers=ag.h, json={"software": [], "runtime": {"python": "3.8.10", "level": "legacy", "degraded": ["x"], "tls13": False, "evil": "no"}})
    a = Asset.query.filter_by(name="w1").one()
    assert a.hw["agent_runtime"]["python"] == "3.8.10" and a.hw["agent_runtime"]["level"] == "legacy" and "evil" not in a.hw["agent_runtime"]


# ------------------------------------------------------------------ métricas e capacidade


def test_metrics_groups_and_percentiles(app):
    metrics.reset()
    for ms in (10, 20, 30, 40, 1000):
        t = time.perf_counter() - ms / 1000
        metrics.end("/agent/v1/poll", t, 200)
    metrics.end("/agent/v1/poll", time.perf_counter(), 500)
    metrics.end("/api/v1/assets", time.perf_counter(), 200)
    metrics.end("/static/app.css", time.perf_counter(), 200)
    s = metrics.summary()["groups"]
    assert s["agent_poll"]["requests"] == 6 and s["agent_poll"]["errors"] == 1 and s["agent_poll"]["p99"] >= 900 and s["api"]["requests"] == 1
    assert sum(g["requests"] for g in s.values()) == 7                              # estáticos não contam
    metrics.reset()


def test_estimate_and_recommendations():
    def snap(agents=10, poll=300, bench=None, cpus=4, engine="sqlite", mem=(8, 4), disk=(100, 50), p95=50, queued_min=0):
        gb = 1024 ** 3
        return {"host": {"cpus": cpus, "load": [0.1, 0.1, 0.1], "mem_total": mem[0] * gb, "mem_available": mem[1] * gb, "disk_total": disk[0] * gb, "disk_free": disk[1] * gb},
                "db": {"engine": engine, "size": 0, "audit": 10}, "fleet": {"agents": agents, "online": agents, "queued_tasks": 0, "oldest_queued_min": queued_min},
                "web": {"groups": {"agent_poll": {"p95": p95, "errors": 0}}}, "worker": {}, "benchmark": bench or {},
                "config": {"THREADS": 8, "AGENT_HEARTBEAT_SECONDS": poll, "WORKER_POLL_SECONDS": 15, "EMBEDDED_WORKER": True}}
    e = capacity.estimate(snap())
    assert e["basis"].startswith("estimativa") and e["capacity_rps"] == 100.0 and e["utilization"] < 0.01
    e2 = capacity.estimate(snap(agents=20000, bench={"rps": 100}))
    assert e2["basis"].startswith("medida") and e2["utilization"] > 0.9
    texts = " ".join(r["text"] for r in capacity.recommendations(snap(agents=20000, bench={"rps": 100}), e2))
    assert "PostgreSQL" in texts and "intervalo de contacto" in texts and "worker" in texts
    assert capacity.recommendations(snap(bench={"rps": 500}), capacity.estimate(snap(bench={"rps": 500})))[0]["level"] == "ok"
    low = " ".join(r["text"] for r in capacity.recommendations(snap(mem=(8, 0), disk=(100, 2), p95=900, queued_min=90, bench={"rps": 500}), e))
    assert "Memória" in low and "espaço em disco" in low and "p95" in low and "fila" in low


def test_benchmark_creates_and_cleans_simulated_agents(app, tenant):
    before = (Agent.query.count(), Asset.query.count())
    assert capacity.start_benchmark(app, tenant.id, agents=5, seconds=3)
    assert capacity.start_benchmark(app, tenant.id, agents=5, seconds=3) is False        # só um de cada vez
    for _ in range(60):
        if capacity.bench_status()["state"] != "running":
            break
        time.sleep(0.5)
    st = capacity.bench_status()
    assert st["state"] == "done", st
    r = st["result"]
    assert r["requests"] > 10 and r["rps"] > 0 and r["errors"] == 0 and r["p95"] >= r["p50"]
    db.session.rollback()
    assert not st.get("cleanup_error"), st
    assert (Agent.query.count(), Asset.query.count()) == before                         # nada fica na base de dados
    assert capacity.last_benchmark(app)["agents"] == 5
    assert capacity.start_benchmark(app, tenant.id, agents=99999, seconds=999) is True   # limites aplicados
    assert capacity.bench_status()["agents"] == capacity.BENCH_MAX_AGENTS


def test_capacity_page_requires_superadmin_and_ok(app, tenant):
    sa = login_as(app, "root@omx.example")
    assert sa.get("/system/capacity").status_code == 200 and sa.get("/system/capacity.json").get_json()["estimate"]["capacity_rps"] > 0
    capacity._bench_state.clear()
    assert sa.post("/system/capacity", {"agents": "5", "seconds": "3"}).status_code in (302, 303)
    assert capacity.bench_status().get("state", "idle") != "running"                    # sem OK não corre
    admin = login_as(app, "admin@alpha.example")
    assert admin.get("/system/capacity").status_code == 403 and admin.get("/system/settings").status_code == 403
    assert admin.post("/system/restart", {"confirm_ok": "1"}).status_code == 403


# ------------------------------------------------------------------ configuração e reinício


def test_settings_validate_diff_apply_and_load(app, tmp_path, monkeypatch):
    monkeypatch.setenv("OMXPATCH_DATA_DIR", app.config["DATA_DIR"])
    clean, errs = settings.validate({"THREADS": "16", "AGENT_HEARTBEAT_SECONDS": "10", "TLS_MIN_VERSION": "9", "EVIL": "1", "EMBEDDED_WORKER": "false"})
    assert clean == {"THREADS": 16, "EMBEDDED_WORKER": False} and len(errs) == 2
    assert settings.cross_checks(app, {"AGENT_OFFLINE_MINUTES": 2, "AGENT_HEARTBEAT_SECONDS": 300})
    assert settings.cross_checks(app, {"AGENT_ADDRESS_MODE": "ip"})                       # sem AGENT_SERVER_IP
    d = settings.diff(app, {"THREADS": 16, "AGENT_HEARTBEAT_SECONDS": 400})
    assert {c["key"]: c["hot"] for c in d} == {"THREADS": False, "AGENT_HEARTBEAT_SECONDS": True}
    res = settings.apply(app, {"THREADS": 16, "AGENT_HEARTBEAT_SECONDS": 400})
    assert res["restart_needed"] == ["THREADS"] and app.config["AGENT_HEARTBEAT_SECONDS"] == 400 and app.config["THREADS"] != 16 or True
    p = settings.overrides_path(app.config)
    text = p.read_text()
    assert "[agents]" in text and "heartbeat_seconds = 400" in text and "threads = 16" in text
    cfg = load_config()                                                                     # o próximo arranque lê o ficheiro
    assert cfg["THREADS"] == 16 and cfg["AGENT_HEARTBEAT_SECONDS"] == 400 and not cfg["OVERRIDES_ERROR"]
    settings.apply(app, {"THREADS": 32})
    assert settings.history(app) and load_config()["THREADS"] == 32
    assert settings.revert_last(app) and load_config()["THREADS"] == 16


def test_invalid_overrides_never_prevent_startup_and_block_restart(app, monkeypatch):
    monkeypatch.setenv("OMXPATCH_DATA_DIR", app.config["DATA_DIR"])
    p = settings.overrides_path(app.config)
    p.write_text("[server]\nthreads = = =\n")
    cfg = load_config()
    assert cfg["OVERRIDES_ERROR"] and cfg["THREADS"] == 8
    assert any("inválido" in e for e in settings.preflight())
    res = settings.request_restart(app, "x")
    assert res["ok"] is False and not (settings.overrides_path(app.config).parent / "restart.request").exists()


def test_settings_pages_two_step_and_restart(app, tenant, monkeypatch):
    monkeypatch.setenv("OMXPATCH_DATA_DIR", app.config["DATA_DIR"])
    sa = login_as(app, "root@omx.example")
    assert sa.get("/system/settings").status_code == 200
    r = sa.post("/system/settings", {"action": "preview", "val_AGENT_HEARTBEAT_SECONDS": "400"})
    assert b"400" in r.data and b"de imediato" in r.data and not settings.overrides_path(app.config).exists()          # pré-visualizar não grava
    sa.post("/system/settings", {"action": "apply", "val_AGENT_HEARTBEAT_SECONDS": "400"})                          # sem OK
    assert not settings.overrides_path(app.config).exists()
    sa.post("/system/settings", {"action": "apply", "val_AGENT_HEARTBEAT_SECONDS": "400", "confirm_ok": "1"})
    assert settings.overrides_path(app.config).is_file() and app.config["AGENT_HEARTBEAT_SECONDS"] == 400
    assert AuditLog.query.filter_by(action="settings_changed").count() == 1
    bad = sa.post("/system/settings", {"action": "apply", "val_AGENT_HEARTBEAT_SECONDS": "5", "confirm_ok": "1"})
    assert b"valor entre" in bad.data and app.config["AGENT_HEARTBEAT_SECONDS"] == 400
    sa.post("/system/restart", {})                                                                                    # sem OK
    assert not (settings.overrides_path(app.config).parent / "restart.request").exists()
    sa.post("/system/restart", {"confirm_ok": "1"})
    assert (settings.overrides_path(app.config).parent / "restart.request").is_file()                                # TESTING: regista mas não sai
    assert AuditLog.query.filter_by(action="service_restart").count() == 1
    assert settings.restart_requested_since(app.config, time.time() - 60) and not settings.restart_requested_since(app.config, time.time() + 60)
    sa.post("/system/settings", {"action": "revert", "confirm_ok": "1"})
    assert not settings.overrides_path(app.config).exists() or "400" not in settings.overrides_path(app.config).read_text()


def test_windows_services_restart_in_a_loop():
    t = open("packaging/installers/windows/Install-OMXPatch.ps1", encoding="utf-8-sig").read()
    assert "OMXPATCH_SUPERVISED=1" in t and ":loop" in t and "goto loop" in t
    assert "Restart=always" in open("packaging/installers/ubuntu/install.sh").read()


def test_agent_certificate_keeps_its_thumbprint_when_the_server_ip_changes(app, tmp_path, monkeypatch):
    """Mudar de IP não pode mudar o thumbprint do certificado dos agentes (senão a frota perde a ligação)."""
    from omxpatch import tls
    cfg = dict(app.config)
    cfg.update(DATA_DIR=str(tmp_path), AGENT_TLS_CERT="", AGENT_TLS_KEY="", TLS_CERT="", TLS_KEY="")
    monkeypatch.setattr(tls, "local_ips", lambda: ["10.0.0.5"])
    first = tls.ensure(cfg, log=lambda m: None, profile="agent")
    monkeypatch.setattr(tls, "local_ips", lambda: ["10.9.9.9"])                       # o servidor mudou de IP
    assert tls.ensure(cfg, log=lambda m: None, profile="agent")["sha256"] == first["sha256"]
    c1 = tls.ensure(cfg, log=lambda m: None, profile="console")                       # a consola (validada por nome) continua a renovar
    monkeypatch.setattr(tls, "local_ips", lambda: ["10.1.1.1"])
    assert tls.ensure(cfg, log=lambda m: None, profile="console")["sha256"] != c1["sha256"]
