"""Rotação do thumbprint, tarefas e pacote assinados, atualização automática do agente, limitação de pedidos."""
import hashlib
import io
import os
import time
import zipfile
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from omxpatch import ratelimit, signing, tls
from omxpatch.extensions import db
from omxpatch.models import Agent, Task, utcnow
from omxpatch_agent import ed25519, trust, update
from tests.test_flow import FakeAgent, enroll_token  # noqa: F401


# ------------------------------------------------------------------ Ed25519 em Python puro


def test_pure_python_ed25519_matches_cryptography():
    k = Ed25519PrivateKey.generate()
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    for n in (0, 1, 33, 400):
        m = os.urandom(n)
        sig = k.sign(m)
        assert ed25519.verify(pub, m, sig) and not ed25519.verify(pub, m + b"x", sig)
    sig = bytearray(k.sign(b"a"))
    sig[10] ^= 1
    assert not ed25519.verify(pub, b"a", bytes(sig)) and not ed25519.verify(pub, b"a", b"short") and not ed25519.verify(b"x" * 32, b"a", bytes(sig))
    assert not ed25519.verify(pub, b"a", k.sign(b"a")[:32] + b"\xff" * 32)             # s fora do intervalo


# ------------------------------------------------------------------ tarefas assinadas


def test_server_signs_tasks_and_agent_verifies(app, tenant, enroll_token):
    ag = FakeAgent(app, enroll_token, "w1")
    a = Agent.query.filter_by(hostname="w1").one()
    db.session.add(Task(tenant_id=tenant.id, type="inventory", asset_id=a.asset_id, mode="agent", status="queued", payload="{}"))
    db.session.commit()
    r = ag.c.post("/agent/v1/poll", headers=ag.h, json={"version": "1"}).get_json()
    t = r["tasks"][0]
    keys = r["trust"]["task_keys"]
    assert t["sig"] and isinstance(t["iat"], int) and keys and r["trust"]["agent_id"] == a.id
    cfg = {"task_keys": keys}
    assert trust.verify_task(cfg, t, a.id) == (True, "")
    assert trust.verify_task(cfg, {**t, "type": "patch"}, a.id)[1] == "assinatura inválida"                        # tipo alterado
    assert trust.verify_task(cfg, {**t, "payload": {"x": 1}}, a.id)[0] is False                                     # payload alterado
    assert trust.verify_task(cfg, t, a.id + 1)[0] is False                                                          # tarefa de outro agente
    assert "sem assinatura" in trust.verify_task(cfg, {k: v for k, v in t.items() if k != "sig"}, a.id)[1]
    assert "prazo" in trust.verify_task(cfg, t, a.id, now=time.time() + 7200)[1]                                    # repetição tardia
    assert trust.verify_task({}, {"id": 1, "type": "x"}, 1)[0] is True                                              # agente ainda sem chaves


def test_trust_adoption_requires_continuity(app):
    cfg = {"pin_sha256": "a" * 64}
    new_pin = "b" * 64
    assert trust.adopt(cfg, {"pins": ["a" * 64, new_pin], "task_keys": ["c" * 64], "agent_id": 7})                 # 1.º contacto: fixa
    assert cfg["pin_sha256"] == f"{'a' * 64},{new_pin}" and cfg["task_keys"] == ["c" * 64] and cfg["agent_id"] == 7
    assert not trust.adopt(cfg, {"pins": ["d" * 64], "task_keys": ["e" * 64]})                                     # sem continuidade: recusa
    assert cfg["pin_sha256"].startswith("a" * 64) and cfg["task_keys"] == ["c" * 64]
    assert trust.adopt(cfg, {"pins": [new_pin], "task_keys": ["e" * 64, "c" * 64]})                                # rotação com continuidade
    assert cfg["pin_sha256"] == new_pin and cfg["task_keys"] == ["e" * 64, "c" * 64]
    assert not trust.adopt({"pin_sha256": ""}, {"pins": ["a" * 64]})                                               # modo CA: não mexe nas pins


def test_agent_rejects_unsigned_task_and_reports_failure(app, tenant, enroll_token, monkeypatch):
    from omxpatch_agent import cli, config as acfg
    cfgd = {"agent_key": "k", "agent_id": 1, "task_keys": ["a" * 64], "pin_sha256": ""}
    monkeypatch.setattr(acfg, "load", lambda: dict(cfgd))
    monkeypatch.setattr(acfg, "save", lambda c: None)
    reports = []

    class C:
        s = object()

        def poll(self, state=None):
            return {"tasks": [{"id": 5, "type": "inventory", "payload": {}}], "poll_seconds": 60}

        def task_result(self, i, rep):
            reports.append((i, rep))
    monkeypatch.setattr(cli.executor, "execute", lambda c, t: pytest.fail("não deve executar"))
    cli.cycle(C(), {"last_inventory": time.time()})
    assert reports and reports[0][1]["rejected"] and "sem assinatura" in reports[0][1]["output"]


# ------------------------------------------------------------------ rotação do thumbprint do certificado dos agentes


def _cfg(app, tmp_path):
    cfg = dict(app.config)
    cfg.update(DATA_DIR=str(tmp_path), AGENT_TLS_CERT="", AGENT_TLS_KEY="", TLS_ENABLED=True)
    return cfg


def test_certificate_rotation_publishes_next_pin_then_promotes(app, tmp_path):
    cfg = _cfg(app, tmp_path)
    first = tls.ensure(cfg, log=lambda m: None, profile="agent")
    assert tls.agent_pins(cfg) == [first["sha256"].replace(":", "").lower()]
    assert tls.maintain(cfg, log=lambda m: None) == ""                       # longe do fim: nada a fazer
    cert, key, _ = tls.paths(cfg, "agent")
    # envelhece o certificado atual: gera um que expira em 40 dias
    cfg2 = dict(cfg, TLS_DAYS=40)
    tls.generate(cfg2, cert, key, "agent")
    old = tls.info(cert)["sha256"]
    assert tls.maintain(cfg, log=lambda m: None) == "prepared"
    pins = tls.agent_pins(cfg)
    assert len(pins) == 2 and pins[0] == old.replace(":", "").lower()      # atual + seguinte publicados
    nxt = pins[1]
    # ainda dentro do período de publicação (<7 dias) e a expirar em < 30 dias: mantém o atual, não gera outro
    tls.generate(dict(cfg, TLS_DAYS=20), cert, key, "agent")
    cur = tls.info(cert)["sha256"].replace(":", "").lower()
    pins = tls.agent_pins(cfg)
    assert tls.ensure(cfg, log=lambda m: None, profile="agent")["sha256"].replace(":", "").lower() == cur
    assert tls.agent_pins(cfg)[1] == pins[1]
    # passado o período: o seguinte passa a atual (o thumbprint publicado antes)
    ncert, _nk = tls.next_paths(cfg, "agent")
    past = time.time() - 8 * 86400
    os.utime(ncert, (past, past))
    done = tls.ensure(cfg, log=lambda m: None, profile="agent")
    assert done["sha256"].replace(":", "").lower() == nxt and tls.agent_pins(cfg) == [nxt] and not ncert.exists()


def test_poll_publishes_both_pins_and_agents_follow(app, tenant, enroll_token, tmp_path):
    cfg = _cfg(app, tmp_path)
    app.config["DATA_DIR"] = str(tmp_path)
    tls.ensure(cfg, log=lambda m: None, profile="agent")
    cert, key, _ = tls.paths(cfg, "agent")
    tls.generate(dict(cfg, TLS_DAYS=40), cert, key, "agent")
    tls.maintain(cfg, log=lambda m: None)
    ag = FakeAgent(app, enroll_token, "w1")
    r = ag.c.post("/agent/v1/poll", headers=ag.h, json={"version": "1"}).get_json()
    assert len(r["trust"]["pins"]) == 2
    agent_cfg = {"pin_sha256": r["trust"]["pins"][0]}
    assert trust.adopt(agent_cfg, r["trust"]) and agent_cfg["pin_sha256"] == ",".join(r["trust"]["pins"])


# ------------------------------------------------------------------ atualização automática do agente


def _bundle_with_version(version: str) -> bytes:
    root = Path(update.pkg.__file__).resolve().parent
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for f in sorted(root.rglob("*.py")):
            text = f.read_text(encoding="utf-8")
            if f.name == "__init__.py" and f.parent == root:
                text = text.replace(update.__version__, version)
            z.writestr(f"omxpatch_agent/{f.relative_to(root).as_posix()}", text)
    return buf.getvalue()


def test_update_requires_signed_newer_bundle(app, monkeypatch):
    keys = signing.public_keys(app.config)
    v = "9.9.20991231"
    sha = "f" * 64
    sig = signing.sign(app.config, "bundle", {"version": v, "sha256": sha})
    monkeypatch.setattr(update, "can_update", lambda: (True, ""))
    cfg = {"task_keys": keys}
    assert update.check(cfg, {"agent_version": v, "bundle_sha256": sha, "bundle_sig": sig}) == {"version": v, "sha256": sha}
    assert update.check(cfg, {"agent_version": v, "bundle_sha256": "e" * 64, "bundle_sig": sig}) is None           # SHA alterado
    assert update.check(cfg, {"agent_version": v, "bundle_sha256": sha, "bundle_sig": "00" * 64}) is None          # assinatura falsa
    assert update.check({"task_keys": []}, {"agent_version": v, "bundle_sha256": sha, "bundle_sig": sig}) is None  # sem chaves fixadas
    assert update.check({**cfg, "auto_update": False}, {"agent_version": v, "bundle_sha256": sha, "bundle_sig": sig}) is None
    old = signing.sign(app.config, "bundle", {"version": "0.0.1", "sha256": sha})
    assert update.check(cfg, {"agent_version": "0.0.1", "bundle_sha256": sha, "bundle_sig": old}) is None         # não é mais recente
    monkeypatch.setattr(update, "can_update", lambda: (False, "pacote do sistema"))
    assert update.check(cfg, {"agent_version": v, "bundle_sha256": sha, "bundle_sig": sig}) is None


def test_update_apply_swaps_folder_after_selftest_and_can_rollback(tmp_path, monkeypatch):
    root = tmp_path / "opt"
    root.mkdir()
    import shutil
    shutil.copytree(Path(update.pkg.__file__).resolve().parent, root / "omxpatch_agent", ignore=shutil.ignore_patterns("__pycache__"))
    monkeypatch.setattr(update, "install_root", lambda: root)
    monkeypatch.setattr(update.config, "config_dir", lambda: tmp_path)
    new_v = "9.9.20991231"
    data = _bundle_with_version(new_v)
    sha = hashlib.sha256(data).hexdigest()

    class C:
        def bundle(self):
            return data, sha
    assert update.apply(C(), {"version": new_v, "sha256": sha}) == new_v
    assert f'"{new_v}"' in (root / "omxpatch_agent" / "__init__.py").read_text() and (root / "omxpatch_agent.prev").is_dir()
    assert update.rollback() and update.__version__ in (root / "omxpatch_agent" / "__init__.py").read_text()
    with pytest.raises(RuntimeError, match="SHA-256"):
        update.apply(C(), {"version": new_v, "sha256": "0" * 64})
    bad = io.BytesIO()
    with zipfile.ZipFile(bad, "w") as z:
        z.writestr("omxpatch_agent/__init__.py", '__version__ = "9.9.20991231"\n')                           # pacote que não arranca
    badb = bad.getvalue()

    class B:
        def bundle(self):
            return badb, hashlib.sha256(badb).hexdigest()
    before = (root / "omxpatch_agent" / "__init__.py").read_text()
    with pytest.raises(RuntimeError, match="autoteste"):
        update.apply(B(), {"version": new_v, "sha256": hashlib.sha256(badb).hexdigest()})
    assert (root / "omxpatch_agent" / "__init__.py").read_text() == before                                  # nada foi trocado
    evil = io.BytesIO()
    with zipfile.ZipFile(evil, "w") as z:
        z.writestr("omxpatch_agent/../../evil.py", "x")
    eb = evil.getvalue()

    class E:
        def bundle(self):
            return eb, hashlib.sha256(eb).hexdigest()
    with pytest.raises(Exception):
        update.apply(E(), {"version": new_v, "sha256": hashlib.sha256(eb).hexdigest()})
    assert not (tmp_path / "evil.py").exists()


def test_server_advertises_signed_bundle(app, tenant, enroll_token):
    ag = FakeAgent(app, enroll_token, "w1")
    t = ag.c.post("/agent/v1/poll", headers=ag.h, json={"version": "1"}).get_json()["trust"]
    import omxpatch_agent
    assert t["agent_version"] == omxpatch_agent.__version__
    assert trust.verify_with(t["task_keys"], "bundle", {"version": t["agent_version"], "sha256": t["bundle_sha256"]}, t["bundle_sig"])
    r = ag.c.get("/agent/v1/bundle", headers=ag.h)
    assert r.status_code == 200 and hashlib.sha256(r.data).hexdigest() == t["bundle_sha256"] == r.headers["X-Content-SHA256"]
    app.config["AGENT_AUTO_UPDATE"] = False
    assert "bundle_sig" not in ag.c.post("/agent/v1/poll", headers=ag.h, json={"version": "1"}).get_json()["trust"]


def test_signing_key_rotation_keeps_previous_published(app):
    before = signing.public_keys(app.config)
    res = signing.rotate(app.config)
    keys = signing.public_keys(app.config)
    assert keys == [res["current"], before[0]] and res["current"] != before[0]
    sig_new = signing.sign(app.config, "task", {"x": 1})
    assert trust.verify_with(keys[:1], "task", {"x": 1}, sig_new) and not trust.verify_with(before, "task", {"x": 1}, sig_new)


# ------------------------------------------------------------------ limitação de pedidos


def test_rate_limiter_window_and_disable():
    ratelimit.reset()
    assert all(ratelimit.hit("k", 3, 60)[0] for _ in range(3))
    ok, retry = ratelimit.hit("k", 3, 60)
    assert not ok and 1 <= retry <= 61
    assert ratelimit.hit("outro", 3, 60)[0] and ratelimit.hit("k", 0)[0]
    assert ratelimit.peek("k") == 3


def test_enroll_endpoint_blocks_token_guessing_by_ip(app, tenant):
    c = app.test_client()
    codes = [c.post("/agent/v1/enroll", json={"token": f"omxe_wrong{i}", "hostname": "h", "os_family": "linux"}).status_code for i in range(35)]
    assert codes[:30] == [401] * 30 and 429 in codes[30:]
    r = c.post("/agent/v1/enroll", json={"token": "omxe_x", "hostname": "h", "os_family": "linux"})
    assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1
    assert c.post("/agent/v1/poll", headers={"Authorization": "Bearer omxa_x"}).status_code == 429               # chaves inválidas também bloqueadas


def test_invalid_agent_keys_and_per_agent_flood_are_limited(app, tenant, enroll_token):
    ag = FakeAgent(app, enroll_token, "w1")
    app.config["RATE_AGENT_PER_MIN"] = 5
    codes = [ag.c.post("/agent/v1/poll", headers=ag.h, json={"version": "1"}).status_code for _ in range(8)]
    assert codes[:5] == [200] * 5 and codes[5:] == [429] * 3
    other = FakeAgent(app, enroll_token, "w2")
    assert other.c.post("/agent/v1/poll", headers=other.h, json={"version": "1"}).status_code == 200            # limite por agente
    app.config["RATE_AGENT_PER_MIN"] = 0
    assert ag.c.post("/agent/v1/poll", headers=ag.h, json={"version": "1"}).status_code == 200


# ------------------------------------------------------------------ migrações versionadas, cópias e retenção


def test_versioned_migrations_apply_once_and_roll_back_failures(app, monkeypatch):
    from omxpatch import migrations
    st = migrations.status()
    assert st["pending"] == [] and "0002_poll_indexes" in st["applied"] and st["latest"] == "0002_poll_indexes"
    assert migrations.upgrade() == []                                               # idempotente
    calls = []

    def ok(conn):
        calls.append("ok")
        conn.execute(migrations.text("CREATE TABLE t_mig (id INTEGER)"))

    def boom(conn):
        conn.execute(migrations.text("CREATE TABLE t_mig2 (id INTEGER)"))
        raise ValueError("falhou")
    monkeypatch.setattr(migrations, "MIGRATIONS", migrations.MIGRATIONS + [("0003_ok", "ok", ok), ("0004_boom", "boom", boom)])
    with pytest.raises(RuntimeError, match="0004_boom falhou e foi revertida"):
        migrations.upgrade()
    assert "0003_ok" in migrations.applied() and "0004_boom" not in migrations.applied()
    with db.engine.connect() as c:
        tables = {r[0] for r in c.execute(migrations.text("SELECT name FROM sqlite_master WHERE type='table'"))}
    assert "t_mig" in tables and "t_mig2" not in tables                              # a falhada foi revertida por inteiro
    assert migrations.pending() == ["0004_boom"] and calls == ["ok"]


def test_migration_helpers_rename_and_drop_column(app):
    from omxpatch import migrations
    with db.engine.begin() as c:
        c.execute(migrations.text("CREATE TABLE t_h (a INTEGER, b INTEGER)"))
        migrations.rename_column(c, "t_h", "a", "x")
        migrations.drop_column(c, "t_h", "b")
        cols = [r[1] for r in c.execute(migrations.text("PRAGMA table_info(t_h)"))]
    assert cols == ["x"]


def test_backup_restore_roundtrip_and_prune(app, tenant, tmp_path):
    from omxpatch.engine import backup
    app.config.update(DATA_DIR=str(tmp_path), BACKUP_KEEP=2, BACKUP_DIR="")
    (tmp_path / "tls").mkdir(exist_ok=True)
    (tmp_path / "tls" / "x.crt").write_text("CERT")
    (tmp_path / "secret.key").write_text("S3CRET")
    signing.private_key(app.config)
    res = backup.create(app)
    f = Path(res["file"])
    assert f.is_file() and oct(f.stat().st_mode)[-3:] == "600" and res["engine"] == "sqlite"
    import tarfile
    names = tarfile.open(f).getnames()
    assert "database.sqlite" in names and "files/secret.key" in names and "files/tls/x.crt" in names and "files/signing/task.key" in names
    time.sleep(1.1)
    backup.create(app)
    time.sleep(1.1)
    last = backup.create(app)
    assert len(backup.listing(app.config)) == 2 and last["pruned"] == 1
    # restauro numa pasta nova
    target = tmp_path / "novo"
    out = backup.restore(last["file"], str(target))
    assert Path(out["restored"]).is_file() and (target / "secret.key").read_text() == "S3CRET" and (target / "tls" / "x.crt").read_text() == "CERT"
    with pytest.raises(FileExistsError):
        backup.restore(last["file"], str(target))                                     # não sobrescreve sem --force
    backup.restore(last["file"], str(target), force=True)
    assert list(target.glob("omxpatch.db.before-restore-*"))                            # a anterior fica guardada
    import sqlite3
    assert sqlite3.connect(str(target / "omxpatch.db")).execute("select count(*) from tenants").fetchone()[0] >= 2


def test_restore_rejects_path_traversal(tmp_path):
    import tarfile
    from omxpatch.engine import backup
    evil = tmp_path / "evil.tar.gz"
    with tarfile.open(evil, "w:gz") as t:
        data = tmp_path / "d"
        data.write_text("x")
        t.add(data, arcname="../escape.txt")
    with pytest.raises(ValueError):
        backup.restore(str(evil), str(tmp_path / "t"))


def test_retention_deletes_only_old_records(app, tenant):
    from omxpatch.engine import backup
    from omxpatch.models import AuditLog
    from tests.conftest import make_asset
    a = make_asset(tenant, "r1", software=())
    old, new = utcnow() - timedelta(days=400), utcnow()
    for when in (old, new):
        db.session.add(AuditLog(action="x", detail="", created_at=when))
        db.session.add(Task(tenant_id=tenant.id, type="inventory", asset_id=a.id, status="succeeded", payload="{}", created_at=when))
    db.session.add(Task(tenant_id=tenant.id, type="inventory", asset_id=a.id, status="queued", payload="{}", created_at=old))   # em fila: nunca apagada
    db.session.commit()
    n_audit, n_tasks = AuditLog.query.count(), Task.query.count()
    assert backup.retention(app) == {"audit": 0, "tasks": 0, "agent_logs": 0}                         # 0 = guardar sempre
    app.config.update(AUDIT_RETENTION_DAYS=365, TASK_RETENTION_DAYS=365)
    assert backup.retention(app) == {"audit": 1, "tasks": 1, "agent_logs": 0}
    assert AuditLog.query.count() == n_audit - 1 and Task.query.count() == n_tasks - 1
    assert Task.query.filter_by(status="queued").count() == 1


def test_backup_page_and_cli_helpers(app, tenant, tmp_path):
    from tests.conftest import login_as
    app.config.update(DATA_DIR=str(tmp_path), BACKUP_KEEP=3)
    sa = login_as(app, "root@omx.example")
    assert "Cópias de segurança" in sa.get("/system/capacity").get_data(as_text=True)
    sa.post("/system/backup", {})
    assert not list((tmp_path / "backups").glob("omxpatch-*.tar.gz"))               # sem OK
    sa.post("/system/backup", {"confirm_ok": "1"})
    assert len(list((tmp_path / "backups").glob("omxpatch-*.tar.gz"))) == 1
    assert login_as(app, "admin@alpha.example").post("/system/backup", {"confirm_ok": "1"}).status_code == 403
