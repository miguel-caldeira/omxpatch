"""Análise de carga e escalabilidade: estado da máquina e da base de dados, carga prevista dos agentes, teste de carga
sintético (agentes simulados a falar com a pilha real: autenticação, base de dados) e recomendações."""
from __future__ import annotations

import json
import os
import shutil
import sys
import threading
import time
from datetime import timedelta
from pathlib import Path

from sqlalchemy import func

from .. import metrics
from ..extensions import db
from ..models import Agent, Asset, AuditLog, Exposure, Task, utcnow

BENCH_MAX_AGENTS, BENCH_MAX_SECONDS = 500, 60
_bench_lock = threading.Lock()
_bench_state: dict = {"state": "idle"}


def _data_dir(app) -> Path:
    return Path(app.config["DATA_DIR"])


# --------------------------------------------------------------------------- máquina


def _meminfo() -> dict:
    try:
        if sys.platform.startswith("linux"):
            kv = {l.split(":")[0]: int(l.split()[1]) * 1024 for l in Path("/proc/meminfo").read_text().splitlines() if ":" in l}
            return {"total": kv.get("MemTotal", 0), "available": kv.get("MemAvailable", 0)}
        if sys.platform.startswith("win"):
            import ctypes

            class MS(ctypes.Structure):
                _fields_ = [("l", ctypes.c_ulong), ("load", ctypes.c_ulong), ("total", ctypes.c_ulonglong), ("avail", ctypes.c_ulonglong),
                            ("tp", ctypes.c_ulonglong), ("ap", ctypes.c_ulonglong), ("tv", ctypes.c_ulonglong), ("av", ctypes.c_ulonglong), ("ae", ctypes.c_ulonglong)]
            st = MS()
            st.l = ctypes.sizeof(MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st))
            return {"total": int(st.total), "available": int(st.avail)}
    except (OSError, ValueError, AttributeError):
        pass
    return {"total": 0, "available": 0}


def _rss() -> int:
    try:
        if sys.platform.startswith("linux"):
            for line in Path("/proc/self/status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        pass
    return 0


def host(app) -> dict:
    mem, d = _meminfo(), _data_dir(app)
    usage = shutil.disk_usage(d)
    try:
        load = os.getloadavg()
    except (AttributeError, OSError):
        load = None
    return {"cpus": os.cpu_count() or 1, "load": [round(x, 2) for x in load] if load else None, "mem_total": mem["total"],
            "mem_available": mem["available"], "process_rss": _rss(), "disk_total": usage.total, "disk_free": usage.free,
            "python": sys.version.split()[0], "platform": sys.platform}


def database(app) -> dict:
    url = str(app.config["DATABASE_URL"])
    engine = db.engine.dialect.name
    size = 0
    if engine == "sqlite":
        try:
            size = Path(url.replace("sqlite:///", "")).stat().st_size
        except OSError:
            pass
    return {"engine": engine, "size": size, "assets": db.session.query(func.count(Asset.id)).scalar() or 0,
            "tasks": db.session.query(func.count(Task.id)).scalar() or 0, "exposures": db.session.query(func.count(Exposure.id)).scalar() or 0,
            "audit": db.session.query(func.count(AuditLog.id)).scalar() or 0}


def fleet(app) -> dict:
    now = utcnow()
    offline = timedelta(minutes=int(app.config["AGENT_OFFLINE_MINUTES"]))
    agents = Agent.query.filter_by(revoked=False).filter(~Agent.hostname.like("loadtest-%")).all()
    online = sum(1 for a in agents if a.last_seen and now - a.last_seen < offline)
    queued = Task.query.filter(Task.status.in_(("queued", "pending", "sent"))).count()
    oldest = db.session.query(func.min(Task.created_at)).filter(Task.status.in_(("queued", "sent"))).scalar()
    return {"agents": len(agents), "online": online, "queued_tasks": queued,
            "oldest_queued_min": int((now - oldest).total_seconds() // 60) if oldest else 0}


def worker_stats(app) -> dict:
    try:
        return json.loads((_data_dir(app) / "worker-stats.json").read_text())
    except (OSError, ValueError):
        return {}


def save_worker_stats(app, duration_ms: float, summary: dict) -> None:
    try:
        (_data_dir(app) / "worker-stats.json").write_text(json.dumps({"at": utcnow().isoformat(), "duration_ms": round(duration_ms, 1), **summary}))
    except OSError:
        pass


def last_benchmark(app) -> dict:
    try:
        return json.loads((_data_dir(app) / "benchmark.json").read_text())
    except (OSError, ValueError):
        return {}


def snapshot(app) -> dict:
    return {"host": host(app), "db": database(app), "fleet": fleet(app), "web": metrics.summary(), "worker": worker_stats(app),
            "benchmark": last_benchmark(app), "config": {k: app.config[k] for k in ("THREADS", "AGENT_HEARTBEAT_SECONDS", "WORKER_POLL_SECONDS", "EMBEDDED_WORKER")}}


# --------------------------------------------------------------------------- modelo de capacidade


def estimate(snap: dict) -> dict:
    """Carga prevista (agentes ÷ intervalo de contacto, com folga para picos) face à capacidade medida ou estimada."""
    poll = max(1, int(snap["config"]["AGENT_HEARTBEAT_SECONDS"]))
    n = snap["fleet"]["agents"]
    expected = n / poll
    peak = expected * 3                      # reinício do servidor / pico de contactos (os agentes usam jitter de ~10%)
    b = snap["benchmark"]
    if b and b.get("rps"):
        capacity, basis = b["rps"] * 0.6, "medida (teste de carga) com 40% de folga"
    else:
        capacity, basis = 25.0 * min(snap["host"]["cpus"], 4), "estimativa conservadora (sem teste de carga)"
    return {"expected_rps": round(expected, 2), "peak_rps": round(peak, 2), "capacity_rps": round(capacity, 1), "basis": basis,
            "utilization": round(peak / capacity, 3) if capacity else 0, "max_agents": int(capacity * poll / 3),
            "max_agents_at_300s": int(capacity * 300 / 3), "poll_seconds": poll}


def recommendations(snap: dict, est: dict) -> list:
    out = []

    def add(level, text):
        out.append({"level": level, "text": text})
    h, d, f = snap["host"], snap["db"], snap["fleet"]
    if not snap["benchmark"]:
        add("info", "Ainda não há teste de carga: execute-o para trocar a estimativa por uma medição desta máquina.")
    u = est["utilization"]
    if u > 0.9:
        need = int(est["poll_seconds"] * u / 0.6) + 1
        add("critical", f"Carga de pico prevista a {u:.0%} da capacidade: aumente o intervalo de contacto dos agentes para ≥ {need}s, "
                        f"mude para PostgreSQL e/ou aumente CPU. Limite atual: ~{est['max_agents']} agentes.")
    elif u > 0.6:
        add("warning", f"Carga de pico prevista a {u:.0%} da capacidade (~{est['max_agents']} agentes no máximo ao intervalo atual): planeie escalar.")
    if d["engine"] == "sqlite" and (f["agents"] > 300 or d["audit"] > 2_000_000):
        add("warning", "SQLite com muitos agentes/registos: os escritores são serializados. Migre para PostgreSQL (DATABASE_URL) acima de ~300 agentes.")
    if d["engine"] == "sqlite" and d["size"] > 2 * 1024 ** 3:
        add("warning", f"Base de dados SQLite com {d['size'] / 1024 ** 3:.1f} GB: considere PostgreSQL e política de retenção da auditoria.")
    if h["mem_total"] and h["mem_available"] / h["mem_total"] < 0.15:
        add("warning", f"Memória livre baixa ({h['mem_available'] / h['mem_total']:.0%}).")
    if h["disk_free"] < 5 * 1024 ** 3 or h["disk_free"] / max(1, h["disk_total"]) < 0.1:
        add("warning", f"Pouco espaço em disco ({h['disk_free'] / 1024 ** 3:.1f} GB livres): o repositório de patches e a base de dados crescem.")
    if h["load"] and h["load"][0] > h["cpus"] * 1.5:
        add("warning", f"Carga do sistema alta ({h['load'][0]} para {h['cpus']} CPU).")
    t = int(snap["config"]["THREADS"])
    if t < h["cpus"] * 2 and f["agents"] > 100:
        add("info", f"THREADS={t} é baixo para {h['cpus']} CPU: considere {h['cpus'] * 4}.")
    if t > 64:
        add("info", "THREADS muito alto aumenta a contenção no Python (GIL); prefira mais instâncias atrás de um balanceador.")
    gp = snap["web"]["groups"]["agent_poll"]
    if gp["p95"] > 500:
        add("warning", f"Latência p95 dos contactos de agentes = {gp['p95']} ms (> 500 ms): verifique a base de dados e a carga.")
    if gp["errors"]:
        add("warning", f"{gp['errors']} erros 5xx nos contactos de agentes nos últimos 5 minutos.")
    w = snap["worker"]
    if w and w.get("duration_ms", 0) > int(snap["config"]["WORKER_POLL_SECONDS"]) * 1000:
        add("warning", f"O ciclo do worker ({w['duration_ms'] / 1000:.0f}s) demora mais que o intervalo ({snap['config']['WORKER_POLL_SECONDS']}s): ciclos acumulam.")
    if snap["config"]["EMBEDDED_WORKER"] and f["agents"] > 200:
        add("info", "Com muitos agentes, execute o worker como serviço separado (EMBEDDED_WORKER=false) para não competir com os pedidos web.")
    if f["oldest_queued_min"] > 30 and f["online"]:
        add("warning", f"Há tarefas em fila há {f['oldest_queued_min']} min com agentes online: verifique janelas de manutenção e o worker.")
    if f["agents"] and f["online"] / f["agents"] < 0.5:
        add("info", f"Só {f['online']}/{f['agents']} agentes estão online.")
    if not out:
        add("ok", "Sem alertas de capacidade.")
    return out


# --------------------------------------------------------------------------- teste de carga


def bench_status() -> dict:
    return dict(_bench_state)


def start_benchmark(app, tenant_id: int, agents: int = 50, seconds: int = 10) -> bool:
    """Arranca o teste numa thread; devolve False se já houver um em curso. Cria agentes simulados («loadtest-N») e remove-os no fim."""
    agents, seconds = max(1, min(int(agents), BENCH_MAX_AGENTS)), max(3, min(int(seconds), BENCH_MAX_SECONDS))
    if not _bench_lock.acquire(blocking=False):
        return False
    _bench_state.clear()
    _bench_state.update({"state": "running", "agents": agents, "seconds": seconds, "started": time.time()})
    threading.Thread(target=_run_benchmark, args=(app, tenant_id, agents, seconds), daemon=True, name="omxpatch-benchmark").start()
    return True


def _run_benchmark(app, tenant_id: int, n: int, seconds: int) -> None:
    import hashlib
    import secrets
    lat: list = []
    errors = [0]
    lock = threading.Lock()
    try:
        with app.app_context():
            keys = []
            for i in range(n):
                key = "omxa_" + secrets.token_urlsafe(24)
                a = Asset(tenant_id=tenant_id, uid=f"loadtest-{i}", name=f"loadtest-{i}", source="loadtest", managed=True, os_family="linux")
                db.session.add(a)
                db.session.flush()
                db.session.add(Agent(tenant_id=tenant_id, asset_id=a.id, key_hash=hashlib.sha256(key.encode()).hexdigest(), key_prefix=key[:10],
                                     hostname=f"loadtest-{i}", os_family="linux", version="loadtest"))
                keys.append(key)
            db.session.commit()
        stop = time.time() + seconds

        def worker(key):
            c = app.test_client()
            h = {"Authorization": f"Bearer {key}"}
            k = 0
            while time.time() < stop:
                t0 = time.perf_counter()
                try:
                    if k % 25 == 24:
                        r = c.post("/agent/v1/inventory", headers=h, json={"software": [], "hardware": {"cpu_count": 2}, "open_ports": [], "version": "loadtest"})
                    else:
                        r = c.post("/agent/v1/poll", headers=h, json={"version": "loadtest"})
                    bad = r.status_code >= 500
                except Exception:  # noqa: BLE001 - um erro é um resultado do teste
                    bad = True
                with lock:
                    lat.append((time.perf_counter() - t0) * 1000)
                    errors[0] += 1 if bad else 0
                k += 1

        threads = [threading.Thread(target=worker, args=(k,), daemon=True) for k in keys]
        t_start = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join(seconds + 30)
        elapsed = max(0.001, time.time() - t_start)
        lat.sort()
        pct = lambda p: round(lat[min(len(lat) - 1, int(len(lat) * p))], 1) if lat else 0.0  # noqa: E731
        res = {"agents": n, "seconds": round(elapsed, 1), "requests": len(lat), "errors": errors[0], "rps": round(len(lat) / elapsed, 1),
               "p50": pct(.5), "p95": pct(.95), "p99": pct(.99), "engine": "", "cpus": os.cpu_count() or 1, "at": utcnow().isoformat(),
               "note": "Pilha real (autenticação + base de dados) em processo, sem rede/TLS; mede um processo web."}
        with app.app_context():
            res["engine"] = db.engine.dialect.name
        (_data_dir(app) / "benchmark.json").write_text(json.dumps(res))
        metrics.reset()                          # os pedidos simulados não contam como tráfego real
        outcome = {"state": "done", "result": res}
    except Exception as exc:  # noqa: BLE001
        outcome = {"state": "error", "error": str(exc)[:300]}
    finally:
        try:
            with app.app_context():
                for a in Agent.query.filter(Agent.hostname.like("loadtest-%")).all():
                    db.session.delete(a)
                for a in Asset.query.filter(Asset.uid.like("loadtest-%")).all():
                    db.session.delete(a)
                db.session.commit()
        except Exception as exc:  # noqa: BLE001
            _bench_state["cleanup_error"] = str(exc)[:200]
        _bench_state.update(locals().get("outcome") or {"state": "error", "error": "interrompido"})   # só «concluído» depois da limpeza
        _bench_lock.release()
