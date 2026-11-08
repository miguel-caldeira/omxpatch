"""Worker do OMXPatch: motor contínuo de monitorização e remediação.

A cada ciclo (``WORKER_POLL_SECONDS``):

* devolve à fila tarefas de agentes sem resposta e liberta as que aguardavam o seu momento;
* executa em modo **sem agente** (Ansible) as tarefas dos ativos com ``connection = ansible``;
* avança campanhas (anéis, janelas, promoção automática) e fluxos autónomos;
e, por temporizador: inteligência (KEV/EPSS/NVD…), correlação, sinais multi-vendor, OMXVuln, OMXGRC.

Pode correr embebido no processo web (executável) ou como processo próprio (``omxpatch worker``).
"""
from __future__ import annotations

import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from .connectors import omxgrc, omxvuln, sync
from .connectors.store import ConnectorError, effective
from .engine import ansible_runner, autonomous, correlate, deploy, intel, validation
from .extensions import db
from .licensing import is_suspended
from .models import AppMeta, Campaign, Exposure, Task, Tenant, utcnow
from .notifications import notify

log = logging.getLogger("omxpatch.worker")


def due(key: str, minutes: float, now=None) -> bool:
    """Temporizador persistente (partilhado por vários workers): True e regista se já passou o intervalo."""
    now = now or utcnow()
    row = db.session.get(AppMeta, key)
    if row is not None:
        try:
            from datetime import datetime
            if now - datetime.fromisoformat(row.value) < timedelta(minutes=minutes):
                return False
        except ValueError:
            pass
    else:
        row = AppMeta(key=key)
        db.session.add(row)
    row.value = now.isoformat()
    db.session.commit()
    return True


class Worker:
    def __init__(self, app):
        self.app = app
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="omxpatch-ansible")
        self._busy: set[int] = set()
        self._lock = threading.Lock()
        self.last_tick = None
        self.last_error = ""
        self.started = time.time()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="omxpatch-worker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._pool.shutdown(wait=False)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                t0 = time.perf_counter()
                with self.app.app_context():
                    summary = self.tick()
                    from .engine import capacity
                    capacity.save_worker_stats(self.app, (time.perf_counter() - t0) * 1000, summary or {})
                self.last_error = ""
                from .engine import settings as settings_mod
                if not self.app.config.get("TESTING") and settings_mod.restart_requested_since(self.app.config, self.started):
                    log.warning("Reinício pedido na consola: o worker termina (o supervisor volta a arrancá-lo)")
                    os._exit(0)
            except Exception as exc:  # noqa: BLE001 - o worker nunca morre
                log.exception("Ciclo do worker falhou: %s", exc)
                self.last_error = str(exc)
                try:
                    db.session.rollback()
                except Exception:  # noqa: BLE001
                    pass
            self._stop.wait(int(self.app.config["WORKER_POLL_SECONDS"]))

    # ------------------------------------------------------------------ um ciclo (também usado nos testes)

    def tick(self, now=None) -> dict:
        now = now or utcnow()
        self.last_tick = now
        summary = {"tenants": 0, "ansible": 0, "campaigns": 0, "runs": 0}
        cfg = self.app.config
        if due("job:intel", float(cfg["INTEL_SYNC_HOURS"]) * 60, now) and not cfg.get("TESTING"):
            try:
                intel.sync_all()
            except Exception as exc:  # noqa: BLE001
                log.warning("Inteligência: %s", exc)
        for tenant in Tenant.query.filter_by(active=True):
            if is_suspended(tenant):
                continue
            summary["tenants"] += 1
            self._tenant(tenant, now, summary)
        return summary

    def _tenant(self, tenant: Tenant, now, summary: dict) -> None:
        cfg = self.app.config
        deploy.requeue_stale(tenant.id)
        for t in Task.query.filter(Task.tenant_id == tenant.id, Task.status == "pending", Task.campaign_id.is_(None),
                                   Task.not_before <= now):
            t.status = "queued"
        db.session.commit()
        from .engine import plans
        plans.release(tenant, now)
        db.session.commit()
        summary["ansible"] += self._run_ansible_tasks(tenant)
        for c in Campaign.query.filter(Campaign.tenant_id == tenant.id, Campaign.status.in_(("scheduled", "running"))):
            deploy.advance(c, tenant, now)
            summary["campaigns"] += 1
        db.session.commit()
        for run in autonomous.AutonomousRun.query.filter(autonomous.AutonomousRun.tenant_id == tenant.id,
                                                          autonomous.AutonomousRun.status.in_(("running", "waiting"))):
            autonomous.advance(run, now)
            summary["runs"] += 1
        db.session.commit()
        if due(f"job:correlate:{tenant.id}", float(cfg["CORRELATE_MINUTES"]), now):
            self._monitor(tenant)
        if effective(tenant.id, "omxvuln") is not None and due(f"job:omxvuln:{tenant.id}", float(cfg["OMXVULN_SYNC_MINUTES"]), now):
            try:
                oc = effective(tenant.id, "omxvuln")
                omxvuln.sync(tenant, "both" if str(oc.opts.get("sync_assets", "true")).lower() in ("1", "true", "yes", "sim") else "findings")
            except (ConnectorError, Exception) as exc:  # noqa: BLE001
                log.warning("OMXVuln %s: %s", tenant.slug, exc)
                db.session.rollback()
        if effective(tenant.id, "omxgrc") is not None and due(f"job:omxgrc:{tenant.id}", float(cfg["OMXGRC_PUSH_MINUTES"]), now):
            try:
                omxgrc.push_metrics(tenant)
                db.session.commit()
            except Exception as exc:  # noqa: BLE001
                log.warning("OMXGRC %s: %s", tenant.slug, exc)
                db.session.rollback()

    def _monitor(self, tenant: Tenant) -> None:
        """Monitorização contínua: sinais multi-vendor → correlação → risco → alertas → novos fluxos autónomos."""
        try:
            sync.pull_signal_sources(tenant)
        except Exception as exc:  # noqa: BLE001
            log.warning("Sinais %s: %s", tenant.slug, exc)
            db.session.rollback()
        res = correlate.correlate_tenant(tenant)
        correlate.refresh_tenant(tenant)
        for ex in Exposure.query.filter(Exposure.id.in_(res.get("new_ids") or [0]), Exposure.risk_category.in_(("critical", "emergency"))):
            try:
                sync.notify_critical(tenant, ex)
                notify(tenant, f"[OMXPatch] Exposição {ex.risk_category}: {ex.cve_id} em {ex.asset.name}",
                       f"{ex.verdict_data.get('summary', '')}\nRisco {ex.risk_score}/100 · patch "
                       f"{'disponível' if ex.patch_available else 'indisponível'}.")
            except Exception as exc:  # noqa: BLE001
                log.warning("Alerta %s: %s", ex.cve_id, exc)
        autonomous.scan_new_cves(tenant)
        db.session.commit()

    # ------------------------------------------------------------------ modo sem agente (Ansible)

    def _run_ansible_tasks(self, tenant: Tenant) -> int:
        if not self.app.config["ANSIBLE_ENABLED"]:
            return 0
        n = 0
        for t in Task.query.filter_by(tenant_id=tenant.id, mode="ansible", status="queued").limit(8):
            with self._lock:
                if t.id in self._busy:
                    continue
                self._busy.add(t.id)
            t.status, t.started_at, t.sent_at, t.attempts = "running", utcnow(), utcnow(), (t.attempts or 0) + 1
            db.session.commit()
            self._pool.submit(self._exec, t.id)
            n += 1
        return n

    def _exec(self, task_id: int) -> None:
        with self.app.app_context():
            try:
                task = db.session.get(Task, task_id)
                try:
                    report = ansible_runner.run_task(task)
                except ansible_runner.AnsibleUnavailable as exc:
                    report = {"status": "failed", "output": str(exc)}
                deploy.complete_task(task, report)
                db.session.commit()
            except Exception as exc:  # noqa: BLE001
                log.exception("Tarefa Ansible %s: %s", task_id, exc)
                db.session.rollback()
            finally:
                with self._lock:
                    self._busy.discard(task_id)


__all__ = ["validation"]
