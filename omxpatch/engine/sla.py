"""I5 — SLA, envelhecimento (aging) e cobertura da remediação: MTTR por gravidade, cumprimento de SLA, exportação CSV e relatório agendado."""
from __future__ import annotations

import csv
import io
from datetime import timedelta

from ..models import RISK_CATEGORIES, Agent, Asset, Exposure, Tenant, utcnow

OPEN = ("open", "mitigated", "patching")
BUCKETS = (("0–7 d", 0, 7), ("8–30 d", 8, 30), ("31–60 d", 31, 60), ("61–90 d", 61, 90), ("> 90 d", 91, 10 ** 6))
PERIODS = {"off": "Desligado", "weekly": "Semanal (segundas-feiras)", "monthly": "Mensal (dia 1)"}


def _days(a, b) -> float:
    return (b - a).total_seconds() / 86400


def _closed_at(e: Exposure):
    return e.closed_at or e.patched_at


def report(tenant: Tenant, now=None, window_days: int = 90) -> dict:
    now = now or utcnow()
    exps = Exposure.query.filter_by(tenant_id=tenant.id).all()
    since = now - timedelta(days=window_days)
    cats = {}
    for cat in reversed(RISK_CATEGORIES):
        rows = [e for e in exps if e.risk_category == cat]
        open_ = [e for e in rows if e.status in OPEN]
        closed = [e for e in rows if _closed_at(e) and _closed_at(e) >= since and e.status in ("closed", "remediated")]
        times = [_days(e.detected_at, _closed_at(e)) for e in closed if _closed_at(e) >= e.detected_at]
        with_due = [e for e in closed if e.due_date]
        in_sla = [e for e in with_due if _closed_at(e) <= e.due_date]
        cats[cat] = {"sla_days": tenant.sla_days(cat), "open": len(open_), "overdue": sum(1 for e in open_ if e.due_date and e.due_date < now), "closed": len(closed),
                     "mttr_days": round(sum(times) / len(times), 1) if times else None,
                     "sla_compliance": round(100 * len(in_sla) / len(with_due), 1) if with_due else None}
    open_all = [e for e in exps if e.status in OPEN]
    aging = []
    for label, lo, hi in BUCKETS:
        aging.append({"label": label, "n": sum(1 for e in open_all if lo <= int(_days(e.detected_at, now)) <= hi),
                      "critical": sum(1 for e in open_all if e.risk_category in ("critical", "emergency") and lo <= int(_days(e.detected_at, now)) <= hi)})
    total_closed = sum(c["closed"] for c in cats.values())
    scored = [(c["sla_compliance"], c["closed"]) for c in cats.values() if c["sla_compliance"] is not None]
    overall = round(sum(p * n for p, n in scored) / sum(n for _, n in scored), 1) if scored and sum(n for _, n in scored) else None
    assets = Asset.query.filter_by(tenant_id=tenant.id).all()
    fresh = now - timedelta(hours=48)
    agent_ok = {a.asset_id for a in Agent.query.filter(Agent.tenant_id == tenant.id, Agent.revoked.is_(False), Agent.last_seen > fresh) if a.asset_id}
    agentless = [a for a in assets if a.connection == "ansible" and a.managed]
    coverage = {"assets": len(assets), "managed": sum(1 for a in assets if a.managed), "agent_active": len(agent_ok), "agentless": len(agentless),
                "unmanaged": sum(1 for a in assets if not a.managed and a.id not in agent_ok),
                "pct": round(100 * len({a.id for a in assets if a.managed or a.id in agent_ok}) / len(assets), 1) if assets else None}
    months = []
    for m in range(5, -1, -1):
        end = (now - timedelta(days=30 * m))
        start = end - timedelta(days=30)
        ts = [_days(e.detected_at, _closed_at(e)) for e in exps if _closed_at(e) and start <= _closed_at(e) < end and _closed_at(e) >= e.detected_at]
        months.append({"label": end.strftime("%m/%Y"), "closed": len(ts), "mttr_days": round(sum(ts) / len(ts), 1) if ts else None})
    overdue = sorted((e for e in open_all if e.due_date and e.due_date < now), key=lambda e: e.due_date)[:15]
    return {"generated_at": now, "window_days": window_days, "categories": cats, "aging": aging, "coverage": coverage, "trend": months,
            "overall_sla": overall, "closed": total_closed, "open": len(open_all), "overdue_total": sum(c["overdue"] for c in cats.values()),
            "oldest": [{"cve": e.cve_id, "asset": e.asset.name, "category": e.risk_category, "age_days": int(_days(e.detected_at, now)),
                        "overdue_days": int(_days(e.due_date, now))} for e in overdue]}


def csv_text(tenant: Tenant, now=None) -> str:
    """Todas as exposições com idade, prazo e estado de SLA (para auditoria/Excel). Campos que começam por = + - @ são neutralizados (CSV injection)."""
    now = now or utcnow()
    out = io.StringIO()
    w = csv.writer(out, delimiter=";", lineterminator="\n")
    w.writerow(["CVE", "Ativo", "Software", "Estado", "Categoria", "Risco", "Detetada", "Prazo (SLA)", "Fechada", "Idade (dias)", "Dias em atraso", "SLA"])

    def safe(v):
        v = "" if v is None else str(v)
        return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v
    for e in Exposure.query.filter_by(tenant_id=tenant.id).order_by(Exposure.detected_at).all():
        end = _closed_at(e) if e.status in ("closed", "remediated") else now
        end = end or now
        late = int(_days(e.due_date, end)) if e.due_date and end > e.due_date else 0
        state = "sem prazo" if not e.due_date else ("fora do prazo" if late else "dentro do prazo")
        w.writerow([safe(e.cve_id), safe(e.asset.name), safe(e.software_name), e.status, e.risk_category, e.risk_score, e.detected_at.strftime("%Y-%m-%d"),
                    e.due_date.strftime("%Y-%m-%d") if e.due_date else "", _closed_at(e).strftime("%Y-%m-%d") if e.status in ("closed", "remediated") and _closed_at(e) else "",
                    int(_days(e.detected_at, end)), late, state])
    return out.getvalue()


def summary_text(tenant: Tenant, r: dict) -> str:
    lines = [f"Relatório de SLA e envelhecimento — {tenant.name}", f"Gerado em {r['generated_at'].strftime('%d/%m/%Y %H:%M')} (janela de {r['window_days']} dias)", "",
             f"Exposições em aberto: {r['open']} · fora do prazo: {r['overdue_total']} · cumprimento de SLA: {r['overall_sla'] if r['overall_sla'] is not None else 'n/d'} %", "",
             "Por categoria (SLA · abertas · em atraso · MTTR · cumprimento):"]
    for cat, c in r["categories"].items():
        lines.append(f"  {cat:<10} {c['sla_days']} d · {c['open']} · {c['overdue']} · {c['mttr_days'] if c['mttr_days'] is not None else 'n/d'} d · "
                     f"{c['sla_compliance'] if c['sla_compliance'] is not None else 'n/d'} %")
    lines += ["", "Envelhecimento: " + "; ".join(f"{b['label']}: {b['n']}" for b in r["aging"]),
              f"Cobertura: {r['coverage']['managed']}/{r['coverage']['assets']} ativos geridos ({r['coverage']['pct'] if r['coverage']['pct'] is not None else 'n/d'} %), agentes ativos: {r['coverage']['agent_active']}"]
    return "\n".join(lines) + "\n"


def due_now(tenant: Tenant, now=None) -> bool:
    now = now or utcnow()
    mode = tenant.report_schedule
    if mode not in ("weekly", "monthly") or not (tenant.notify_emails or "").strip():
        return False
    if tenant.report_last_sent and (now - tenant.report_last_sent) < timedelta(days=5):
        return False
    return (mode == "weekly" and now.weekday() == 0) or (mode == "monthly" and now.day == 1)


def send_report(tenant: Tenant, now=None) -> int:
    from .. import notifications
    now = now or utcnow()
    emails = [e.strip() for e in (tenant.notify_emails or "").replace(";", ",").split(",") if e.strip()]
    if not emails:
        raise ValueError("Defina os destinatários em Notificações (e-mails da organização).")
    r = report(tenant, now)
    notifications.send_email(emails, f"OMXPatch — SLA e envelhecimento ({tenant.name})", summary_text(tenant, r),
                             attachments=[(f"omxpatch-sla-{now.strftime('%Y%m%d')}.csv", ("﻿" + csv_text(tenant, now)).encode("utf-8"), "text/csv")])
    tenant.report_last_sent = now
    return len(emails)
