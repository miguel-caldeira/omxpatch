"""Administração: utilizadores, organizações, definições, auditoria, sistema, integrações e agentes."""
from __future__ import annotations

import re
from datetime import date

from pathlib import Path

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required

from .. import branding as _branding
from .. import installers, licensing, tls, versioninfo
from ..connectors import discovery, omxgrc, omxvuln, outbound, signals as signals_mod, sync
from ..connectors import store as cstore
from ..connectors.catalog import GROUPS, KINDS
from ..connectors.store import ConnectorError
from ..engine import agentops, ansible_runner, intel, rings
from ..extensions import db
from ..models import (ROLES, Agent, AgentLog, AuditLog, Connector, EnrollmentToken, Tenant, User, PrimaryAdminError, utcnow)
from ..security import (audit, current_tenant, flash_errors, get_scoped_or_404, password_problems, require_tenant, roles_required, scoped,
                        superadmin_required)
from .api import new_enrollment_token

bp = Blueprint("admin", __name__)


# --------------------------------------------------------------------------- utilizadores


@bp.route("/users")
@login_required
@roles_required("admin")
def users():
    q = User.query
    if not current_user.is_superadmin:
        q = q.filter_by(tenant_id=current_user.tenant_id)
    elif session.get("tenant_id"):
        q = q.filter_by(tenant_id=session["tenant_id"])
    return render_template("admin/users.html", rows=q.order_by(User.email).all())


@bp.route("/users/new", methods=["GET", "POST"])
@login_required
@roles_required("admin")
def user_new():
    tenant = require_tenant()
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "user")
        problems = password_problems(password)
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("E-mail inválido.", "danger")
        elif User.query.filter(db.func.lower(User.email) == email).first():
            flash("E-mail já registado.", "danger")
        elif role not in ROLES:
            flash("Perfil inválido.", "danger")
        elif problems:
            flash_errors(["Password fraca: " + "; ".join(problems)])
        else:
            u = User(email=email, name=request.form.get("name", "")[:200], tenant_id=tenant.id, role=role, must_change_password=True)
            u.set_password(password)
            db.session.add(u)
            audit("user_created", f"{email} ({role})")
            db.session.commit()
            return redirect(url_for("admin.users"))
    return render_template("admin/user_form.html", u=None)


@bp.route("/users/<int:user_id>", methods=["GET", "POST"])
@login_required
@roles_required("admin")
def user_edit(user_id: int):
    u = db.session.get(User, user_id) or abort(404)
    if not current_user.is_superadmin and u.tenant_id != current_user.tenant_id:
        abort(404)
    if request.method == "POST":
        try:
            if request.form.get("role") in ROLES and not u.is_superadmin:
                u.role = request.form["role"]
            u.enabled = bool(request.form.get("enabled"))
            if request.form.get("password"):
                problems = password_problems(request.form["password"])
                if problems:
                    flash_errors(["Password fraca: " + "; ".join(problems)])
                    return render_template("admin/user_form.html", u=u), 400
                u.set_password(request.form["password"])
                u.must_change_password = True
            u.session_version += 1
            audit("user_updated", u.email)
            db.session.commit()
        except PrimaryAdminError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
            return render_template("admin/user_form.html", u=u), 400
        return redirect(url_for("admin.users"))
    return render_template("admin/user_form.html", u=u)


# --------------------------------------------------------------------------- organizações


@bp.route("/tenants")
@login_required
@superadmin_required
def tenants():
    rows = Tenant.query.order_by(Tenant.name).all()
    return render_template("admin/tenants.html", rows=rows, status={t.id: licensing.status(t) for t in rows})


@bp.route("/tenants/new", methods=["GET", "POST"])
@login_required
@superadmin_required
def tenant_new():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        slug = re.sub(r"[^a-z0-9-]+", "-", (request.form.get("slug") or name).lower()).strip("-")[:64]
        if not name or not slug:
            flash("Indique o nome da organização.", "danger")
        elif Tenant.query.filter_by(slug=slug).first():
            flash("Já existe uma organização com esse identificador.", "danger")
        else:
            t = Tenant(name=name[:200], slug=slug, country=request.form.get("country", "PT")[:2].upper() or "PT",
                       license_expires_on=_date(request.form.get("license_expires_on")),
                       license_ref=request.form.get("license_ref", "")[:120])
            db.session.add(t)
            db.session.flush()
            rings.ensure_policies(t)
            audit("tenant_created", name, tenant_id=t.id)
            db.session.commit()
            session["tenant_id"] = t.id
            flash("Organização criada.", "success")
            return redirect(url_for("admin.users"))
    return render_template("admin/tenant_form.html", t=None)


def _date(text):
    try:
        return date.fromisoformat(text) if text else None
    except ValueError:
        return None


@bp.route("/tenants/<int:tenant_id>/license", methods=["POST"])
@login_required
@superadmin_required
def tenant_license(tenant_id: int):
    t = db.session.get(Tenant, tenant_id) or abort(404)
    t.license_expires_on = _date(request.form.get("license_expires_on"))
    t.license_ref = request.form.get("license_ref", "")[:120]
    audit("license_updated", f"{t.name}: {t.license_expires_on}", tenant_id=t.id)
    db.session.commit()
    return redirect(url_for("admin.tenants"))


@bp.route("/settings", methods=["GET", "POST"])
@login_required
@roles_required("admin")
def tenant_settings():
    t = require_tenant()
    if request.method == "POST":
        f = request.form
        try:
            for k in ("emergency", "critical", "high", "medium", "low"):
                setattr(t, f"sla_{k}", max(1, int(f.get(f"sla_{k}") or getattr(t, f"sla_{k}"))))
        except ValueError:
            flash("Prazos de SLA inválidos.", "danger")
            return redirect(url_for("admin.tenant_settings"))
        t.notify_emails = f.get("notify_emails", "")[:1000]
        t.webhook_url = f.get("webhook_url", "").strip()[:500]
        t.require_mfa = bool(f.get("require_mfa"))
        t.security_officer = f.get("security_officer", "")[:200]
        t.security_officer_email = f.get("security_officer_email", "")[:255]
        t.sector = f.get("sector", "")[:120]
        t.default_country = f.get("default_country", "PT")[:2].upper()
        if t.webhook_url:
            from ..security import OutboundURLError, check_outbound_url
            try:
                check_outbound_url(t.webhook_url)
            except OutboundURLError as exc:
                flash(str(exc), "danger")
                db.session.rollback()
                return redirect(url_for("admin.tenant_settings"))
        audit("tenant_settings", t.name)
        db.session.commit()
        flash("Definições guardadas.", "success")
        return redirect(url_for("admin.tenant_settings"))
    return render_template("admin/settings.html", t=t, branding=_branding)


@bp.route("/audit")
@login_required
@roles_required("admin", "auditor")
def audit_log():
    q = AuditLog.query
    if not current_user.is_superadmin or session.get("tenant_id"):
        q = q.filter_by(tenant_id=require_tenant().id)
    if request.args.get("q"):
        q = q.filter(AuditLog.action.ilike(f"%{request.args['q']}%") | AuditLog.detail.ilike(f"%{request.args['q']}%"))
    pag = q.order_by(AuditLog.id.desc()).paginate(page=request.args.get("page", 1, type=int), per_page=100, error_out=False)
    return render_template("admin/audit.html", pag=pag)


def _certs(cfg) -> list[dict]:
    out = []
    for profile, port in (("console", cfg["PORT"]), ("agent", cfg["AGENT_PORT"])):
        try:
            cert, _, _ = tls.paths(cfg, profile)
            if cert.is_file():
                out.append({**tls.info(cert), "profile": tls.PROFILES[profile]["label"], "port": port})
        except Exception:  # noqa: BLE001
            continue
    return out


@bp.route("/system")
@login_required
@superadmin_required
def system():
    cfg = current_app.config
    return render_template("admin/system.html", ansible=ansible_runner.available(), ansible_bin=ansible_runner.binary(),
                           ansible_dir=cfg["ANSIBLE_DIR"], intel=intel.stats(), cfg=cfg, certs=_certs(cfg),
                           worker=current_app.extensions.get("omxpatch_worker"), vinfo=versioninfo.read(cfg))


# --------------------------------------------------------------------------- capacidade, configuração e reinício


@bp.route("/system/capacity", methods=["GET", "POST"])
@login_required
@superadmin_required
def capacity_page():
    from ..engine import backup as backup_mod, capacity
    from .. import migrations
    if request.method == "POST":
        if not request.form.get("confirm_ok"):
            flash("Confirme a caixa «OK»: o teste cria agentes simulados e carrega o servidor durante alguns segundos.", "danger")
        elif capacity.start_benchmark(current_app._get_current_object(), (current_tenant() or Tenant.query.filter_by(active=True).first()).id,
                                      request.form.get("agents", type=int) or 50,
                                      request.form.get("seconds", type=int) or 10):
            audit("capacity_benchmark", f"{request.form.get('agents')} agentes, {request.form.get('seconds')} s")
            db.session.commit()
            flash("Teste de carga iniciado: atualize a página dentro de alguns segundos.", "info")
        else:
            flash("Já existe um teste de carga em curso.", "warning")
        return redirect(url_for("admin.capacity_page"))
    snap = capacity.snapshot(current_app)
    est = capacity.estimate(snap)
    return render_template("admin/capacity.html", snap=snap, est=est, recs=capacity.recommendations(snap, est), bench=capacity.bench_status(),
                           max_agents=capacity.BENCH_MAX_AGENTS, max_seconds=capacity.BENCH_MAX_SECONDS,
                           backups=backup_mod.listing(current_app.config), migrations=migrations.status())


@bp.route("/system/backup", methods=["POST"])
@login_required
@superadmin_required
def backup_now():
    from ..engine import backup
    if not request.form.get("confirm_ok"):
        flash("Confirme a caixa «OK» para criar a cópia.", "danger")
    else:
        try:
            res = backup.create(current_app)
            audit("backup_created", f"{Path(res['file']).name} ({res['size']} bytes)")
            db.session.commit()
            flash(f"Cópia criada: {Path(res['file']).name}. Contém chaves privadas: guarde-a cifrada e fora do servidor.", "success")
        except Exception as exc:  # noqa: BLE001
            flash(f"Cópia falhou: {exc}", "danger")
    return redirect(url_for("admin.capacity_page"))


@bp.route("/system/capacity.json")
@login_required
@superadmin_required
def capacity_json():
    from ..engine import capacity
    snap = capacity.snapshot(current_app)
    est = capacity.estimate(snap)
    return jsonify({"snapshot": snap, "estimate": est, "recommendations": capacity.recommendations(snap, est), "benchmark": capacity.bench_status()})


@bp.route("/system/settings", methods=["GET", "POST"])
@login_required
@superadmin_required
def system_settings_page():
    """Alterar configuração em dois passos: pré-visualizar (diferenças, o que exige reinício) → OK → gravar."""
    from ..engine import settings as st
    preview, errors = None, []
    if request.method == "POST":
        raw = {k[4:]: v for k, v in request.form.items() if k.startswith("val_")}
        clean, errors = st.validate(raw)
        errors += st.cross_checks(current_app, clean)
        if request.form.get("action") == "revert":
            if request.form.get("confirm_ok") and st.revert_last(current_app):
                audit("settings_reverted", "")
                db.session.commit()
                flash("Cópia de segurança anterior reposta. Reinicie para aplicar o que exigir reinício.", "success")
                return redirect(url_for("admin.system_settings_page"))
            flash("Confirme a caixa «OK» para repor a versão anterior.", "danger")
        elif not errors:
            changes = st.diff(current_app, clean)
            if request.form.get("action") == "apply":
                if not request.form.get("confirm_ok"):
                    flash("Confirme a caixa «OK» para gravar.", "danger")
                else:
                    res = st.apply(current_app, clean)
                    audit("settings_changed", ", ".join(f"{c['key']}={c['new']}" for c in changes)[:480])
                    db.session.commit()
                    flash(f"{res['changed']} parâmetro(s) gravado(s)." + (f" Exigem reinício: {', '.join(res['restart_needed'])}." if res["restart_needed"] else ""), "success")
                    return redirect(url_for("admin.system_settings_page"))
            preview = changes
    return render_template("admin/system_settings.html", rows=st.current(current_app), preview=preview, errors=errors, history=st.history(current_app),
                           supervised=st.supervised(), overrides_error=current_app.config.get("OVERRIDES_ERROR"))


@bp.route("/system/restart", methods=["POST"])
@login_required
@superadmin_required
def restart_service():
    from ..engine import settings as st
    if not request.form.get("confirm_ok"):
        flash("Confirme a caixa «OK» para reiniciar o serviço.", "danger")
        return redirect(url_for("admin.system_settings_page"))
    res = st.request_restart(current_app, current_user.email)
    if not res["ok"]:
        flash("Reinício recusado — a configuração não arrancaria: " + "; ".join(res["errors"]), "danger")
    else:
        audit("service_restart", f"por {current_user.email} ({res['mode']})")
        db.session.commit()
        flash("Reinício em curso: a consola fica indisponível alguns segundos. Os agentes voltam a ligar-se sozinhos."
              + ("" if res["supervised"] else " Sem supervisor (systemd/serviço): o processo relança-se a si próprio."), "info")
    return redirect(url_for("admin.system"))


# --------------------------------------------------------------------------- integrações


@bp.route("/integrations")
@login_required
@roles_required("admin")
def integrations():
    tenant = require_tenant()
    rows = {c.kind: c for c in Connector.query.filter_by(tenant_id=tenant.id)}
    return render_template("admin/integrations.html", groups=GROUPS, kinds=KINDS, rows=rows)


@bp.route("/integrations/<kind>", methods=["GET", "POST"])
@login_required
@roles_required("admin")
def integration_edit(kind: str):
    if kind not in KINDS:
        abort(404)
    tenant = require_tenant()
    spec = KINDS[kind]
    c = Connector.query.filter_by(tenant_id=tenant.id, kind=kind).first()
    if request.method == "POST":
        f = request.form
        url = f.get("base_url", "").strip()
        if url and not re.match(r"^(https?|ldaps?)://", url):
            flash("O endereço tem de começar por https:// (ou http://, ldap://).", "danger")
        else:
            if url.startswith("http"):
                from ..security import OutboundURLError, check_outbound_url
                try:
                    check_outbound_url(url)
                except OutboundURLError as exc:
                    flash(str(exc), "danger")
                    return render_template("admin/integration_form.html", kind=kind, spec=spec, c=c), 400
            opts = {k: f.get(f"opt_{k}", "").strip() for k in spec["options"]}
            c = cstore.save(tenant.id, kind, url, f.get("username", ""), {k: f.get(f"secret_{k}", "") for k in spec["secrets"]},
                            opts, bool(f.get("verify_tls")), bool(f.get("enabled")))
            audit("integration_saved", kind)
            db.session.commit()
            flash("Integração guardada.", "success")
            return redirect(url_for("admin.integrations"))
    return render_template("admin/integration_form.html", kind=kind, spec=spec, c=c)


@bp.route("/integrations/omxvuln/import", methods=["GET", "POST"])
@login_required
@roles_required("admin")
def omxvuln_import():
    """Importação do OMXVuln em dois passos: simular (nada é gravado) → confirmar."""
    tenant = require_tenant()
    report, error = None, None
    if request.method == "POST":
        what = request.form.get("what", "both")
        apply_ = request.form.get("mode") == "apply"
        if apply_ and not request.form.get("confirm_ok"):
            flash("Confirme a caixa «OK» para importar.", "danger")
        else:
            try:
                report = omxvuln.sync(tenant, what, dry_run=not apply_)
                audit("omxvuln_import" if apply_ else "omxvuln_import_simulated", f"{what}: {report.get('new_assets', 0)} ativos novos, {report.get('new_exposures', 0)} exposições novas")
                db.session.commit()
                if apply_:
                    flash("Importação concluída.", "success")
            except Exception as exc:  # noqa: BLE001 - mostra o erro ao administrador
                db.session.rollback()
                error = str(exc)
    return render_template("admin/omxvuln_import.html", report=report, error=error, what=request.form.get("what", "both"),
                           configured=cstore.effective(tenant.id, "omxvuln") is not None)


@bp.route("/integrations/<kind>/<action>", methods=["POST"])
@login_required
@roles_required("admin")
def integration_action(kind: str, action: str):
    tenant = require_tenant()
    c = cstore.effective(tenant.id, kind, ) if kind in ("omxvuln", "omxgrc") else Connector.query.filter_by(tenant_id=tenant.id, kind=kind).first()
    if c is None:
        flash("Integração não configurada.", "danger")
        return redirect(url_for("admin.integrations"))
    try:
        group = KINDS[kind]["group"]
        if action == "test":
            ok, detail = (omxvuln.test(c) if kind == "omxvuln" else omxgrc.test(c) if kind == "omxgrc" else outbound.test(c))
            if c.id:
                c.last_ok, c.last_detail, c.last_sync_at = ok, detail, utcnow()
            flash(("Ligação OK: " if ok else "Falhou: ") + detail, "success" if ok else "danger")
        elif action == "sync":
            if kind == "omxvuln":
                res = omxvuln.pull_findings(tenant)
                flash(f"OMXVuln: {res['findings']} findings, {res['new_assets']} ativos novos, {res['new_exposures']} exposições novas.", "success")
            elif kind == "omxgrc":
                flash("Métricas enviadas ao OMXGRC." if omxgrc.push_metrics(tenant) else "Envio ao OMXGRC falhou.", "info")
            elif group == "discovery":
                res = discovery.run(c, tenant)
                flash(f"Descoberta: {res['found']} ativos ({res['new']} novos).", "success")
            elif group in ("edr", "vm", "cspm", "fw"):
                res = signals_mod.pull(c, tenant)
                sync.apply_signals(tenant)
                flash(f"{res['new']} novos sinais.", "success")
            else:
                flash("Sem ação de sincronização para este tipo.", "info")
        elif action == "delete" and c.id:
            db.session.delete(c)
            flash("Integração removida.", "info")
        audit(f"integration_{action}", kind)
        db.session.commit()
    except (ConnectorError, Exception) as exc:  # noqa: BLE001 - mostra o erro ao administrador
        db.session.rollback()
        flash(f"Erro: {exc}", "danger")
    return redirect(url_for("admin.integrations"))


# --------------------------------------------------------------------------- agentes


@bp.route("/agents")
@login_required
@roles_required("admin", "auditor", "user")
def agents():
    tenant = require_tenant()
    return render_template("admin/agents.html", agents=scoped(Agent).order_by(Agent.last_seen.desc().nullslast()).all(),
                           tokens=scoped(EnrollmentToken).order_by(EnrollmentToken.id.desc()).all(),
                           new_token=session.pop("new_enroll", None), base_url=current_app.config["AGENT_BASE_URL"],
                           agent_pin=agent_pin(), agent_cert=agent_cert_info(), server_ip=current_app.config["AGENT_SERVER_IP"],
                           address_mode=current_app.config["AGENT_ADDRESS_MODE"],
                           offline=current_app.config["AGENT_OFFLINE_MINUTES"], tenant=tenant, console_version=versioninfo.__version__)


def agent_cert_info() -> dict:
    """Certificado do servidor de agentes: impressões digitais SHA-256 e SHA-1 (o «Thumbprint» do Windows) e IPs no SAN."""
    cfg = current_app.config
    if not cfg["TLS_ENABLED"]:
        return {}
    try:
        cert, _, _ = tls.paths(cfg, "agent")
        return tls.info(cert) if cert.is_file() else tls.ensure(cfg, profile="agent")
    except Exception:  # noqa: BLE001
        return {}


def agent_pin() -> str:
    """Impressão digital SHA-256 do certificado do servidor de agentes (omxpatchcli.oramix.local)."""
    return agent_cert_info().get("sha256", "")


@bp.route("/agents/script", methods=["POST"])
@login_required
@roles_required("admin")
def agent_script():
    """Gera o script de auto-instalação (Windows/Linux/macOS) para a organização ativa, com um novo token de registo."""
    from datetime import datetime
    from urllib.parse import urlsplit
    tenant = require_tenant()
    f = request.form
    os_kind = f.get("os", "")
    if os_kind not in installers.OS_KINDS:
        abort(400, description="Sistema operativo inválido")
    ring = f.get("ring", type=int)
    ring = ring if ring in (0, 1, 2, 3, 4) else 4
    cfg = current_app.config
    raw, tok = new_enrollment_token(tenant, f"script-{os_kind}", ring, min(f.get("days", type=int) or 7, 365), f.get("max_uses", type=int) or 0)
    host = urlsplit(cfg["AGENT_BASE_URL"]).hostname or ""
    try:
        name, body = installers.render(os_kind, url=cfg["AGENT_BASE_URL"], pin=agent_pin(), token=raw, tenant_name=tenant.name,
                                       host=host, server_ip=cfg["AGENT_SERVER_IP"], when=datetime.now().strftime("%Y-%m-%d %H:%M"))
    except ValueError as exc:
        db.session.rollback()
        flash(f"Não foi possível gerar o script: {exc}", "danger")
        return redirect(url_for("admin.agents"))
    audit("agent_script_generated", f"{os_kind}, anel {ring}, token {tok.prefix}…")
    db.session.commit()
    from flask import Response
    return Response(_with_bom(name, body), mimetype="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})


def _with_bom(name: str, body: str) -> bytes:
    """Os .ps1 levam BOM UTF-8: sem ele o Windows PowerShell 5.1 lê o ficheiro como ANSI e estraga os acentos."""
    return (b"\xef\xbb\xbf" if name.endswith(".ps1") else b"") + body.encode("utf-8")


@bp.route("/agents/uninstall/<os_kind>")
@login_required
@roles_required("admin")
def agent_uninstall_script(os_kind: str):
    try:
        name, body = installers.render_uninstall(os_kind)
    except ValueError:
        abort(404)
    from flask import Response
    return Response(_with_bom(name, body), mimetype="text/plain; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{name}"'})


@bp.route("/agents/<int:agent_id>/delete", methods=["POST"])
@login_required
@roles_required("admin")
def agent_delete(agent_id: int):
    ag = get_scoped_or_404(Agent, agent_id)
    audit("agent_deleted", ag.hostname)
    agentops.delete_agent(ag)
    db.session.commit()
    flash("Agente eliminado (o equipamento fica livre para ser registado noutra organização).", "info")
    return redirect(url_for("admin.agents"))


@bp.route("/agents/tokens", methods=["POST"])
@login_required
@roles_required("admin")
def agent_token_new():
    f = request.form
    raw, tok = new_enrollment_token(require_tenant(), f.get("name") or "ansible", f.get("ring", type=int) if f.get("ring") != "" else 4,
                                    min(f.get("days", type=int) or 30, 365), f.get("max_uses", type=int) or 0)
    audit("enrollment_token_created", tok.name)
    db.session.commit()
    session["new_enroll"] = raw
    return redirect(url_for("admin.agents"))


@bp.route("/agents/tokens/<int:token_id>/revoke", methods=["POST"])
@login_required
@roles_required("admin")
def agent_token_revoke(token_id: int):
    tok = get_scoped_or_404(EnrollmentToken, token_id)
    tok.revoked = True
    audit("enrollment_token_revoked", tok.name)
    db.session.commit()
    return redirect(url_for("admin.agents"))


@bp.route("/agents/<int:agent_id>/revoke", methods=["POST"])
@login_required
@roles_required("admin")
def agent_revoke(agent_id: int):
    ag = get_scoped_or_404(Agent, agent_id)
    ag.revoked = True
    audit("agent_revoked", ag.hostname)
    db.session.commit()
    return redirect(url_for("admin.agents"))


# --------------------------------------------------------------------------- operação remota e registos de cada agente


def _agent_log_query(ag: Agent):
    q = AgentLog.query.filter(AgentLog.agent_id == ag.id, AgentLog.tenant_id == ag.tenant_id)
    a = request.args
    if a.get("kind") in agentops.KINDS:
        q = q.filter(AgentLog.kind == a["kind"])
    if a.get("level") in agentops.LEVELS:
        q = q.filter(AgentLog.level == a["level"])
    if a.get("q"):
        q = q.filter(AgentLog.message.ilike(f"%{a['q'][:80]}%"))
    return q


@bp.route("/agents/<int:agent_id>")
@login_required
@roles_required("admin", "auditor", "user")
def agent_detail(agent_id: int):
    ag = get_scoped_or_404(Agent, agent_id)
    page = max(1, request.args.get("page", 1, type=int))
    logs = _agent_log_query(ag).order_by(AgentLog.ts.desc(), AgentLog.id.desc()).offset((page - 1) * 100).limit(100).all()
    from ..models import Task
    cmds = Task.query.filter(Task.tenant_id == ag.tenant_id, Task.asset_id == ag.asset_id, Task.type == "agent_ctl").order_by(Task.id.desc()).limit(8).all() if ag.asset_id else []
    return render_template("admin/agent_detail.html", ag=ag, logs=logs, page=page, cmds=cmds, actions=agentops.ACTIONS, now=utcnow(),
                           offline=current_app.config["AGENT_OFFLINE_MINUTES"], heartbeat=current_app.config["AGENT_HEARTBEAT_SECONDS"],
                           giveup=current_app.config["AGENT_GIVEUP_MINUTES"], debug_default=current_app.config["AGENT_DEBUG_DEFAULT_MINUTES"])


@bp.route("/agents/<int:agent_id>/command", methods=["POST"])
@login_required
@roles_required("admin")
def agent_command(agent_id: int):
    ag = get_scoped_or_404(Agent, agent_id)
    action = request.form.get("action", "")
    if action not in agentops.ACTIONS:
        abort(400)
    if ag.revoked:
        flash("Agente revogado.", "danger")
        return redirect(url_for("admin.agent_detail", agent_id=ag.id))
    agentops.command(ag, action, current_user, request.form.get("minutes", type=int))
    audit("agent_command", f"{ag.hostname}: {action}")
    db.session.commit()
    hb = max(1, int(current_app.config["AGENT_HEARTBEAT_SECONDS"]) // 60)
    flash(f"«{agentops.ACTIONS[action]}» pedido: o agente aplica-o no próximo contacto (até ~{hb} min).", "info")
    return redirect(url_for("admin.agent_detail", agent_id=ag.id))


@bp.route("/agents/<int:agent_id>/logs.csv")
@login_required
@roles_required("admin", "auditor")
def agent_logs_csv(agent_id: int):
    import csv
    import io
    from flask import Response
    ag = get_scoped_or_404(Agent, agent_id)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ts_utc", "origem", "tipo", "nivel", "mensagem"])
    for r in _agent_log_query(ag).order_by(AgentLog.ts.desc(), AgentLog.id.desc()).limit(20000):
        w.writerow([r.ts.isoformat(), r.source, r.kind, r.level, ("'" + r.message) if r.message[:1] in "=+-@" else r.message])
    audit("agent_logs_export", ag.hostname)
    db.session.commit()
    return Response(buf.getvalue(), mimetype="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="agente-{ag.hostname}-registos.csv"'})


@bp.route("/agents/purge-revoked", methods=["POST"])
@login_required
@roles_required("admin")
def agents_purge_revoked():
    """Elimina as entradas de agentes revogados (p.ex. as antigas, de reinstalações anteriores à 1.22)."""
    rows = scoped(Agent).filter(Agent.revoked.is_(True)).all()
    for ag in rows:
        agentops.delete_agent(ag)
    audit("agents_purged", f"{len(rows)} agente(s) revogado(s)")
    db.session.commit()
    flash(f"{len(rows)} entrada(s) de agentes revogados eliminada(s).", "info")
    return redirect(url_for("admin.agents"))
