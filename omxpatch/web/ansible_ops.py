"""Motor Ansible sem agente: atualização completa de SO e software, CyberArk e avaliação de equipamentos de rede."""
from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..connectors import store
from ..engine import ansible_engine as eng, ansible_runner
from ..extensions import db
from ..models import CREDENTIAL_KINDS, NET_PLATFORMS, AnsibleCredential, Asset, NetBaseline, NetworkAssessment, Task
from ..security import audit, get_scoped_or_404, require_tenant, roles_required, scoped
from .common import tenant_or_select

bp = Blueprint("ansible_ops", __name__)


@bp.route("/ansible")
@login_required
def index():
    if (r := tenant_or_select()) is not None:
        return r
    require_tenant()
    assets = scoped(Asset).filter(Asset.connection == "ansible").order_by(Asset.name).all()
    jobs = scoped(Task).filter(Task.type.in_(eng.TASK_TYPES)).order_by(Task.id.desc()).limit(40).all()
    return render_template("ansible/index.html", assets=assets, jobs=jobs, ops=eng.OPERATIONS, eligible=eng.eligible, available=ansible_runner.available(),
                           word=eng.CONFIRM_WORD, now_fresh=eng.APPLY_FRESHNESS)


@bp.route("/ansible/run", methods=["POST"])
@login_required
@roles_required("admin", "user")
def run():
    tenant = require_tenant()
    f = request.form
    op, mode = f.get("op", ""), f.get("mode", "assess")
    if mode == "apply" and not current_user.can_manage:
        abort(403)
    ids = [int(i) for i in f.getlist("asset_ids") if i.isdigit()]
    options = {"confirm_ok": bool(f.get("confirm_ok")), "reboot_policy": f.get("reboot_policy"), "security_only": bool(f.get("security_only")),
               "target_version": f.get("target_version"), "media_src": f.get("media_src"), "media_sha256": f.get("media_sha256"),
               "upgrade_cmd": f.get("upgrade_cmd"), "post_cmd": f.get("post_cmd"), "confirm_word": f.get("confirm_word")}
    try:
        tasks = eng.create_job(tenant, current_user, op, ids, mode, options)
    except eng.EngineError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("ansible_ops.index"))
    audit("ansible_job", f"{op}/{mode}: {len(tasks)} ativo(s) por {current_user.email}")
    db.session.commit()
    flash(f"{len(tasks)} tarefa(s) criada(s) ({'aplicar' if mode == 'apply' else 'avaliar'}). O worker executa-as em segundo plano; o resultado fica em «Trabalhos».", "info")
    return redirect(url_for("ansible_ops.index"))


@bp.route("/ansible/jobs/<int:task_id>")
@login_required
def job(task_id: int):
    t = get_scoped_or_404(Task, task_id)
    if t.type not in eng.TASK_TYPES:
        abort(404)
    return render_template("ansible/job.html", t=t, result=t.result_data, payload=t.payload_data, ops=eng.OPERATIONS)


@bp.route("/ansible/jobs/<int:task_id>/cancel", methods=["POST"])
@login_required
@roles_required("admin")
def job_cancel(task_id: int):
    t = get_scoped_or_404(Task, task_id)
    if t.type in eng.TASK_TYPES and t.status in ("queued", "waiting_dep", "pending"):
        t.status = "cancelled"
        audit("ansible_job_cancelled", f"#{t.id}")
        db.session.commit()
    return redirect(url_for("ansible_ops.index"))


# --------------------------------------------------------------------------- credenciais


@bp.route("/ansible/credentials", methods=["GET", "POST"])
@login_required
@roles_required("admin")
def credentials():
    tenant = require_tenant()
    if request.method == "POST":
        f = request.form
        kind = f.get("kind", "")
        name = f.get("name", "").strip()[:120]
        if kind not in CREDENTIAL_KINDS or not name:
            flash("Nome e tipo são obrigatórios.", "danger")
            return redirect(url_for("ansible_ops.credentials"))
        secret = {"password": {"password": f.get("password", "")}, "ssh_key": {"ssh_key": f.get("ssh_key", ""), "passphrase": f.get("passphrase", "")},
                  "api_token": {"api_token": f.get("api_token", "")}}[kind]
        if not any(secret.values()):
            flash("Indique o segredo (palavra-passe, chave ou token).", "danger")
            return redirect(url_for("ansible_ops.credentials"))
        if kind == "ssh_key" and "PRIVATE KEY" not in secret["ssh_key"]:
            flash("A chave SSH tem de estar em formato PEM/OpenSSH (BEGIN … PRIVATE KEY).", "danger")
            return redirect(url_for("ansible_ops.credentials"))
        c = AnsibleCredential(tenant_id=tenant.id, name=name, kind=kind, username=f.get("username", "").strip()[:120], secret=store.encrypt_json(secret),
                              become_password=bool(f.get("become_password")))
        db.session.add(c)
        audit("ansible_credential_created", f"{name} ({kind})")          # o segredo nunca vai para a auditoria
        db.session.commit()
        flash("Credencial guardada (cifrada).", "success")
        return redirect(url_for("ansible_ops.credentials"))
    return render_template("ansible/credentials.html", creds=scoped(AnsibleCredential).order_by(AnsibleCredential.name).all(), kinds=CREDENTIAL_KINDS)


@bp.route("/ansible/credentials/<int:cid>/delete", methods=["POST"])
@login_required
@roles_required("admin")
def credential_delete(cid: int):
    c = get_scoped_or_404(AnsibleCredential, cid)
    if Asset.query.filter_by(credential_id=c.id).first():
        flash("A credencial está em uso por ativos: retire-a deles primeiro.", "danger")
    else:
        audit("ansible_credential_deleted", c.name)
        db.session.delete(c)
        db.session.commit()
    return redirect(url_for("ansible_ops.credentials"))


# --------------------------------------------------------------------------- avaliação de rede


@bp.route("/network")
@login_required
def network():
    if (r := tenant_or_select()) is not None:
        return r
    tenant = require_tenant()
    devices = scoped(Asset).filter(Asset.platform != "", Asset.platform.isnot(None)).order_by(Asset.name).all()
    last = {}
    for a in NetworkAssessment.query.filter_by(tenant_id=tenant.id).order_by(NetworkAssessment.id):
        last[a.asset_id] = a
    return render_template("ansible/network.html", devices=devices, last=last, baselines=scoped(NetBaseline).order_by(NetBaseline.platform, NetBaseline.model_glob).all(),
                           platforms=NET_PLATFORMS)


@bp.route("/network/baseline", methods=["POST"])
@login_required
@roles_required("admin")
def baseline_save():
    tenant = require_tenant()
    f = request.form
    if f.get("platform") not in NET_PLATFORMS:
        abort(400)
    b = NetBaseline(tenant_id=tenant.id, platform=f["platform"], model_glob=(f.get("model_glob") or "*").strip()[:120], min_version=f.get("min_version", "").strip()[:60],
                    recommended=f.get("recommended", "").strip()[:60], eol_below=f.get("eol_below", "").strip()[:60], notes=f.get("notes", "").strip()[:500])
    db.session.add(b)
    audit("net_baseline_created", f"{b.platform} {b.model_glob}")
    db.session.commit()
    return redirect(url_for("ansible_ops.network"))


@bp.route("/network/baseline/<int:bid>/delete", methods=["POST"])
@login_required
@roles_required("admin")
def baseline_delete(bid: int):
    b = get_scoped_or_404(NetBaseline, bid)
    db.session.delete(b)
    audit("net_baseline_deleted", f"{b.platform} {b.model_glob}")
    db.session.commit()
    return redirect(url_for("ansible_ops.network"))
