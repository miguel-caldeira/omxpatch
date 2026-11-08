"""Linha de comandos do OMXPatch (também é o ponto de entrada do executável compilado).

    omxpatch serve   [--host H] [--port 4434] [--agent-port 4444] [--prefix /omxpatch] [--no-worker] [--no-tls]
    omxpatch worker
    omxpatch tls     info|generate [--hostname omxpatch.oramix.local] [--days 730]
    omxpatch init    --email admin@exemplo.pt [--password ...] [--tenant "Empresa"]
    omxpatch create-tenant --name "Empresa" --admin-email a@b.pt
    omxpatch reset-admin [--email admin@omxpatch.local] [--reset-mfa]
    omxpatch initial-password
    omxpatch check
    omxpatch intel-sync | correlate --tenant slug
    omxpatch import-intel ficheiro.json
    omxpatch agent-token --tenant slug [--ring 4] [--days 30] [--name ansible]
    omxpatch ansible-vars --tenant slug      (variáveis para os playbooks de instalação dos agentes)
"""
from __future__ import annotations

import argparse
import getpass
import os
import secrets
import signal
import sys
import threading
from pathlib import Path


def _app(start_worker=False, **overrides):
    from .app import create_app
    return create_app(overrides or None, start_worker=start_worker)


def _port_free(host: str, port: int) -> bool:
    import socket
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def port_guard(app, mode: str, prefix: str = ""):
    """Separa as duas portas: a **consola** (4434) não serve ``/agent/``; a porta dos **agentes** (4444) só serve ``/agent/``
    (e ``/healthz``) — o ambiente gráfico nunca fica exposto aos postos clientes e vice-versa."""
    def wsgi(environ, start_response):
        path = environ.get("PATH_INFO", "")
        if prefix and (path == prefix or path.startswith(prefix + "/")):
            path = path[len(prefix):] or "/"
        is_agent = path.startswith("/agent/")
        if (mode == "console" and is_agent) or (mode == "agent" and not (is_agent or path == "/healthz")):
            body = b'{"error": "Nao encontrado"}'
            start_response("404 Not Found", [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
            return [body]
        return app(environ, start_response)
    return wsgi


def cmd_serve(args) -> int:
    from .config import load_config
    overrides = {}
    if args.prefix is not None:
        overrides["URL_PREFIX"] = args.prefix
    if args.port:
        overrides["PORT"] = args.port
    if args.agent_port:
        overrides["AGENT_PORT"] = args.agent_port
    base = load_config(overrides)
    platform_port = os.environ.get("HTTP_PLATFORM_PORT")
    use_tls = bool(base["TLS_ENABLED"]) and not args.no_tls and not platform_port
    if use_tls:
        overrides["TRUSTED_PROXIES"] = 0
        overrides["SESSION_COOKIE_SECURE"] = True
    if args.no_tls:
        overrides["TLS_ENABLED"] = False
    app = _app(start_worker=False, **overrides)
    cfg = app.config
    host = args.host or cfg["HOST"] or ("0.0.0.0" if use_tls else "127.0.0.1")  # nosec B104
    port = int(platform_port or cfg["PORT"])
    agent_port = int(cfg["AGENT_PORT"])
    from . import admin_reset
    admin_reset.on_startup(app, log=lambda m: print(m, flush=True))
    admin_reset.ensure_primary(app, log=lambda m: print(m, flush=True))
    if cfg["EMBEDDED_WORKER"] and not args.no_worker:
        from .worker import Worker
        app.extensions["omxpatch_worker"] = Worker(app)
        app.extensions["omxpatch_worker"].start()
    prefix = cfg["URL_PREFIX"]
    console_app, agent_app = port_guard(app, "console", prefix), port_guard(app, "agent", prefix)
    threads, maxbody = int(cfg["THREADS"]), int(cfg["MAX_CONTENT_LENGTH"]) + 1024 * 1024
    run_agents = not platform_port                      # atrás do IIS (HttpPlatformHandler) só existe a porta de gestão
    stoppers = []
    if not use_tls:
        from waitress import create_server
        console = create_server(console_app, host=host, port=port, threads=threads, ident="OMXPatch", max_request_body_size=maxbody,
                                clear_untrusted_proxy_headers=not int(cfg["TRUSTED_PROXIES"]))
        print(f"OMXPatch — consola em http://{host}:{port}{prefix or '/'}  (dados: {cfg['DATA_DIR']})", flush=True)
        if run_agents:
            agents = create_server(agent_app, host=host, port=agent_port, threads=threads, ident="OMXPatch-Agent",
                                   max_request_body_size=maxbody, clear_untrusted_proxy_headers=not int(cfg["TRUSTED_PROXIES"]))
            print(f"OMXPatch — agentes em http://{host}:{agent_port}/agent/v1", flush=True)
            threading.Thread(target=agents.run, daemon=True, name="omxpatch-agents").start()
            stoppers.append(agents.close)
        try:
            console.run()
        except KeyboardInterrupt:
            pass
        finally:
            for st in stoppers:
                st()
        return 0
    from cheroot import wsgi
    from cheroot.ssl.builtin import BuiltinSSLAdapter

    from . import tls

    def make(profile: str, application, listen_port: int, name: str):
        cert = tls.ensure(cfg, log=lambda m: print(m, flush=True), profile=profile)
        cert_path, key_path, _ = tls.paths(cfg, profile)
        adapter = BuiltinSSLAdapter(str(cert_path), str(key_path))
        adapter.context = tls.context(cfg, profile)
        srv = wsgi.Server((host, listen_port), application, numthreads=threads, server_name=name, max=-1, request_queue_size=64,
                          timeout=60, shutdown_timeout=10, accepted_queue_timeout=10)
        srv.max_request_body_size = maxbody
        srv.ssl_adapter = adapter
        return srv, cert

    console, ccert = make("console", console_app, port, "OMXPatch")
    print(f"OMXPatch — consola de gestão em https://{host}:{port}{prefix or '/'}  (acesso: https://{cfg['TLS_HOSTNAME']}:{port}/; "
          f"TLS ≥ {cfg.get('TLS_MIN_VERSION', '1.2')}; dados: {cfg['DATA_DIR']})", flush=True)
    print(f"  Certificado da consola ({cfg['TLS_HOSTNAME']}) válido até {ccert['not_after']:%Y-%m-%d}; SHA-256 {ccert['sha256']}", flush=True)
    if run_agents:
        agents, acert = make("agent", agent_app, agent_port, "OMXPatch-Agent")
        print(f"OMXPatch — agentes → consola em https://{host}:{agent_port}/agent/v1  (nome: {cfg['AGENT_TLS_HOSTNAME']})", flush=True)
        print(f"  Certificado dos agentes válido até {acert['not_after']:%Y-%m-%d}; SHA-256 {acert['sha256']}", flush=True)
        threading.Thread(target=agents.start, daemon=True, name="omxpatch-agents").start()
        stoppers.append(agents.stop)

    def _terminate(*_):
        raise KeyboardInterrupt

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _terminate)
    try:
        console.start()
    except KeyboardInterrupt:
        pass
    finally:
        console.stop()
        for st in stoppers:
            st()
    return 0


def cmd_tls(args) -> int:
    """Certificados TLS: consola (omxpatch.oramix.local, porta 4434) e agentes (omxpatchcli.oramix.local, porta 4444)."""
    from . import tls
    from .config import load_config
    cfg = load_config()
    if args.hostname:
        cfg["TLS_HOSTNAME"] = args.hostname
    if args.agent_hostname:
        cfg["AGENT_TLS_HOSTNAME"] = args.agent_hostname
    if args.days:
        cfg["TLS_DAYS"] = args.days
    for profile, port in (("console", cfg["PORT"]), ("agent", cfg["AGENT_PORT"])):
        data = tls.ensure(cfg, force=args.action == "generate", profile=profile)
        print(f"[{tls.PROFILES[profile]['label']} — porta {port}]\n  Certificado: {data['path']}\n  Nomes: {', '.join(data['dns'])}\n  IPs:   {', '.join(data['ips'])}")
        print(f"  Válido de {data['not_before']:%Y-%m-%d} a {data['not_after']:%Y-%m-%d} ({data['days_left']} dias)\n  SHA-256: {data['sha256']}")
    return 0


def cmd_capacity(args) -> int:
    """Estado de capacidade; com --benchmark corre antes o teste de carga (agentes simulados) na organização indicada."""
    import json as _json
    from .engine import capacity
    from .models import Tenant
    app = _app(start_worker=False)
    with app.app_context():
        if args.benchmark:
            tenant = Tenant.query.filter_by(slug=args.tenant).first() if args.tenant else Tenant.query.filter_by(active=True).first()
            if tenant is None:
                print("Organização não encontrada.", file=sys.stderr)
                return 2
            n, secs = max(1, min(args.agents, capacity.BENCH_MAX_AGENTS)), max(3, min(args.seconds, capacity.BENCH_MAX_SECONDS))
            print(f"Teste de carga: {n} agentes simulados durante {secs}s…", flush=True)
            capacity._bench_lock.acquire()
            capacity._run_benchmark(app, tenant.id, n, secs)
        snap = capacity.snapshot(app)
        est = capacity.estimate(snap)
        recs = capacity.recommendations(snap, est)
        if args.json:
            print(_json.dumps({"snapshot": snap, "estimate": est, "recommendations": recs}, indent=2, default=str))
        else:
            print(f"Agentes: {snap['fleet']['agents']} ({snap['fleet']['online']} online) · pico previsto {est['peak_rps']} req/s · capacidade {est['capacity_rps']} req/s "
                  f"({est['basis']}) · utilização {est['utilization']:.0%} · máx. ~{est['max_agents']} agentes")
            b = snap["benchmark"]
            if b:
                print(f"Último teste: {b['rps']} req/s, p95 {b['p95']} ms, {b['errors']} erros em {b['requests']} pedidos ({b['agents']} agentes, {b['engine']})")
            for r in recs:
                print(f"  [{r['level']}] {r['text']}")
    return 0


def cmd_backup(args) -> int:
    from .engine import backup
    app = _app(start_worker=False)
    with app.app_context():
        if args.action == "list":
            for b in backup.listing(app.config):
                print(f"{b['at']}  {b['size'] / 1048576:8.1f} MB  {b['name']}")
            return 0
        res = backup.create(app)
        print(f"Cópia criada: {res['file']} ({res['size'] / 1048576:.1f} MB, {res['engine']}); {res['pruned']} antiga(s) removida(s).")
        print("AVISO: contém chaves privadas e a chave de sessão — guarde-a cifrada e fora deste servidor.")
    return 0


def cmd_restore(args) -> int:
    """Repõe uma cópia (serviço parado)."""
    from .config import load_config
    from .engine import backup
    cfg = load_config()
    try:
        res = backup.restore(args.file, cfg["DATA_DIR"], force=args.force)
    except (ValueError, FileExistsError, OSError) as exc:
        print(f"Não foi possível restaurar: {exc}", file=sys.stderr)
        return 2
    print(f"Cópia reposta em {res['restored']}. Arranque o serviço de novo.")
    return 0


def cmd_db(args) -> int:
    from . import migrations
    app = _app(start_worker=False)
    with app.app_context():
        if args.action == "upgrade":
            done = migrations.upgrade(backup_dir=Path(app.config["DATA_DIR"]) / "backups")
            print("Migrações aplicadas: " + (", ".join(done) or "nenhuma (já está atualizado)"))
        st = migrations.status()
        print(f"Aplicadas: {len(st['applied'])} · pendentes: {', '.join(st['pending']) or 'nenhuma'} · última: {st['latest']}")
    return 0


def cmd_signing(args) -> int:
    from . import signing
    app = _app(start_worker=False)
    if args.action == "rotate":
        res = signing.rotate(app.config)
        print(f"Chave de assinatura rodada. Atual: {res['current']}  (a anterior continua publicada: {res['previous']})")
        print("Os agentes adotam a nova lista no contacto seguinte; só depois remova task.prev.pub.")
    else:
        for i, k in enumerate(signing.public_keys(app.config)):
            print(("atual   " if i == 0 else "anterior"), k)
    return 0


def cmd_worker(args) -> int:
    from .worker import Worker
    app = _app(start_worker=False)
    worker = Worker(app)
    stop = threading.Event()

    def _stop(*_):
        worker.stop()
        stop.set()

    signal.signal(signal.SIGINT, _stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _stop)
    worker.start()
    print("Worker OMXPatch em execução (Ctrl+C para terminar)", flush=True)
    while not stop.is_set():
        stop.wait(1)
    return 0


def _slug(name: str) -> str:
    import re
    return re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")[:64]


def _password(args) -> str:
    from .security import password_problems
    pw = args.password or getpass.getpass("Password: ")
    app = _app()
    with app.test_request_context():
        problems = password_problems(pw)
    if problems:
        sys.exit("Password fraca: " + "; ".join(problems))
    return pw


def cmd_init(args) -> int:
    from datetime import date, timedelta

    from .engine import rings
    from .extensions import db
    from .models import Tenant, User
    app = _app()
    with app.app_context():
        if User.query.filter(db.func.lower(User.email) == args.email.lower()).first():
            print("Utilizador já existe.")
            return 1
        u = User(email=args.email.lower(), name="Super-administrador", role="admin", is_superadmin=True)
        u.set_password(_password(args))
        db.session.add(u)
        if args.tenant and not Tenant.query.filter_by(slug=_slug(args.tenant)).first():
            t = Tenant(name=args.tenant, slug=_slug(args.tenant), license_expires_on=date.today() + timedelta(days=365))
            db.session.add(t)
            db.session.flush()
            rings.ensure_policies(t)
        db.session.commit()
        print(f"Super-administrador {args.email} criado. Base de dados: {app.config['SQLALCHEMY_DATABASE_URI']}")
    return 0


def cmd_create_tenant(args) -> int:
    from datetime import date, timedelta

    from .engine import rings
    from .extensions import db
    from .models import Tenant, User
    app = _app()
    with app.app_context():
        slug = _slug(args.slug or args.name)
        if Tenant.query.filter_by(slug=slug).first():
            print("Organização já existe.")
            return 1
        until = date.fromisoformat(args.license_until) if args.license_until else date.today() + timedelta(days=365)
        t = Tenant(name=args.name, slug=slug, license_expires_on=until)
        db.session.add(t)
        db.session.flush()
        rings.ensure_policies(t)
        if args.admin_email:
            pw = secrets.token_urlsafe(12) + "!A1"
            u = User(tenant_id=t.id, email=args.admin_email.lower(), role="admin", must_change_password=True)
            u.set_password(pw)
            db.session.add(u)
            print(f"Administrador {args.admin_email} — password temporária: {pw}")
        db.session.commit()
        print(f"Organização '{args.name}' criada (id={t.id}, slug={slug}); licença até {until:%Y-%m-%d}.")
    return 0


def cmd_reset_admin(args) -> int:
    from . import admin_reset
    app = _app(start_worker=False)
    try:
        email, password = admin_reset.reset(app, args.email or "", reset_mfa=args.reset_mfa)
    except ValueError as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 2
    print(f"Password reposta para {email}: {password}")
    return 0


def cmd_initial_password(args) -> int:
    from . import admin_reset
    app = _app(start_worker=False)
    admin_reset.ensure_primary(app, log=lambda m: None)
    email, password, message = admin_reset.initial_password(app)
    print(f"utilizador: {email}")
    print(f"password:   {password}" if password else message)
    return 0 if password else 1


def cmd_check(args) -> int:
    from .engine import ansible_runner, intel
    app = _app()
    print(f"Configuração: {app.config.get('CONFIG_FILE') or '(omissão)'}\nDados: {app.config['DATA_DIR']}")
    print(f"Base de dados: {app.config['SQLALCHEMY_DATABASE_URI'].split('@')[-1]}")
    with app.app_context():
        print(f"  [{'OK' if ansible_runner.available() else '--'}] ansible-playbook: {ansible_runner.binary() or 'não encontrado'} "
              f"(playbooks em {app.config['ANSIBLE_DIR']})")
        st = intel.stats()
        print(f"  [OK] inteligência: {st['total']} CVE, {st['kev']} KEV, {st['with_epss']} com EPSS")
        for kind in ("OMXVULN", "OMXGRC"):
            print(f"  [{'OK' if app.config[kind + '_URL'] else '--'}] {kind}: {app.config[kind + '_URL'] or 'não configurado'}")
    return 0


def _tenant(app, slug):
    from .models import Tenant
    t = Tenant.query.filter_by(slug=slug).first()
    if t is None:
        sys.exit(f"Organização '{slug}' não encontrada")
    return t


def cmd_intel_sync(args) -> int:
    from .engine import intel
    app = _app()
    with app.app_context():
        for k, v in intel.sync_all().items():
            print(f"  {k}: {v}")
    return 0


def cmd_correlate(args) -> int:
    from .engine import correlate
    app = _app()
    with app.app_context():
        res = correlate.correlate_tenant(_tenant(app, args.tenant))
        res.pop("new_ids", None)
        print(res)
    return 0


def cmd_import_intel(args) -> int:
    from .engine import intel
    app = _app()
    with app.app_context():
        print(intel.import_file(Path(args.file).read_text(encoding="utf-8-sig")))
    return 0


def cmd_agent_token(args) -> int:
    from .extensions import db
    from .web.api import new_enrollment_token
    app = _app()
    with app.app_context():
        t = _tenant(app, args.tenant)
        raw, tok = new_enrollment_token(t, args.name, args.ring, args.days, args.max_uses)
        db.session.commit()
        print(raw)
        print(f"(token de registo '{tok.name}', anel {tok.ring}, válido até {tok.expires_at:%Y-%m-%d})", file=sys.stderr)
    return 0


def cmd_ansible_vars(args) -> int:
    """Mostra as variáveis (``-e``) dos playbooks de instalação dos agentes, com um novo token de registo."""
    from .extensions import db
    from .web.api import new_enrollment_token
    app = _app()
    with app.app_context():
        t = _tenant(app, args.tenant)
        raw, tok = new_enrollment_token(t, "ansible-" + secrets.token_hex(3), args.ring, args.days, 0)
        db.session.commit()
        print(f"omxpatch_server_url={app.config['BASE_URL']} omxpatch_enrollment_token={raw}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="omxpatch", description="OMXPatch — gestão de patches e remediação contínua")
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("serve"); s.add_argument("--host"); s.add_argument("--port", type=int); s.add_argument("--agent-port", type=int); s.add_argument("--prefix")
    s.add_argument("--no-worker", action="store_true"); s.add_argument("--no-tls", action="store_true"); s.set_defaults(fn=cmd_serve)
    sub.add_parser("worker").set_defaults(fn=cmd_worker)
    b = sub.add_parser("backup"); b.add_argument("action", nargs="?", choices=["create", "list"], default="create"); b.set_defaults(fn=cmd_backup)
    r_ = sub.add_parser("restore"); r_.add_argument("file"); r_.add_argument("--force", action="store_true"); r_.set_defaults(fn=cmd_restore)
    d_ = sub.add_parser("db"); d_.add_argument("action", choices=["status", "upgrade"]); d_.set_defaults(fn=cmd_db)
    sg = sub.add_parser("signing"); sg.add_argument("action", choices=["show", "rotate"]); sg.set_defaults(fn=cmd_signing)
    cp = sub.add_parser("capacity"); cp.add_argument("--benchmark", action="store_true"); cp.add_argument("--agents", type=int, default=50)
    cp.add_argument("--seconds", type=int, default=10); cp.add_argument("--tenant"); cp.add_argument("--json", action="store_true"); cp.set_defaults(fn=cmd_capacity)
    t = sub.add_parser("tls"); t.add_argument("action", choices=["info", "generate"]); t.add_argument("--hostname"); t.add_argument("--agent-hostname"); t.add_argument("--days", type=int)
    t.set_defaults(fn=cmd_tls)
    i = sub.add_parser("init"); i.add_argument("--email", required=True); i.add_argument("--password"); i.add_argument("--tenant"); i.set_defaults(fn=cmd_init)
    c = sub.add_parser("create-tenant"); c.add_argument("--name", required=True); c.add_argument("--slug"); c.add_argument("--admin-email")
    c.add_argument("--license-until"); c.set_defaults(fn=cmd_create_tenant)
    r = sub.add_parser("reset-admin"); r.add_argument("--email"); r.add_argument("--reset-mfa", action="store_true"); r.set_defaults(fn=cmd_reset_admin)
    sub.add_parser("initial-password").set_defaults(fn=cmd_initial_password)
    sub.add_parser("check").set_defaults(fn=cmd_check)
    sub.add_parser("intel-sync").set_defaults(fn=cmd_intel_sync)
    co = sub.add_parser("correlate"); co.add_argument("--tenant", required=True); co.set_defaults(fn=cmd_correlate)
    ii = sub.add_parser("import-intel"); ii.add_argument("file"); ii.set_defaults(fn=cmd_import_intel)
    for name, fn in (("agent-token", cmd_agent_token), ("ansible-vars", cmd_ansible_vars)):
        a = sub.add_parser(name); a.add_argument("--tenant", required=True); a.add_argument("--ring", type=int, default=4)
        a.add_argument("--days", type=int, default=30); a.add_argument("--name", default="ansible"); a.add_argument("--max-uses", type=int, default=0)
        a.set_defaults(fn=fn)
    args = p.parse_args(argv)
    if not getattr(args, "fn", None):
        p.print_help()
        return 1
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
