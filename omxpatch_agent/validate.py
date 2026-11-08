"""Validação do agente num sistema real (Windows, macOS ou Linux): ``python -m omxpatch_agent validate``.

Níveis:

* ``read`` (por omissão) — **só leitura**: autoteste, inventário, origens de atualização, descoberta de atualizações (sem instalar),
  contexto do ativo, deteção de servidores web, planos de boas práticas (sem aplicar) e ferramentas de firewall;
* ``lab`` — acrescenta **alterações reversíveis** (regra de firewall de teste, endurecimento do SO aplicado e revertido). Exige
  ``--yes-lab``: use só em VM/equipamento de laboratório;
* ``--with-isolation`` (só com ``lab`` e ``--server``) — testa o isolamento real (5 min, com libertação automática): cuidado, corta a rede
  do equipamento exceto a consola.

O relatório (JSON e Markdown) oculta por omissão o nome do equipamento e os IP (``--no-redact`` desliga)."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import socket
import sys
import time

from . import __version__

STATUS = ("pass", "warn", "skip", "fail")


class Report:
    def __init__(self, level: str, redact: bool = True):
        self.level, self.redact, self.checks = level, redact, []
        self.started = time.time()

    def add(self, cid: str, title: str, status: str, detail: str = "", ms: int = 0, data: dict | None = None) -> None:
        self.checks.append({"id": cid, "title": title, "status": status, "detail": str(detail)[:600], "ms": ms, **({"data": data} if data else {})})

    def run(self, cid: str, title: str, fn) -> None:
        """Executa uma verificação isolada: ``fn`` devolve (estado, detalhe[, dados]); uma exceção é uma falha, não pára as outras."""
        t0 = time.time()
        try:
            res = fn()
            status, detail, data = (res + (None,))[:3] if isinstance(res, tuple) else ("pass", str(res or ""), None)
        except Exception as exc:  # noqa: BLE001
            status, detail, data = "fail", f"{type(exc).__name__}: {exc}", None
        self.add(cid, title, status, detail, int((time.time() - t0) * 1000), data)

    def summary(self) -> dict:
        c = {s: sum(1 for x in self.checks if x["status"] == s) for s in STATUS}
        return {"counts": c, "ok": c["fail"] == 0, "seconds": round(time.time() - self.started, 1)}


def is_admin() -> bool:
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except (AttributeError, OSError):
        return False


def host_info() -> dict:
    return {"agent_version": __version__, "python": sys.version.split()[0], "implementation": platform.python_implementation(), "system": platform.system(),
            "release": platform.release(), "version": platform.version()[:120], "machine": platform.machine(), "admin": is_admin(),
            "hostname": socket.gethostname()}


IP_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b")


def redact_text(text: str, hostname: str) -> str:
    tag = "host-" + hashlib.sha256(hostname.encode()).hexdigest()[:6]
    text = IP_RE.sub(lambda m: f"{m.group(1)}.{m.group(2)}.x.x", text)
    return re.sub(re.escape(hostname), tag, text, flags=re.I) if hostname else text


# --------------------------------------------------------------------------- verificações (leitura)


def _selftest(rep: Report) -> None:
    from . import compat

    def f():
        res = compat.selftest()
        fails = [s for s in res["steps"] if s["status"] != "ok"]
        data = {"python_level": res["runtime"]["level"], "tls_max": res["runtime"]["tls_max"], "openssl": res["runtime"]["openssl"], "steps": len(res["steps"])}
        return ("pass" if res["ok"] else "fail", f"{len(res['steps'])} passos, {len(fails)} falha(s)" + ("".join(f"; {s['name']}: {s['detail']}" for s in fails[:5])), data)
    rep.run("selftest", "Autoteste do agente (módulos, coletor, TLS, pin, boas práticas)", f)


def _inventory(rep: Report) -> None:
    from . import collectors

    def f():
        info = collectors.collect()
        n = len(info.get("software", []))
        data = {"software": n, "os_name": info.get("os_name"), "os_version": info.get("os_version"), "open_ports": len(info.get("open_ports", [])), "hotfixes": len(info.get("hotfixes", [])),
                "reboot_pending": info.get("reboot_pending"), "webservers": [w.get("type") for w in info.get("webservers", [])]}
        if n == 0:
            return "fail", "inventário de software vazio", data
        return "pass", f"{n} aplicações/pacotes; SO {info.get('os_name')} {info.get('os_version')}; {data['open_ports']} portas abertas", data
    rep.run("inventory", "Inventário (software, portas, SO)", f)


def _sources(rep: Report) -> None:
    from . import sources

    def f():
        caps = sources.capabilities()
        av = sorted(k for k, v in caps.get("sources", {}).items() if v.get("available"))
        miss = sorted(k for k, v in caps.get("sources", {}).items() if not v.get("available"))
        return "pass" if av else "warn", f"disponíveis: {', '.join(av) or 'nenhuma'}; indisponíveis: {', '.join(miss) or '—'}", {"available": av, "unavailable": miss, "context": caps.get("context", {})}
    rep.run("sources", "Origens de atualização utilizáveis neste equipamento", f)


def _updates(rep: Report) -> None:
    from . import updates

    def f():
        r = updates.discover(refresh=False)
        bad = {k: v["error"] for k, v in r["sources"].items() if not v.get("ok")}
        data = {"sources": {k: {"ok": v["ok"], "count": v["count"], "seconds": v.get("seconds")} for k, v in r["sources"].items()}, "total": len(r["updates"]),
                "with_url": sum(1 for u in r["updates"] if u.get("download_url")), "with_sha256": sum(1 for u in r["updates"] if u.get("sha256")),
                "security": sum(1 for u in r["updates"] if u.get("category") == "security")}
        if bad:
            return "fail", "origem(ns) com erro: " + "; ".join(f"{k}: {v}" for k, v in bad.items()), data
        if not r["sources"]:
            return "warn", "nenhuma origem de atualização aplicável detetada", data
        return "pass", f"{len(r['updates'])} atualização(ões) descoberta(s) em {', '.join(r['sources'])} ({data['with_url']} com URL, {data['with_sha256']} com SHA-256)", data
    rep.run("updates", "Descoberta de atualizações instaláveis (sem instalar)", f)


def _context(rep: Report) -> None:
    from . import context

    def f():
        c = context.collect_context(budget_s=40)
        fw = c.get("firewall") or {}
        data = {"collect_ms": c["collect_ms"], "processes": len(c["processes"]), "listeners": len(c["listeners"]), "services": len(c["services"]), "firewall_engine": fw.get("engine"),
                "firewall_enabled": fw.get("enabled"), "firewall_default_in": fw.get("default_in"), "admins": len((c.get("access") or {}).get("admins", [])), "errors": c["errors"][:5],
                "scopes": sorted({l.get("scope") for l in c["listeners"]})}
        if c["errors"]:
            return "warn", f"contexto recolhido com avisos: {c['errors'][0]}", data
        if not c["listeners"] and not c["processes"]:
            return "warn", "sem processos nem escutas (permissões?)", data
        return "pass", f"{len(c['processes'])} processos, {len(c['listeners'])} escutas, firewall {fw.get('engine') or '—'} {'ativa' if fw.get('enabled') else 'inativa'}, {c['collect_ms']} ms", data
    rep.run("context", "Contexto do ativo (processos, escutas, firewall, acessos)", f)


def _practices(rep: Report) -> None:
    from . import practices
    from .config import platform_family

    def f():
        ws = practices.detect_webservers()
        return "pass", "servidores web: " + (", ".join(w["type"] for w in ws) or "nenhum"), {"webservers": ws}
    rep.run("webservers", "Deteção de servidores web (nginx, Apache, IIS)", f)
    names = ["windows_hardening"] if platform_family() == "windows" else ["ssh_hardening"]
    for n in names + ["hsts"]:
        def g(n=n):
            r = practices.simulate(n, {})
            blocks = [c for c in r["checks"] if c["status"] == "block"]
            data = {"actions": len(r["actions"]), "noop": bool(r["predicted"].get("noop")), "checks": [(c["id"], c["status"]) for c in r["checks"]][:8]}
            if blocks and n in ("windows_hardening", "ssh_hardening"):
                return "warn", "plano bloqueado: " + "; ".join(f"{c['label']}: {c['detail']}" for c in blocks[:2]), data
            return "pass", f"plano sem aplicar: {len(r['actions'])} ação(ões); {'já conforme' if data['noop'] else 'alterações previstas'}", data
        rep.run(f"practice_{n}", f"Simulação da boa prática «{n}» (não aplica)", g)


def _firewall_tools(rep: Report) -> None:
    from .config import platform_family
    from .runner import run

    def f():
        fam = platform_family()
        if fam == "windows":
            r = run(["netsh", "advfirewall", "show", "allprofiles", "state"], 60)
            return ("pass" if r.ok and "State" in r.out else "fail"), r.out.strip().replace("\r", "")[:200], {"tool": "netsh"}
        if fam == "macos":
            r = run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], 30)
            p = run(["pfctl", "-s", "info"], 30)
            return ("pass" if r.ok else "warn"), f"alf: {r.out.strip()[:100]}; pf: {'acessível' if p.ok else 'sem permissões'}", {"tool": "alf/pf"}
        r = run(["sh", "-c", "command -v nft || command -v iptables"], 15)
        return ("pass" if r.ok else "warn"), r.out.strip() or "sem nft/iptables", {"tool": "nft/iptables"}
    rep.run("firewall_tools", "Ferramentas de firewall local acessíveis", f)


def _server(rep: Report, server: str, pin: str) -> None:
    """Ligação à consola só por IP + impressão digital (sem DNS nem CA)."""
    from . import client as ac

    def f():
        t0 = time.time()
        s = ac.StdSession(pin_sha256=pin)
        r = s.request("GET", server.rstrip("/") + "/healthz", timeout=15)
        host = server.split("//")[-1].split(":")[0].split("/")[0]
        data = {"status": r.status_code, "ms": int((time.time() - t0) * 1000), "ip_only": ac.is_ip_host(host), "pinned": bool(pin), "matched_pin": s.matched_pin[:16]}
        skew = None
        if r.headers.get("date"):
            from email.utils import parsedate_to_datetime
            try:
                skew = abs(parsedate_to_datetime(r.headers["date"]).timestamp() - time.time())
                data["clock_skew_s"] = int(skew)
            except (TypeError, ValueError):
                pass
        if r.status_code != 200:
            return "fail", f"/healthz devolveu HTTP {r.status_code}", data
        if skew is not None and skew > 600:
            return "warn", f"relógio desfasado {int(skew)} s (as tarefas assinadas exigem < 10 min)", data
        return "pass", f"TLS com impressão digital OK ({data['ms']} ms){' por IP' if data['ip_only'] else ''}", data
    rep.run("server_pin", "Ligação à consola com impressão digital (thumbprint)", f)


# --------------------------------------------------------------------------- verificações com alterações reversíveis (lab)


def _firewall_cycle(rep: Report) -> None:
    from . import firewall

    def f():
        if not is_admin():
            return "skip", "exige administrador/root"
        name = f"OMXPatch-validate-{int(time.time()) % 100000}"
        op = {"op": "firewall_block_port", "name": name, "port": 59871, "proto": "tcp"}
        res = firewall.block(op)
        present = firewall.verify(name)
        firewall.remove({"name": name})
        gone = not firewall.verify(name)
        if not (res.get("verified") or present):
            return "fail", f"regra aplicada mas não verificada: {res}", {"applied": True, "verified": False}
        return ("pass" if gone else "fail"), f"regra {name} aplicada, verificada e removida (removida={gone})", {"verified": present, "removed": gone}
    rep.run("firewall_cycle", "Regra de firewall de teste: aplicar → verificar → remover", f)


def _hardening_cycle(rep: Report) -> None:
    from .config import platform_family
    from .practices import oshardening

    def f():
        fam = platform_family()
        practice = "windows_hardening" if fam == "windows" else "ssh_hardening"
        if not is_admin():
            return "skip", "exige administrador/root"
        sim = oshardening.simulate(practice, {})
        if any(c["status"] == "block" for c in sim["checks"]):
            return "skip", "; ".join(c["detail"] for c in sim["checks"] if c["status"] == "block")[:200]
        if sim["predicted"].get("noop"):
            return "pass", f"«{practice}» já conforme: nada a aplicar (ciclo aplicar/reverter não exercitado)", {"noop": True}
        item = f"validate-{int(time.time())}"
        app = oshardening.apply(practice, {}, item)
        if app["status"] != "succeeded":
            return "fail", f"aplicação falhou (revertido={app.get('rolled_back')}): {app['output'][:200]}", {"applied": False}
        after = oshardening.simulate(practice, {})
        rb = oshardening.rollback(practice, item)
        back = oshardening.simulate(practice, {})
        ok = bool(after["predicted"].get("noop")) and rb["status"] == "succeeded" and not back["predicted"].get("noop")
        return ("pass" if ok else "fail"), f"aplicado ({len(app['actions'])} ação[ões]) → conforme={after['predicted'].get('noop')} → revertido={rb['status']} → estado original={not back['predicted'].get('noop')}", {"actions": len(app["actions"])}
    rep.run("hardening_cycle", "Endurecimento do SO: aplicar → verificar → reverter", f)


def _isolation_cycle(rep: Report, server: str) -> None:
    from . import isolation

    def f():
        if not is_admin():
            return "skip", "exige administrador/root"
        from urllib.parse import urlsplit
        u = urlsplit(server)
        port = u.port or 443
        try:
            ips = {i[4][0] for i in socket.getaddrinfo(u.hostname, port, proto=socket.IPPROTO_TCP)}
        except OSError:
            ips = set()
        eps = [(ip, port) for ip in sorted(ips)] or isolation.console_endpoints()
        if not eps:
            return "skip", "não foi possível resolver a consola"
        before = isolation.reachable([("1.1.1.1", 443)], 4)
        isolation.isolate({"ttl_minutes": 5, "endpoints": eps})
        console_ok = isolation.reachable(eps, 4)
        out_blocked = not isolation.reachable([("1.1.1.1", 443)], 3)
        isolation.release({})
        after = isolation.reachable([("1.1.1.1", 443)], 4)
        ok = console_ok and (out_blocked or not before) and (after or not before)
        return ("pass" if ok else "fail"), f"consola acessível={console_ok}; Internet bloqueada={out_blocked}; libertado e Internet restabelecida={after}", {"console_ok": console_ok, "blocked": out_blocked, "restored": after}
    rep.run("isolation_cycle", "Isolamento real (5 min): só a consola → libertar", f)


# --------------------------------------------------------------------------- orquestração e relatórios


def validate(level: str = "read", server: str = "", pin: str = "", with_isolation: bool = False, redact: bool = True) -> dict:
    rep = Report(level, redact)
    host = host_info()
    _selftest(rep)
    _inventory(rep)
    _sources(rep)
    _updates(rep)
    _context(rep)
    _practices(rep)
    _firewall_tools(rep)
    if server:
        _server(rep, server, pin)
    if level == "lab":
        _firewall_cycle(rep)
        _hardening_cycle(rep)
        if with_isolation and server:
            _isolation_cycle(rep, server)
    out = {"agent_version": __version__, "level": level, "host": host, "summary": rep.summary(), "checks": rep.checks, "generated_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    if redact:
        txt = redact_text(json.dumps(out), host["hostname"])
        out = json.loads(txt)
        out["host"]["hostname"] = "host-" + hashlib.sha256(host["hostname"].encode()).hexdigest()[:6]
    return out


ICON = {"pass": "✅", "warn": "⚠️", "skip": "⏭️", "fail": "❌"}


def to_markdown(r: dict) -> str:
    h, s = r["host"], r["summary"]
    L = [f"# Validação OMXPatch Agent {r['agent_version']} — {h['system']} {h['release']} ({h['machine']})", "",
         f"- Nível: **{r['level']}** · Python {h['python']} ({h['implementation']}) · administrador: **{'sim' if h['admin'] else 'não'}** · duração {s['seconds']} s · {r['generated_at']}",
         f"- Resultado: ✅ {s['counts']['pass']} · ⚠️ {s['counts']['warn']} · ⏭️ {s['counts']['skip']} · ❌ {s['counts']['fail']} → **{'OK' if s['ok'] else 'COM FALHAS'}**", "",
         "| | Verificação | Detalhe | ms |", "|---|---|---|---|"]
    for c in r["checks"]:
        L.append(f"| {ICON[c['status']]} | {c['title']} | {c['detail'].replace('|', '/').replace(chr(10), ' ')[:300]} | {c['ms']} |")
    L += ["", "<details><summary>Dados técnicos</summary>", "", "```json", json.dumps({c["id"]: c.get("data") for c in r["checks"] if c.get("data")}, indent=1, ensure_ascii=False)[:12000], "```", "</details>"]
    return "\n".join(L) + "\n"
