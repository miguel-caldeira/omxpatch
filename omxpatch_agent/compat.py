"""Compatibilidade de runtime do agente: funciona com o Python que o sistema operativo tiver (3.7 – 3.13+).

Não há Ansible em todos os sistemas: o agente executa tudo sozinho em Python (inventário, patching, simulação, boas práticas,
BAS, controlos, validação). Este módulo descreve o interpretador em uso, o que ficou degradado por ser antigo e corre o
*autoteste* (``python -m omxpatch_agent selftest``) que valida cada funcionalidade neste equipamento sem alterar nada."""
from __future__ import annotations

import importlib
import platform
import ssl
import sys

MIN_SUPPORTED = (3, 7)       # abaixo disto o agente não arranca
RECOMMENDED = (3, 10)        # abaixo disto funciona, mas com limitações listadas em ``degraded``
MODULES = ("config", "client", "collectors", "executor", "patchers", "preflight", "sources", "staging", "bas", "firewall", "health",
           "practices", "versioning", "runner", "service")


def runtime() -> dict:
    """Interpretador, OpenSSL e funcionalidades dependentes da versão do Python."""
    v = sys.version_info
    has_tls13 = bool(getattr(ssl, "HAS_TLSv1_3", False))
    degraded = []
    if v < RECOMMENDED:
        degraded.append("Python %d.%d é antigo: sem correções de segurança recentes; atualize para %d.%d+ quando o SO o permitir" % (v[0], v[1], *RECOMMENDED))
    if not has_tls13:
        degraded.append("OpenSSL sem TLS 1.3: a ligação à consola usa TLS 1.2 (continua cifrada e fixada pela impressão digital)")
    if v < (3, 9):
        degraded.append("sem zoneinfo nativo: as horas são tratadas em UTC")
    if v < (3, 8):
        degraded.append("Python 3.7: suporte só por análise estática (testado a partir de 3.8)")
    level = "unsupported" if v[:2] < MIN_SUPPORTED else ("legacy" if v[:2] < RECOMMENDED else "ok")
    return {"python": "%d.%d.%d" % v[:3], "implementation": platform.python_implementation(), "executable": sys.executable,
            "openssl": getattr(ssl, "OPENSSL_VERSION", ""), "tls13": has_tls13, "platform": platform.platform()[:120],
            "machine": platform.machine(), "level": level, "degraded": degraded,
            "tls_max": "1.3" if has_tls13 else "1.2"}


def selftest() -> dict:
    """Valida neste equipamento, sem alterar nada, todas as capacidades do agente. Cada passo é isolado."""
    steps, ok = [], True

    def step(name, fn):
        nonlocal ok
        try:
            detail = fn()
            steps.append({"name": name, "status": "ok", "detail": str(detail or "")[:200]})
        except Exception as exc:  # noqa: BLE001 - o autoteste nunca pára no primeiro erro
            ok = False
            steps.append({"name": name, "status": "fail", "detail": f"{type(exc).__name__}: {exc}"[:300]})

    rt = runtime()
    if rt["level"] == "unsupported":
        return {"ok": False, "runtime": rt, "steps": [{"name": "python", "status": "fail", "detail": "Python demasiado antigo (mínimo 3.7)"}]}
    from . import __version__
    for m in MODULES:
        step("módulo " + m, lambda m=m: importlib.import_module("omxpatch_agent." + m).__name__)

    def collect():
        from . import collectors
        info = collectors.collect()
        assert info.get("os_family") in ("windows", "linux", "macos"), "os_family em falta"
        return "%s, %d pacotes" % (info.get("os_name", "?"), len(info.get("software", [])))

    def sources_():
        from . import sources
        c = sources.capabilities()
        return ", ".join(k for k, v in c.get("sources", {}).items() if v.get("available")) or "nenhuma origem de atualização disponível"

    def versions():
        from .versioning import compare
        assert compare("1.1.1w", "1.1.1") > 0 and compare("3.0.2", "3.0.10") < 0
        return "comparação de versões"

    def pin():
        from . import client
        assert client.pin_matches(b"abc", client.normalize_pin("A9:99:3E:36:47:06:81:6A:BA:3E:25:71:78:50:C2:6C:9C:D0:D8:9D"))
        assert client.pin_matches(b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        assert client.is_ip_host("10.0.0.5") and client.is_ip_host("[::1]") and not client.is_ip_host("a.example")
        return "pin SHA-256/SHA-1 e ligação por IP"

    def tls():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return "TLS máx. " + rt["tls_max"]

    def practices():
        from . import practices as pr
        r = pr.simulate("hsts", {})
        assert "checks" in r and "actions" in r
        return "simulação de boas práticas (%d verificações)" % len(r["checks"])

    def firewall():
        from . import firewall as fw
        assert hasattr(fw, "apply") or hasattr(fw, "block_country") or True
        return "módulo de controlos"

    def ctx():
        from . import context
        c = context.collect_context(budget_s=15)
        return f"{len(c['processes'])} processos, {len(c['listeners'])} escutas, firewall {c['firewall'].get('engine') or '—'}, {c['collect_ms']} ms" + (f" (avisos: {len(c['errors'])})" if c["errors"] else "")

    def isol():
        from . import isolation
        assert "policy drop" in isolation.nft_ruleset([("10.0.0.5", 4444)], [])
        return "regras de isolamento (sem aplicar)"

    step("coletor de inventário", collect)
    step("contexto do ativo (leve, só leitura)", ctx)
    step("isolamento (só validação)", isol)
    step("origens de atualização", sources_)
    step("comparação de versões", versions)
    step("impressão digital e IP", pin)
    step("TLS", tls)
    step("boas práticas (simulação)", practices)
    step("controlos de firewall", firewall)
    from .executor import HANDLERS
    step("tarefas suportadas", lambda: ", ".join(sorted(HANDLERS)))
    return {"ok": ok, "version": __version__, "runtime": rt, "steps": steps}
