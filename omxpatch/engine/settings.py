"""Alteração de configuração pela consola, com validação, pré-visualização, cópia de segurança e reinício controlado.

As alterações ficam em ``<dados>/omxpatch.overrides.toml`` (o ``omxpatch.toml`` original não é tocado; as variáveis de ambiente
continuam a ter precedência). Cada parâmetro diz se se aplica de imediato (``hot``) ou só após reiniciar."""
from __future__ import annotations

import json
import os
import subprocess  # nosec B404 - só para relançar o próprio processo no Windows sem supervisor
import sys
import threading
import time
from pathlib import Path

from ..config import DEFAULTS, OVERRIDES_NAME, _TOML_SECTIONS, load_config

# chave: (rótulo, grupo, tipo, mínimo, máximo ou opções, aplica de imediato, ajuda)
CATALOG: dict[str, tuple] = {
    "THREADS": ("Threads do servidor web", "Desempenho", "int", 2, 256, False, "Pedidos simultâneos por processo. Regra: 2–4× o n.º de CPU."),
    "AGENT_HEARTBEAT_SECONDS": ("Intervalo de contacto dos agentes (s)", "Agentes", "int", 30, 3600, True,
                                "Maior intervalo = menos carga. Os agentes adotam o novo valor no contacto seguinte."),
    "AGENT_OFFLINE_MINUTES": ("Agente offline após (min)", "Agentes", "int", 2, 1440, True, "Sem contacto durante este tempo = offline."),
    "AGENT_TASK_TIMEOUT_MINUTES": ("Limite de uma tarefa de agente (min)", "Agentes", "int", 5, 1440, True, ""),
    "AGENT_ADDRESS_MODE": ("Endereçamento dos agentes", "Agentes", "choice", None, ("name", "ip"), False,
                           "ip = os agentes usam só o IP do servidor e o thumbprint do certificado (exige AGENT_SERVER_IP)."),
    "WORKER_POLL_SECONDS": ("Ciclo do worker (s)", "Desempenho", "int", 5, 600, False, ""),
    "CORRELATE_MINUTES": ("Correlação (min)", "Desempenho", "int", 1, 1440, False, ""),
    "EMBEDDED_WORKER": ("Worker embebido no servidor web", "Desempenho", "bool", None, None, False, "Com muitos agentes use um worker separado."),
    "OMXVULN_SYNC_MINUTES": ("Sincronização OMXVuln (min)", "Integrações", "int", 5, 1440, False, ""),
    "OMXGRC_PUSH_MINUTES": ("Envio ao OMXGRC (min)", "Integrações", "int", 5, 1440, False, ""),
    "INTEL_SYNC_HOURS": ("Sincronização de inteligência (h)", "Integrações", "int", 1, 168, False, ""),
    "SESSION_HOURS": ("Duração da sessão (h)", "Segurança", "int", 1, 72, False, ""),
    "LOGIN_MAX_FAILURES": ("Falhas de início de sessão até bloquear", "Segurança", "int", 3, 20, True, ""),
    "LOGIN_LOCK_MINUTES": ("Bloqueio (min)", "Segurança", "int", 1, 1440, True, ""),
    "PASSWORD_MIN_LENGTH": ("Tamanho mínimo da palavra-passe", "Segurança", "int", 8, 64, True, ""),
    "TLS_MIN_VERSION": ("TLS mínimo", "Segurança", "choice", None, ("1.2", "1.3"), False, "1.3 exclui clientes antigos."),
    "BACKUP_ENABLED": ("Cópia de segurança automática", "Dados", "bool", None, None, False, "Base de dados + chaves, em <dados>/backups (contém segredos)."),
    "BACKUP_KEEP": ("Cópias a manter", "Dados", "int", 0, 365, False, "0 = não apagar cópias antigas."),
    "AUDIT_RETENTION_DAYS": ("Retenção da auditoria (dias)", "Dados", "int", 0, 3650, False, "0 = guardar sempre. Verifique obrigações legais antes de reduzir."),
    "TASK_RETENTION_DAYS": ("Retenção de tarefas concluídas (dias)", "Dados", "int", 0, 3650, False, "0 = guardar sempre."),
    "RATE_ENROLL_PER_MIN": ("Registos por IP/minuto", "Segurança", "int", 0, 100000, True, "Proteção contra adivinhação de tokens e inundação; 0 = sem limite."),
    "RATE_AGENT_PER_MIN": ("Pedidos por agente/minuto", "Segurança", "int", 0, 100000, True, "0 = sem limite."),
    "AGENT_AUTO_UPDATE": ("Atualização automática dos agentes", "Agentes", "bool", None, None, True, "Só com pacote assinado e autoteste."),
    "MAX_UPLOAD_MB": ("Tamanho máximo de carregamento (MB)", "Desempenho", "int", 1, 4096, False, "Pacotes do repositório de patches."),
}


def overrides_path(cfg) -> Path:
    return Path(cfg["DATA_DIR"]) / OVERRIDES_NAME


def current(app) -> list[dict]:
    rows = []
    saved = _read_overrides(app.config)
    for key, (label, group, typ, lo, hi, hot, help_) in CATALOG.items():
        rows.append({"key": key, "label": label, "group": group, "type": typ, "min": lo, "max": hi if typ != "choice" else None,
                     "choices": hi if typ == "choice" else None, "hot": hot, "help": help_, "value": app.config.get(key),
                     "default": DEFAULTS[key], "overridden": key in saved})
    return rows


def validate(raw: dict) -> tuple[dict, list[str]]:
    clean, errors = {}, []
    for key, value in raw.items():
        if key not in CATALOG:
            continue
        label, _g, typ, lo, hi, _h, _x = CATALOG[key]
        v = str(value).strip()
        if typ == "int":
            if not v.lstrip("-").isdigit() or not (lo <= int(v) <= hi):
                errors.append(f"{label}: valor entre {lo} e {hi}")
                continue
            clean[key] = int(v)
        elif typ == "bool":
            clean[key] = v.lower() in ("1", "true", "on", "yes", "sim")
        elif typ == "choice":
            if v not in hi:
                errors.append(f"{label}: use {' ou '.join(hi)}")
                continue
            clean[key] = v
    return clean, errors


def diff(app, clean: dict) -> list[dict]:
    out = []
    for key, new in clean.items():
        old = app.config.get(key)
        if old != new:
            out.append({"key": key, "label": CATALOG[key][0], "old": old, "new": new, "hot": CATALOG[key][5]})
    return out


def cross_checks(app, clean: dict) -> list[str]:
    """Combinações que partem o sistema: devolvem erros (bloqueiam) — nunca se grava uma configuração que não arranca."""
    merged = {**{k: app.config.get(k) for k in CATALOG}, **clean}
    errs = []
    if merged.get("AGENT_ADDRESS_MODE") == "ip":
        if not str(app.config.get("AGENT_SERVER_IP") or "").strip():
            errs.append("Endereçamento por IP exige AGENT_SERVER_IP definido no ficheiro de configuração.")
        if not app.config.get("TLS_ENABLED"):
            errs.append("Endereçamento por IP exige TLS (o thumbprint é a única forma de confiar no servidor).")
    if int(merged["AGENT_OFFLINE_MINUTES"]) * 60 <= int(merged["AGENT_HEARTBEAT_SECONDS"]) * 2:
        errs.append("«Agente offline após» tem de ser bem maior que o intervalo de contacto (pelo menos 2×).")
    return errs


# --------------------------------------------------------------------------- ficheiro de alterações


def _key_to_toml(key: str) -> tuple[str, str]:
    best = ("server", key.lower(), 0)
    for section, prefix in _TOML_SECTIONS.items():
        if prefix and key.startswith(prefix) and len(prefix) > best[2]:
            best = (section, key[len(prefix):].lower(), len(prefix))
    return best[0], best[1]


def _read_overrides(cfg) -> dict:
    p = overrides_path(cfg)
    if not p.is_file():
        return {}
    try:
        from ..config import _load_toml
        return {k: v for k, v in _load_toml(p).items() if k in DEFAULTS}
    except Exception:  # noqa: BLE001
        return {}


def _write(path: Path, values: dict) -> None:
    sections: dict[str, list] = {}
    for key, v in sorted(values.items()):
        sec, name = _key_to_toml(key)
        lit = ("true" if v else "false") if isinstance(v, bool) else (str(int(v)) if isinstance(v, int) else json.dumps(str(v)))
        sections.setdefault(sec, []).append(f"{name} = {lit}")
    text = "# Gerado pela consola (Sistema → Configuração). Não edite com a consola aberta; as variáveis de ambiente têm precedência.\n"
    text += "".join(f"\n[{sec}]\n" + "\n".join(lines) + "\n" for sec, lines in sections.items())
    tmp = path.with_suffix(".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def history(app) -> list[dict]:
    d = Path(app.config["DATA_DIR"])
    return [{"name": p.name, "at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.stat().st_mtime))}
            for p in sorted(d.glob(OVERRIDES_NAME + ".bak-*"), reverse=True)[:10]]


def apply(app, clean: dict) -> dict:
    """Grava (com cópia da versão anterior), aplica de imediato o que for ``hot`` e indica o que exige reinício."""
    changes = diff(app, clean)
    p = overrides_path(app.config)
    saved = _read_overrides(app.config)
    if p.is_file():
        p.with_name(f"{p.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}").write_bytes(p.read_bytes())
    saved.update({c["key"]: c["new"] for c in changes})
    _write(p, saved)
    restart = []
    for c in changes:
        if c["hot"]:
            app.config[c["key"]] = c["new"]
        else:
            restart.append(c["key"])
    return {"changed": len(changes), "restart_needed": restart}


def revert_last(app) -> bool:
    """Repõe a cópia de segurança mais recente (ou remove as alterações se não houver)."""
    p = overrides_path(app.config)
    baks = sorted(p.parent.glob(p.name + ".bak-*"))
    if baks:
        p.write_bytes(baks[-1].read_bytes())
        baks[-1].unlink()
        return True
    if p.is_file():
        p.unlink()
        return True
    return False


# --------------------------------------------------------------------------- reinício


def preflight() -> list[str]:
    """Carrega a configuração tal como o próximo arranque a vai ler e valida-a. Lista vazia = pode reiniciar."""
    errs = []
    try:
        cfg = load_config()
        if cfg.get("OVERRIDES_ERROR"):
            errs.append("Ficheiro de alterações inválido: " + cfg["OVERRIDES_ERROR"])
        for k in ("PORT", "AGENT_PORT", "THREADS"):
            if not (1 <= int(cfg[k]) <= 65535):
                errs.append(f"{k} inválido")
        from sqlalchemy.engine import make_url
        make_url(str(cfg["DATABASE_URL"]))
        if cfg["TLS_ENABLED"]:
            for prefix in ("", "AGENT_"):
                cert, key = str(cfg.get(prefix + "TLS_CERT") or ""), str(cfg.get(prefix + "TLS_KEY") or "")
                if (cert or key) and not (Path(cert).is_file() and Path(key).is_file()):
                    errs.append(f"{prefix}TLS_CERT/TLS_KEY apontam para ficheiros inexistentes")
    except Exception as exc:  # noqa: BLE001
        errs.append(f"{type(exc).__name__}: {exc}")
    return errs


def supervised() -> bool:
    """Há alguém que volta a arrancar o processo? (systemd, ou o ciclo dos serviços Windows do instalador)."""
    return bool(os.environ.get("INVOCATION_ID") or os.environ.get("OMXPATCH_SUPERVISED"))


def request_restart(app, who: str = "") -> dict:
    errs = preflight()
    if errs:
        return {"ok": False, "errors": errs}
    d = Path(app.config["DATA_DIR"])
    (d / "restart.request").write_text(json.dumps({"at": time.time(), "by": who}))
    if not app.config.get("TESTING"):
        threading.Timer(2.0, _exit_for_restart).start()
    return {"ok": True, "supervised": supervised(), "mode": "supervisor" if supervised() else ("reexec" if os.name != "nt" else "spawn")}


def _exit_for_restart() -> None:
    if supervised():
        os._exit(0)                       # systemd (Restart=always) ou o ciclo do instalador Windows volta a arrancar
    if os.name != "nt":
        os.execv(sys.executable, [sys.executable] + sys.argv)  # nosec B606 - o mesmo processo e os mesmos argumentos
    args = " ".join(f'"{a}"' for a in [sys.executable] + sys.argv)
    subprocess.Popen(f'cmd /c timeout /t 4 /nobreak >nul & {args}', shell=True, creationflags=0x00000208)  # nosec B602 B603 - DETACHED|NEW_GROUP
    os._exit(0)


def restart_requested_since(cfg, since: float) -> bool:
    """O worker chama isto em cada ciclo: houve pedido de reinício depois de ele arrancar?"""
    try:
        return (Path(cfg["DATA_DIR"]) / "restart.request").stat().st_mtime > since
    except OSError:
        return False
