"""Gera docs/REFERENCIA.md a partir do código (parâmetros, comandos, rotas, perfis…) para o manual nunca divergir da solução.
Uso: python docs/tools/gen_reference.py"""
from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from omxpatch import __version__  # noqa: E402
from omxpatch.config import DEFAULTS, _TOML_SECTIONS  # noqa: E402


def toml_name(key: str) -> str:
    best = ("server", key.lower(), 0)
    for sec, pre in _TOML_SECTIONS.items():
        if pre and key.startswith(pre) and len(pre) > best[2]:
            best = (sec, key[len(pre):].lower(), len(pre))
    return f"[{best[0]}] {best[1]}"


def val(v) -> str:
    if isinstance(v, bool):
        return "sim" if v else "não"
    if v == "":
        return "(vazio)"
    return f"`{v}`"


def config_table() -> str:
    L = ["| Parâmetro (`OMXPATCH_<NOME>`) | TOML | Omissão |", "|---|---|---|"]
    for k, v in DEFAULTS.items():
        if k.endswith(("_TOKEN", "_PASSWORD", "_API_KEY", "SECRET_KEY")):
            v = "(segredo)" if v == "" else v
        L.append(f"| `{k}` | `{toml_name(k)}` | {val(v) if v != '(segredo)' else '(segredo)'} |")
    return "\n".join(L)


def cli_help(mod: str) -> str:
    out = subprocess.run([sys.executable, "-m", mod, "--help"], capture_output=True, text=True, cwd=ROOT, timeout=60).stdout
    m = re.search(r"\{([a-z0-9,-]+)\}", out)
    cmds = sorted(m.group(1).split(",")) if m else []
    rows = []
    for c in cmds:
        h = subprocess.run([sys.executable, "-m", mod, c, "--help"], capture_output=True, text=True, cwd=ROOT, timeout=60).stdout
        usage = re.sub(r"\s+", " ", h.split("\n\n")[0]).replace("usage: ", "")
        rows.append(f"| `{c}` | `{usage[:170]}` |")
    return "\n".join(["| Comando | Utilização |", "|---|---|"] + rows)


def routes_by_role() -> str:
    """Perfil mínimo por rota, lido dos decoradores (@roles_required / @superadmin_required) em omxpatch/web/*.py."""
    rows = []
    for f in sorted((ROOT / "omxpatch" / "web").glob("*.py")):
        if f.stem in ("common", "__init__", "agent_api", "api"):
            continue
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            path, methods, roles = None, "GET", None
            for d in fn.decorator_list:
                if isinstance(d, ast.Call) and getattr(d.func, "attr", "") == "route" and d.args and isinstance(d.args[0], ast.Constant):
                    path = d.args[0].value
                    for kw in d.keywords:
                        if kw.arg == "methods":
                            methods = ",".join(e.value for e in kw.value.elts)
                elif isinstance(d, ast.Call) and getattr(d.func, "attr", getattr(d.func, "id", "")) == "roles_required":
                    roles = "/".join(a.value for a in d.args)
                elif getattr(d, "id", "") == "superadmin_required":
                    roles = "superadmin"
                elif isinstance(d, ast.Call) and getattr(d.func, "attr", getattr(d.func, "id", "")) in ("get", "post"):
                    path, methods = d.args[0].value, d.func.attr.upper()
            if path:
                rows.append((f.stem, path, methods, roles or "qualquer utilizador autenticado"))
    L = ["| Módulo | Rota | Métodos | Perfil exigido |", "|---|---|---|---|"]
    L += [f"| {m} | `{p}` | {me} | {r} |" for m, p, me, r in rows]
    return "\n".join(L)


def api_routes() -> str:
    tree = ast.parse((ROOT / "omxpatch" / "web" / "api.py").read_text(encoding="utf-8"))
    rows = []
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        path = method = None
        roles = "qualquer token"
        doc = (ast.get_docstring(fn) or "").split("\n")[0]
        for d in fn.decorator_list:
            if isinstance(d, ast.Call) and getattr(d.func, "attr", "") in ("get", "post", "put", "delete") and d.args:
                path, method = d.args[0].value, d.func.attr.upper()
            elif isinstance(d, ast.Call) and getattr(d.func, "id", "") == "roles_required":
                roles = "/".join(a.value for a in d.args)
        if path:
            rows.append((path, method, roles, doc))
    return "\n".join(["| Método | Caminho (`/api/v1`) | Perfil | Descrição |", "|---|---|---|---|"] + [f"| {m} | `{p}` | {r} | {d[:110]} |" for p, m, r, d in rows])


def integrations() -> str:
    from omxpatch.connectors.catalog import KINDS
    groups: dict[str, list] = {}
    for k, v in KINDS.items():
        groups.setdefault(v["group"], []).append((k, v))
    names = {"vuln": "Vulnerabilidades (ferramentas irmãs)", "grc": "GRC", "siem": "SIEM", "itsm": "ITSM", "edr": "EDR", "vm": "Gestão de vulnerabilidades", "cspm": "Cloud / CSPM",
             "fw": "Firewalls de rede", "discovery": "Descoberta de ativos", "soar": "SOAR"}
    L = ["| Grupo | Integração (`kind`) | Opções |", "|---|---|---|"]
    for g, items in groups.items():
        for k, v in items:
            L.append(f"| {names.get(g, g)} | {v['label']} (`{k}`) | {', '.join(f'`{o}`' for o in v.get('options', {})) or '—'} |")
    return "\n".join(L)


def practices_table() -> str:
    from omxpatch.engine.practices import PRACTICES
    L = ["| Boa prática | Aplica-se a | Risco | Parâmetros |", "|---|---|---|---|"]
    for k, v in PRACTICES.items():
        ap = ", ".join(v.get("servers") or v.get("os") or [])
        L.append(f"| `{k}` — {v['label']} | {ap} | {v['risk']} | {', '.join(f'`{p}`' for p in v['params']) or '—'} |")
    return "\n".join(L)


def main() -> None:
    from omxpatch.models import ROLES, TASK_TYPES
    out = [f"# Referência técnica — OMXPatch {__version__}", "", "> Gerada automaticamente a partir do código (`python docs/tools/gen_reference.py`). Não editar à mão.", "",
           "## Perfis", "", *[f"- **{k}** — {v}" for k, v in ROLES.items()], "- **superadmin** — administra todas as organizações e o sistema (sem organização própria).", "",
           "## Parâmetros de configuração", "", "Ordem de precedência: variável de ambiente `OMXPATCH_<NOME>` › `omxpatch.overrides.toml` (alterações feitas na consola) › `omxpatch.toml` › omissão.", "", config_table(), "",
           "## Comandos `omxpatch`", "", cli_help("omxpatch"), "", "## Comandos `omxpatch_agent`", "", cli_help("omxpatch_agent"), "",
           "## Tipos de tarefa", "", "| Tipo | Descrição |", "|---|---|", *[f"| `{k}` | {v} |" for k, v in TASK_TYPES.items()], "",
           "## Boas práticas", "", practices_table(), "", "## Integrações", "", integrations(), "",
           "## Rotas da consola e perfil mínimo", "", routes_by_role(), "", "## API REST v1", "", "Autenticação: `Authorization: Bearer omp_…` (token do perfil do utilizador); super-administradores indicam a organização em `X-Tenant-ID`.", "", api_routes(), ""]
    (ROOT / "docs" / "REFERENCIA.md").write_text("\n".join(out), encoding="utf-8")
    print("docs/REFERENCIA.md gerado:", sum(len(x) for x in out), "caracteres")


if __name__ == "__main__":
    main()
