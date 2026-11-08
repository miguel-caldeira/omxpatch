"""nginx e Apache: deteção, plano de alterações (com *diff*), teste da configuração, aplicação com reversão e verificação TLS.

Estratégia: cada boa prática vive num ficheiro gerido (``omxpatch-<prática>.conf``) carregado pelo servidor, e as diretivas
equivalentes já existentes noutros ficheiros (que as sobrepõem, p. ex. ``ssl_protocols`` num ``server {}``) são
corrigidas no sítio. Nada é escrito antes de o plano ser aprovado; a aplicação faz cópia de segurança, testa a
configuração (``nginx -t`` / ``apachectl -t``), recarrega e verifica o TLS — e **reverte sozinha** se algum passo falhar."""
from __future__ import annotations

import re
import time
from pathlib import Path

from ..runner import run
from . import common
from .common import Edit, has_line, replace_directives, which

SNIPPET_NAMES = {"tls_protocols": "omxpatch-tls.conf", "hsts": "omxpatch-hsts.conf", "hide_version": "omxpatch-hide-version.conf",
                 "security_headers": "omxpatch-headers.conf"}
HEADERS = (("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "SAMEORIGIN"), ("Referrer-Policy", "same-origin"))


def _ver(text: str, rx: str) -> tuple[int, ...]:
    m = re.search(rx, text)
    return tuple(int(x) for x in m.group(1).split(".")) if m else ()


def hsts_value(params: dict) -> str:
    v = f"max-age={int(params.get('max_age') or common.HSTS_DEFAULT_MAX_AGE)}"
    if params.get("include_subdomains", True):
        v += "; includeSubDomains"
    if params.get("preload"):
        v += "; preload"
    return v


class WebServer:
    name = "?"
    label = "?"
    binary_names: tuple[str, ...] = ()

    # ----- deteção
    def binary(self) -> str | None:
        for b in self.binary_names:
            p = which(b)
            if p:
                return p
        return None

    def running(self) -> bool:
        return run(["pgrep", "-x", self.process], 10).rc == 0

    def detect(self) -> dict | None:
        raise NotImplementedError

    # ----- a definir por cada servidor
    process = ""

    def files(self) -> dict[str, str]:
        raise NotImplementedError

    def snippet_dir(self) -> str | None:
        raise NotImplementedError

    def directives(self, practice: str, params: dict, info: dict) -> list[tuple[str, str, str]]:
        """[(padrão da linha existente, linha desejada, módulo exigido ou '')]."""
        raise NotImplementedError

    def render_snippet(self, practice: str, dirs: list[tuple[str, str, str]]) -> str:
        raise NotImplementedError

    def test_cmd(self) -> list[str]:
        raise NotImplementedError

    def reload_cmd(self) -> list[str]:
        raise NotImplementedError

    def tls13_supported(self, info: dict) -> bool:
        raise NotImplementedError

    def extra_checks(self, practice: str, params: dict, info: dict) -> list[dict]:
        return []

    def snippet_dirs(self, dirs, files: dict[str, str], snippet: str | None):
        """Diretivas que o ficheiro gerido tem de conter (por omissão, todas)."""
        return dirs

    # ----- plano
    def plan(self, practice: str, params: dict) -> dict:
        info = self.detect()
        checks: list[dict] = []
        if info is None:
            return {"info": None, "edits": [], "checks": [_c("server", f"{self.label} instalado", "block", "não encontrado")], "predicted": {}}
        checks.append(_c("server", f"{self.label} detetado", "ok", f"{info['version']} — {info['config']}"))
        base = run(self.test_cmd(), 60)
        checks.append(_c("config_test", f"Configuração atual válida ({' '.join(self.test_cmd()[:2])})", "ok" if base.ok else "block",
                         "" if base.ok else base.out.strip()[-250:]))
        want13 = params.get("tls13", "auto")
        if practice == "tls_protocols":
            sup = self.tls13_supported(info)
            if want13 in (True, "true") and not sup:
                checks.append(_c("tls13", "TLS 1.3 suportado", "block", "A versão do servidor/OpenSSL não suporta TLS 1.3"))
            elif sup:
                checks.append(_c("tls13", "TLS 1.3 suportado", "ok", "OpenSSL ≥ 1.1.1"))
            else:
                checks.append(_c("tls13", "TLS 1.3 suportado", "warn", "Não suportado nesta versão: só será configurado o TLS 1.2"))
            info["tls13"] = sup and want13 not in (False, "false")
        if practice == "hsts" and not info.get("ports"):
            checks.append(_c("https", "Listener HTTPS", "warn", "Nenhum listener TLS detetado: o HSTS só tem efeito em HTTPS"))
        checks += self.extra_checks(practice, params, info)
        dirs = self.directives(practice, params, info)
        needed_modules = {m for _, _, m in dirs if m}
        files = self.files() if base.ok else {}
        snippet_dir = self.snippet_dir()
        snippet = str(Path(snippet_dir) / SNIPPET_NAMES[practice]) if snippet_dir else None
        edits: list[Edit] = []
        if not snippet_dir:
            checks.append(_c("snippet_dir", "Diretório de configuração incluído", "block", "Não foi possível localizar uma pasta de ficheiros incluídos (conf.d / conf-enabled)"))
        else:
            new_snip = self.render_snippet(practice, self.snippet_dirs(dirs, files, snippet))
            old_snip = files.get(snippet)
            if old_snip is None and Path(snippet).is_file():
                old_snip = Path(snippet).read_text(encoding="utf-8", errors="replace")
            e = Edit(snippet, old_snip, new_snip, "ficheiro gerido pelo OMXPatch com a boa prática")
            if e.changed and (old_snip is not None or self.snippet_dirs(dirs, files, snippet)):
                edits.append(e)
        overrides = 0
        for path, text in files.items():
            if path == snippet or SNIPPET_PREFIX in Path(path).name:
                continue
            new = text
            for pattern, line, _mod in dirs:
                new, n = replace_directives(new, pattern, line)
                overrides += n
            if new != text:
                edits.append(Edit(path, text, new, "corrige diretivas que sobrepõem a boa prática"))
        if overrides:
            checks.append(_c("overrides", "Diretivas que sobrepõem a boa prática", "info", f"{overrides} linha(s) a corrigir noutros ficheiros"))
        compliant = not edits
        return {"info": info, "edits": edits, "checks": checks, "needed_modules": sorted(needed_modules),
                "predicted": {"compliant": compliant, "files": len(edits), "reload": bool(edits) and info.get("running", False)}}

    # ----- aplicação
    def apply(self, practice: str, params: dict, item: str) -> dict:
        plan = self.plan(practice, params)
        edits = [e for e in plan["edits"] if e.changed]
        blocks = [c for c in plan["checks"] if c["status"] == "block"]
        if blocks:
            return {"status": "failed", "output": "Pré-requisitos falhados: " + "; ".join(f"{c['label']}: {c['detail']}" for c in blocks),
                    "actions": [], "rolled_back": False}
        if not edits:
            return {"status": "succeeded", "output": "Já em conformidade: nada a alterar.", "actions": [], "rolled_back": False,
                    "verification": self.verify(plan["info"], practice, plan)}
        common.save_backup(f"{item}-{self.name}", edits)
        actions = [e.action() for e in edits]
        try:
            for e in edits:
                common.write_atomic(e.path, e.new)
        except OSError as exc:
            self.rollback(item)
            return {"status": "failed", "output": f"Falha a escrever: {exc}", "actions": actions, "rolled_back": True}
        t = run(self.test_cmd(), 60)
        if not t.ok:
            self.rollback(item)
            return {"status": "failed", "output": f"Teste da configuração falhou; alterações revertidas.\n{t.out.strip()[-400:]}", "actions": actions,
                    "rolled_back": True}
        reload_out = ""
        if plan["info"].get("running"):
            r = run(self.reload_cmd(), 60)
            reload_out = r.out.strip()
            if not r.ok:
                self.rollback(item)
                self._reload_quiet()
                return {"status": "failed", "output": f"Recarga falhou; alterações revertidas.\n{reload_out[-300:]}", "actions": actions, "rolled_back": True}
            time.sleep(1.0)
        ver = self.verify(plan["info"], practice, plan)
        if ver.get("ok") is False:
            self.rollback(item)
            self._reload_quiet()
            return {"status": "failed", "output": "Verificação TLS falhou depois da aplicação; alterações revertidas: " + "; ".join(ver.get("problems", [])),
                    "actions": actions, "verification": ver, "rolled_back": True}
        return {"status": "succeeded", "output": f"{len(edits)} ficheiro(s) alterado(s); configuração testada" +
                                                   ("; serviço recarregado" if plan["info"].get("running") else "; serviço parado (não recarregado)"),
                "actions": actions, "verification": ver, "rolled_back": False}

    def rollback(self, item: str) -> list[str]:
        return common.restore_backup(f"{item}-{self.name}")

    def _reload_quiet(self) -> None:
        try:
            if self.detect() and self.detect().get("running"):
                run(self.reload_cmd(), 60)
        except Exception:  # noqa: BLE001
            pass

    # ----- verificação
    def verify(self, info: dict, practice: str, plan: dict) -> dict:
        ports = [p for p in info.get("ports", []) if common.tls_speaks("127.0.0.1", p)] if info.get("running") else []
        if practice != "tls_protocols":
            return {"ok": None, "detail": "sem verificação TLS para esta prática", "ports": ports}
        if not ports:
            return {"ok": None, "detail": "sem listener TLS ativo para verificar", "ports": []}
        res, problems = {}, []
        for p in ports:
            m = common.tls_matrix("127.0.0.1", p)
            ok, bad = common.judge_matrix(m, bool(info.get("tls13")))
            res[str(p)] = m
            problems += [f"porta {p}: {b}" for b in bad]
        return {"ok": not problems, "matrix": res, "problems": problems, "ports": ports}


SNIPPET_PREFIX = "omxpatch-"


def _c(cid: str, label: str, status: str, detail: str = "") -> dict:
    return {"id": cid, "label": label, "status": status, "detail": detail}


# =========================================================================== nginx


class Nginx(WebServer):
    name, label, process = "nginx", "nginx", "nginx"
    binary_names = ("nginx",)

    def _v(self) -> str:
        return run([self.binary() or "nginx", "-V"], 30).out

    def detect(self) -> dict | None:
        b = self.binary()
        if not b:
            return None
        out = self._v()
        ver = ".".join(map(str, _ver(out, r"nginx/(\d+\.\d+\.\d+)"))) or "?"
        conf = (re.search(r"--conf-path=(\S+)", out) or [None, "/etc/nginx/nginx.conf"])[1]
        files = self.files()
        ports = sorted({int(p) for t in files.values() for p in re.findall(r"^\s*listen\s+(?:[\w.\[\]:*]+:)?(\d+)\b[^;]*\bssl\b", t, re.M)})
        return {"type": "nginx", "version": ver, "binary": b, "config": conf, "running": self.running(), "ports": ports}

    def files(self) -> dict[str, str]:
        r = run([self.binary() or "nginx", "-T"], 60)
        out, cur, buf = {}, None, []
        for line in r.out.splitlines():
            m = re.match(r"^# configuration file (.+):$", line)
            if m:
                if cur:
                    out[cur] = "\n".join(buf) + "\n"
                cur, buf = m.group(1), []
            elif cur:
                buf.append(line)
        if cur:
            out[cur] = "\n".join(buf) + "\n"
        for path in list(out):                  # o texto fiel vem do disco (o «nginx -T» acrescenta linhas em branco)
            try:
                out[path] = Path(path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        return out

    def snippet_dir(self) -> str | None:
        files = self.files()
        main = next(iter(files), None)
        if main and has_line(files[main], r"include\s+[^;]*conf\.d/\*\.conf"):
            return str(Path(main).parent / "conf.d")
        for p in files:                          # alguma pasta conf.d já é carregada
            if Path(p).parent.name == "conf.d":
                return str(Path(p).parent)
        return None

    def tls13_supported(self, info: dict) -> bool:
        v = _ver(self._v(), r"built with OpenSSL (\d+\.\d+\.\d+)")
        return bool(v) and v >= (1, 1, 1)

    def directives(self, practice, params, info):
        if practice == "tls_protocols":
            protos = "TLSv1.2 TLSv1.3" if info.get("tls13", True) else "TLSv1.2"
            return [(r"ssl_protocols\s", f"ssl_protocols {protos};", ""),
                    (r"ssl_ciphers\s", f"ssl_ciphers {common.INTERMEDIATE_CIPHERS};", ""),
                    (r"ssl_prefer_server_ciphers\s", "ssl_prefer_server_ciphers off;", "")]
        if practice == "hsts":
            return [(r"add_header\s+Strict-Transport-Security\b", f'add_header Strict-Transport-Security "{hsts_value(params)}" always;', "")]
        if practice == "hide_version":
            return [(r"server_tokens\s", "server_tokens off;", "")]
        if practice == "security_headers":
            return [(rf"add_header\s+{h}\b", f'add_header {h} "{v}" always;', "") for h, v in HEADERS]
        raise ValueError(practice)

    def render_snippet(self, practice, dirs):
        return f"# Gerido pelo OMXPatch (boa prática: {practice}). Alterações manuais serão repostas.\n" + "\n".join(l for _, l, _ in dirs) + "\n"

    def snippet_dirs(self, dirs, files, snippet):
        """O nginx rejeita a mesma diretiva repetida no mesmo nível: se já existe uma ao nível ``http`` (corrigida no sítio),
        não se repete no ficheiro gerido; as que só existem em ``server``/``location`` obrigam a definir o valor por omissão em ``http``."""
        http_level = nginx_http_level_patterns(files, snippet, [p for p, _, _ in dirs])
        return [d for d in dirs if d[0] not in http_level]

    def test_cmd(self):
        return [self.binary() or "nginx", "-t"]

    def reload_cmd(self):
        return [self.binary() or "nginx", "-s", "reload"]

    def extra_checks(self, practice, params, info):
        if practice in ("hsts", "security_headers"):
            return [_c("add_header_inheritance", "Herança de add_header", "info",
                       "No nginx, um add_header num bloco server/location anula os do nível acima; as ocorrências existentes são corrigidas, mas confirme blocos com cabeçalhos próprios")]
        return []


# =========================================================================== Apache


class Apache(WebServer):
    name, label = "apache", "Apache HTTP Server"
    binary_names = ("apache2ctl", "apachectl", "httpd")

    @property
    def process(self):  # type: ignore[override]
        return "apache2" if (self.binary() or "").endswith(("apache2ctl",)) else "httpd"

    def _run(self, *args: str):
        return run([self.binary() or "apachectl", *args], 60)

    def detect(self) -> dict | None:
        if not self.binary():
            return None
        v = self._run("-v").out
        ver = ".".join(map(str, _ver(v, r"Apache/(\d+\.\d+\.\d+)"))) or "?"
        files = self.files()
        main = next(iter(files), "?")
        ports = set()
        for t in files.values():
            for m in re.finditer(r"^\s*<VirtualHost[^>]*:(\d+)\s*>(.*?)</VirtualHost>", t, re.M | re.S):
                if re.search(r"^\s*SSLEngine\s+on", m.group(2), re.M | re.I):
                    ports.add(int(m.group(1)))
            if has_line(t, r"SSLEngine\s+on"):
                ports |= {int(x) for x in re.findall(r"^\s*Listen\s+(?:[\w.\[\]:*]+:)?(\d+)\b", t, re.M) if x == "443"}
        return {"type": "apache", "version": ver, "binary": self.binary(), "config": main, "running": self.running(), "ports": sorted(ports),
                "modules": self._run("-M").out}

    def files(self) -> dict[str, str]:
        r = self._run("-t", "-D", "DUMP_INCLUDES")
        out = {}
        for m in re.finditer(r"\((?:\*|\d+)\)\s+(\S+)", r.out):
            p = m.group(1)
            if Path(p).is_file() and p not in out:
                out[p] = Path(p).read_text(encoding="utf-8", errors="replace")
        return out

    def snippet_dir(self) -> str | None:
        for d in ("/etc/apache2/conf-enabled", "/etc/httpd/conf.d", "/etc/apache2/conf.d"):
            if Path(d).is_dir():
                return d
        return None

    def tls13_supported(self, info):
        a = _ver(info.get("version", ""), r"(\d+\.\d+\.\d+)")
        o = _ver(run(["openssl", "version"], 10).out, r"OpenSSL (\d+\.\d+\.\d+)")
        return bool(a) and a >= (2, 4, 36) and bool(o) and o >= (1, 1, 1)

    def directives(self, practice, params, info):
        if practice == "tls_protocols":
            protos = "-all +TLSv1.2 +TLSv1.3" if info.get("tls13", True) else "-all +TLSv1.2"
            return [(r"SSLProtocol\s", f"SSLProtocol {protos}", "mod_ssl.c"),
                    (r"SSLCipherSuite\s+(?!TLSv1\.3)", f"SSLCipherSuite {common.INTERMEDIATE_CIPHERS}", "mod_ssl.c"),
                    (r"SSLHonorCipherOrder\s", "SSLHonorCipherOrder off", "mod_ssl.c")]
        if practice == "hsts":
            return [(r"Header\s+(always\s+)?(set|append|merge|unset)\s+Strict-Transport-Security\b",
                     f'Header always set Strict-Transport-Security "{hsts_value(params)}"', "mod_headers.c")]
        if practice == "hide_version":
            return [(r"ServerTokens\s", "ServerTokens Prod", ""), (r"ServerSignature\s", "ServerSignature Off", "")]
        if practice == "security_headers":
            return [(rf"Header\s+(always\s+)?(set|append|merge|unset)\s+{h}\b", f'Header always set {h} "{v}"', "mod_headers.c") for h, v in HEADERS]
        raise ValueError(practice)

    def render_snippet(self, practice, dirs):
        head = f"# Gerido pelo OMXPatch (boa prática: {practice}). Alterações manuais serão repostas.\n"
        body = []
        for mod in dict.fromkeys(m for _, _, m in dirs):
            lines = [l for _, l, m in dirs if m == mod]
            body += ([f"<IfModule {mod}>", *[f"    {l}" for l in lines], "</IfModule>"] if mod else lines)
        return head + "\n".join(body) + "\n"

    def test_cmd(self):
        return [self.binary() or "apachectl", "-t"]

    def reload_cmd(self):
        return [self.binary() or "apachectl", "graceful"]

    def extra_checks(self, practice, params, info):
        mods = info.get("modules", "")
        out = []
        if practice == "tls_protocols":
            out.append(_c("mod_ssl", "mod_ssl carregado", "ok" if "ssl_module" in mods else "warn",
                          "" if "ssl_module" in mods else "mod_ssl não está carregado: as diretivas ficam em <IfModule> e só atuam quando o SSL for ativado"))
        if practice in ("hsts", "security_headers"):
            out.append(_c("mod_headers", "mod_headers carregado", "ok" if "headers_module" in mods else "warn",
                          "" if "headers_module" in mods else "mod_headers não está carregado (a2enmod headers): os cabeçalhos não serão enviados"))
        return out


def nginx_statements(text: str):
    """[(instrução, pilha de blocos, n.º da linha)] — comentários e cadeias tratados; a pilha tem o nome de cada bloco aberto."""
    out, stack, buf, line, start, i, n = [], [], [], 1, 1, 0, len(text)
    q = ""
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
        if q:
            buf.append(ch)
            if ch == q and text[i - 1] != "\\":
                q = ""
        elif ch in "\"'":
            q = ch
            buf.append(ch)
        elif ch == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif ch == "{":
            head = "".join(buf).split()
            stack.append(head[0] if head else "")
            buf = []
        elif ch == "}":
            if stack:
                stack.pop()
            buf = []
        elif ch == ";":
            stmt = " ".join("".join(buf).split())
            if stmt:
                out.append((stmt, tuple(stack), start))
            buf = []
        else:
            if not buf and not ch.isspace():
                start = line
            buf.append(ch)
        i += 1
    return out


def nginx_include_contexts(files: dict[str, str]) -> dict[str, str]:
    """Contexto (http/server/…) em que cada ficheiro é incluído, seguindo as instruções ``include``."""
    import glob
    paths = list(files)
    if not paths:
        return {}
    base = str(Path(paths[0]).parent)
    ctx = {p: "http" for p in paths[1:]}
    for _ in range(3):
        for path, text in files.items():
            for stmt, stack, _ln in nginx_statements(text):
                m = re.match(r"include\s+(\S+)$", stmt)
                if not m:
                    continue
                pat = m.group(1).strip("\"'")
                pat = pat if pat.startswith("/") else str(Path(base) / pat)
                here = stack[-1] if stack else ctx.get(path, "main")
                for hit in glob.glob(pat):
                    if hit in ctx or hit in files:
                        ctx[hit] = here
    return ctx


def nginx_http_level_patterns(files: dict[str, str], snippet: str | None, patterns: list[str]) -> set[str]:
    ctx = nginx_include_contexts(files)
    found = set()
    for path, text in files.items():
        if path == snippet or SNIPPET_PREFIX in Path(path).name:
            continue
        for stmt, stack, _ln in nginx_statements(text):
            where = stack[-1] if stack else ctx.get(path, "main")
            if where != "http":
                continue
            for pat in patterns:
                if re.match(pat, stmt + " ", re.I):
                    found.add(pat)
    return found


NGINX, APACHE = Nginx(), Apache()
