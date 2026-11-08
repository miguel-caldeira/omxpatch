"""Simulação de exposição (Exposure Validation) — **no servidor**, sem qualquer impacto no ativo.

Cruza a vulnerabilidade com o contexto real recolhido pelo agente (processos, quem escuta e a partir de onde, firewall, acessos) e com a
inteligência (KEV, maturidade do exploit, EPSS, vetor CVSS) para responder: *esta falha pode mesmo ser explorada aqui?* O resultado
é um caminho de ataque em passos (cada um ok / falha / desconhecido) e um veredito:

* ``confirmed`` — componente a correr, alcançável e sem barreiras, com exploração conhecida;
* ``likely`` — alcançável e sem barreiras (sem exploração conhecida) ou barreiras incompletas;
* ``unlikely`` — protegida por controlos ou exige privilégios/acesso local não obtido;
* ``unreachable`` — o contexto prova que não é alcançável (processo parado, escuta só em loopback, firewall bloqueia);
* ``unknown`` — ainda não há contexto do ativo (o agente envia-o com o inventário).

Falsos positivos reduzem-se porque ``unreachable``/``unlikely`` baixam a prioridade (ver ``engine/priority``)."""
from __future__ import annotations

import json
import re

from ..models import Asset, ControlAction, CveIntel, Exposure, utcnow
from . import risk

WEIGHT = {"confirmed": 1.0, "likely": 0.6, "unlikely": 0.2, "unreachable": 0.03, "unknown": 0.5}
LABEL = {"confirmed": "Exploração confirmada como viável", "likely": "Exploração provável", "unlikely": "Exploração improvável",
         "unreachable": "Não alcançável neste ativo", "unknown": "Sem contexto do ativo"}
LIB_HINT = re.compile(r"(^lib|openssl|glibc|libc|zlib|kernel|linux|ssl|tls|curl|expat|sqlite|pcre|gnutls|nss|ca-cert)", re.I)


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def attack_vector(cve: CveIntel | None) -> str:
    """N (rede), A (adjacente), L (local), P (físico) a partir do vetor CVSS; N se desconhecido (pior caso)."""
    m = re.search(r"AV:([NALP])", (cve.cvss_vector if cve else "") or "")
    return m.group(1) if m else "N"


def privileges_required(cve: CveIntel | None) -> str:
    m = re.search(r"PR:([NLH])", (cve.cvss_vector if cve else "") or "")
    return m.group(1) if m else "N"


def _match_running(software: str, ctx: dict) -> tuple[bool | None, str, list[dict]]:
    """O componente está a correr? Devolve (sim/não/desconhecido, detalhe, escutas associadas)."""
    key = _norm(software.split(" ")[0] if " " in software.strip() else software)
    full = _norm(software)
    procs = [p for p in ctx.get("processes", []) if key and (key in _norm(p.get("name", "")) or _norm(p.get("name", "")) in (key, full) and len(_norm(p.get("name", ""))) > 2)]
    svcs = [s for s in ctx.get("services", []) if key and key in _norm(s.get("name", ""))]
    listens = [l for l in ctx.get("listeners", []) if key and (key in _norm(l.get("process", "")) or (l.get("exe") and key in _norm(l["exe"])))]
    if procs or svcs or listens:
        names = sorted({p.get("name", "") for p in procs} | {s["name"] for s in svcs})[:4]
        return True, "em execução: " + (", ".join(names) or "escuta ativa"), listens
    if LIB_HINT.search(software or ""):
        return None, "biblioteca/componente de sistema: não há processo próprio a verificar", []
    if not ctx.get("processes") and not ctx.get("services") and not ctx.get("listeners"):
        return None, "sem lista de processos", []
    return False, "nenhum processo, serviço ou escuta com este nome", []


def _firewall_allows(fw: dict, port: int | None) -> tuple[bool | None, str]:
    if not fw or not fw.get("engine") and not fw.get("enabled"):
        return (True, "sem firewall ativa no ativo") if fw else (None, "estado da firewall desconhecido")
    if not fw.get("enabled"):
        return True, f"firewall ({fw.get('engine') or '?'}) desativada"
    din = (fw.get("default_in") or "").lower()
    if din in ("deny", "drop", "block", "reject"):
        if not port:
            return None, "componente sem porta de rede associada: a firewall não se aplica diretamente"
        if port in (fw.get("allow_in_ports") or []):
            return True, f"firewall permite a porta {port}"
        if port and fw.get("engine") in ("windows", "alf"):
            return None, "firewall bloqueia por omissão; regras de aplicação não avaliadas"
        return False, "firewall bloqueia por omissão" + (f" e a porta {port} não está permitida" if port else "")
    return True, f"política de entrada «{din or 'accept'}»"


def simulate(ex: Exposure, cve: CveIntel | None, asset: Asset, controls: list[ControlAction], verdict: dict) -> dict:
    ctx = (asset.hw or {}).get("context") or {}
    steps: list[dict] = []

    def add(sid, label, status, detail=""):
        steps.append({"id": sid, "label": label, "status": status, "detail": detail})
    vulnerable = ex.status in ("open", "mitigated", "patching")
    add("vulnerable", "Software em versão vulnerável", "ok" if vulnerable else "fail", f"{ex.software_name or 'componente'} {ex.installed_version or ''}".strip())
    if not ctx:
        add("context", "Contexto do ativo recolhido pelo agente", "unknown", "o agente ainda não enviou processos, escutas e firewall")
    av, pr = attack_vector(cve), privileges_required(cve)
    add("vector", "Vetor de ataque", "ok" if av in ("N", "A") else "unknown", {"N": "rede (remoto)", "A": "rede adjacente", "L": "local (exige acesso ao sistema)", "P": "físico"}[av])
    running, rdetail, listens = (None, "", [])
    if ctx:
        running, rdetail, listens = _match_running(ex.software_name or "", ctx)
        add("running", "Componente em execução", {True: "ok", False: "fail", None: "unknown"}[running], rdetail)
    port = ex.port or (listens[0]["port"] if listens else None)
    reach = None
    if ctx and av in ("N", "A"):
        if listens:
            net = [l for l in listens if l.get("scope") in ("all", "lan")]
            reach = bool(net)
            add("listening", "Escuta acessível pela rede", "ok" if net else "fail",
                ", ".join(f"{l['port']}/{l.get('scope')}" for l in (net or listens)[:4]) + ("" if net else " (só loopback)"))
            port = (net or listens)[0]["port"]
        elif port:
            lp = [l for l in ctx.get("listeners", []) if l.get("port") == port]
            reach = bool(lp and any(l.get("scope") in ("all", "lan") for l in lp)) if lp else None
            add("listening", f"Porta {port} acessível pela rede", {True: "ok", False: "fail", None: "unknown"}[reach],
                "ninguém escuta nesta porta" if lp == [] and ctx.get("listeners") else ("escuta só em loopback" if reach is False else ""))
            if lp == [] and ctx.get("listeners"):
                reach = False
        else:
            add("listening", "Escuta acessível pela rede", "unknown", "sem porta associada (componente sem serviço de rede)")
    fw_ok, fw_detail = _firewall_allows(ctx.get("firewall") or {}, port) if ctx else (None, "")
    if ctx and av in ("N", "A"):
        add("firewall", "Firewall do ativo permite o acesso", {True: "ok", False: "fail", None: "unknown"}[fw_ok], fw_detail)
    exposed = risk.internet_exposed(asset)
    add("internet", "Ativo exposto à Internet", "ok" if exposed else "unknown", "IP público ou marcado como exposto" if exposed else "só rede interna")
    eff = [c for c in controls if c.status in risk.EFFECTIVE_STATUS]
    barrier = bool(eff) or verdict.get("firewall_blocks") is True or verdict.get("edr_detects") is True or verdict.get("waf_protected")
    add("controls", "Sem controlos compensatórios eficazes", "fail" if barrier else "ok", ", ".join(sorted({c.action for c in eff})) or ("barreira de firewall/EDR/WAF" if barrier else "nenhum"))
    kev, maturity, epss = bool(cve and cve.kev), (cve.exploit_maturity if cve else "none"), (cve.epss if cve and cve.epss is not None else 0)
    known = kev or maturity in ("functional", "weaponized") or verdict.get("active_exploitation_observed")
    add("exploit", "Exploração conhecida", "ok" if known else ("unknown" if maturity == "poc" or epss >= 0.1 else "fail"),
        "CISA KEV" if kev else (f"exploit {maturity}" if maturity not in ("none", "") else f"EPSS {epss:.0%}"))
    if pr == "H":
        add("privileges", "Privilégios necessários", "fail", "exige privilégios elevados já obtidos")
    elif pr == "L" and av in ("L", "P"):
        add("privileges", "Privilégios necessários", "unknown", "exige uma conta local de baixo privilégio")
    # --- veredito
    st = {s["id"]: s["status"] for s in steps}
    if not ctx:
        verdict_code = "unknown"
    elif not vulnerable:
        verdict_code = "unreachable"
    elif av in ("L", "P"):
        admins = ((ctx.get("access") or {}).get("admins") or [])
        verdict_code = "unlikely" if st.get("privileges") == "fail" or not admins else "likely"
    elif st.get("running") == "fail" or st.get("listening") == "fail" or st.get("firewall") == "fail":
        verdict_code = "unreachable"
    elif barrier or st.get("privileges") == "fail":
        verdict_code = "unlikely"
    elif known and st.get("running") in ("ok", "unknown") and st.get("listening") in ("ok", "unknown", None) and st.get("firewall") in ("ok", "unknown", None):
        verdict_code = "confirmed" if (st.get("running") == "ok" and st.get("listening") == "ok") or exposed else "likely"
    else:
        verdict_code = "likely"
    unknowns = sum(1 for s in steps if s["status"] == "unknown")
    return {"verdict": verdict_code, "label": LABEL[verdict_code], "weight": WEIGHT[verdict_code], "confidence": round(max(0.2, 1 - 0.15 * unknowns), 2), "steps": steps,
            "summary": f"{LABEL[verdict_code]}: " + "; ".join(s["detail"] or s["label"] for s in steps if s["status"] == "fail")[:240] if verdict_code in ("unreachable", "unlikely")
            else LABEL[verdict_code], "at": utcnow().isoformat()}


def apply(ex: Exposure, cve: CveIntel | None, asset: Asset, controls: list[ControlAction], verdict: dict) -> dict:
    res = simulate(ex, cve, asset, controls, verdict)
    ex.exploitability, ex.exposure_sim, ex.sim_at = res["verdict"], json.dumps(res, ensure_ascii=False), utcnow()
    return res


# --------------------------------------------------------------------------- postura do ativo (configurações incorretas)


def misconfigurations(asset: Asset) -> list[dict]:
    """Configurações fracas do ativo (do contexto do agente), cada uma com a ação recomendada. Cálculo no servidor."""
    ctx = (asset.hw or {}).get("context") or {}
    out = []
    if not ctx:
        return out
    fw, acc, sec = ctx.get("firewall") or {}, ctx.get("access") or {}, ctx.get("security") or {}
    ssh = acc.get("ssh") or {}

    def add(fid, sev, text, fix):
        out.append({"id": fid, "severity": sev, "text": text, "fix": fix})
    if fw and not fw.get("enabled"):
        add("firewall_off", "high", "Firewall do ativo desativada", {"type": "control", "action": "block_port", "hint": "ative a firewall do SO"})
    if ssh.get("permit_root_login") in ("yes", "without-password", "prohibit-password") and ssh.get("permit_root_login") == "yes":
        add("ssh_root", "high", "SSH permite início de sessão como root", {"type": "practice", "practice": "ssh_hardening"})
    if ssh.get("password_auth") == "yes" and any(l.get("port") == ssh.get("port", 22) and l.get("scope") in ("all", "lan") for l in ctx.get("listeners", [])):
        add("ssh_password", "medium", "SSH aceita palavra-passe e está acessível pela rede", {"type": "practice", "practice": "ssh_hardening"})
    if ssh.get("permit_empty") == "yes":
        add("ssh_empty", "critical", "SSH permite palavras-passe vazias", {"type": "practice", "practice": "ssh_hardening"})
    if acc.get("smb1"):
        add("smb1", "high", "SMBv1 ativo", {"type": "practice", "practice": "windows_hardening"})
    if acc.get("rdp_enabled") and not acc.get("rdp_nla"):
        add("rdp_nla", "high", "RDP ativo sem autenticação ao nível da rede (NLA)", {"type": "practice", "practice": "windows_hardening"})
    if acc.get("uac") is False:
        add("uac_off", "medium", "UAC desativado", {"type": "manual", "hint": "reativar o UAC por política (GPO)"})
    if sec.get("defender_av") is False or sec.get("defender_realtime") is False:
        add("av_off", "high", "Proteção em tempo real do Defender desativada", {"type": "manual", "hint": "reativar o antivírus/EDR"})
    if sec.get("selinux") == "disabled":
        add("selinux_off", "low", "SELinux desativado", {"type": "manual", "hint": "ativar SELinux em modo enforcing"})
    exposed_db = [l for l in ctx.get("listeners", []) if l.get("port") in (3306, 5432, 1433, 27017, 6379, 9200, 11211) and l.get("scope") == "all"]
    for l in exposed_db[:3]:
        add(f"db_open_{l['port']}", "high", f"Serviço de dados ({l.get('process') or l['port']}) escuta em todas as interfaces na porta {l['port']}", {"type": "control", "action": "block_port", "port": l["port"]})
    return out


def lateral_paths(asset: Asset) -> list[dict]:
    """Vetores de movimento lateral possíveis a partir deste ativo, segundo o contexto (serviços de administração acessíveis)."""
    ctx = (asset.hw or {}).get("context") or {}
    names = {445: "SMB", 3389: "RDP", 5985: "WinRM", 5986: "WinRM", 22: "SSH", 135: "RPC"}
    return [{"port": l["port"], "service": names[l["port"]], "scope": l.get("scope"), "process": l.get("process", "")} for l in ctx.get("listeners", [])
            if l.get("port") in names and l.get("scope") in ("all", "lan")]
