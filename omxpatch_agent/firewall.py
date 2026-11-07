"""Controlos de firewall local (bloquear porta / IP) e reversão, com verificação da regra aplicada."""
from __future__ import annotations

import ipaddress
import json
import re
import shutil

from . import config
from .config import platform_family
from .runner import run

NAME_RE = re.compile(r"^OMXPatch-[A-Za-z0-9._-]{1,100}$")
PF_ANCHOR = "/etc/pf.anchors/omxpatch"


class FirewallError(RuntimeError):
    pass


def _store_path():
    return config.config_dir() / "firewall-rules.json"


def _load() -> dict:
    try:
        return json.loads(_store_path().read_text())
    except (OSError, ValueError):
        return {}


def _save(rules: dict) -> None:
    config.config_dir().mkdir(parents=True, exist_ok=True)
    _store_path().write_text(json.dumps(rules))


def _port(v) -> int:
    p = int(v)
    if not 1 <= p <= 65535:
        raise FirewallError("Porta inválida")
    return p


def _name(v: str) -> str:
    if not NAME_RE.match(v or ""):
        raise FirewallError("Nome de regra inválido")
    return v


def _ip(v: str) -> str:
    try:
        return str(ipaddress.ip_address(v))
    except ValueError as exc:
        raise FirewallError("O firewall local só aceita endereços IP (use a firewall de rede para domínios)") from exc


def _linux_add(name: str, kind: str, value: str, proto: str) -> str:
    if shutil.which("nft"):
        run(["nft", "add", "table", "inet", "omxpatch"], 30)
        run(["nft", "add", "chain", "inet", "omxpatch", "input", "{", "type", "filter", "hook", "input", "priority", "-10", ";", "policy", "accept", ";", "}"], 30)
        run(["nft", "add", "chain", "inet", "omxpatch", "output", "{", "type", "filter", "hook", "output", "priority", "-10", ";", "policy", "accept", ";", "}"], 30)
        rule = (["inet", "omxpatch", "input", proto, "dport", value, "drop", "comment", f'"{name}"'] if kind == "port"
                else ["inet", "omxpatch", "output", "ip", "daddr", value, "drop", "comment", f'"{name}"'])
        r = run(["nft", "add", "rule", *rule], 30)
        if not r.ok:
            raise FirewallError(r.out)
        return "nftables"
    if shutil.which("iptables"):
        args = (["-I", "INPUT", "-p", proto, "--dport", value] if kind == "port" else ["-I", "OUTPUT", "-d", value]) + \
               ["-j", "DROP", "-m", "comment", "--comment", name]
        r = run(["iptables", *args], 30)
        if not r.ok:
            raise FirewallError(r.out)
        return "iptables"
    raise FirewallError("Sem nftables nem iptables")


def _linux_remove(name: str, kind: str, value: str, proto: str) -> None:
    if shutil.which("nft"):
        listing = run(["nft", "-a", "list", "table", "inet", "omxpatch"], 30).out
        chain = None
        for line in listing.splitlines():
            m = re.match(r"\s*chain (\w+)", line)
            if m:
                chain = m.group(1)
            h = re.search(rf'comment "{re.escape(name)}".*# handle (\d+)|comment "{re.escape(name)}" # handle (\d+)', line)
            if h and chain:
                run(["nft", "delete", "rule", "inet", "omxpatch", chain, "handle", h.group(1) or h.group(2)], 30)
    if shutil.which("iptables"):
        args = (["-D", "INPUT", "-p", proto, "--dport", value] if kind == "port" else ["-D", "OUTPUT", "-d", value]) + \
               ["-j", "DROP", "-m", "comment", "--comment", name]
        run(["iptables", *args], 30)


def _pf_apply(rules: dict) -> None:
    lines = []
    for r in rules.values():
        lines.append(f"block in quick proto {r['proto']} from any to any port {r['value']}" if r["kind"] == "port"
                     else f"block out quick from any to {r['value']}")
    from pathlib import Path
    Path(PF_ANCHOR).write_text("\n".join(lines) + "\n")
    run(["pfctl", "-E"], 30)
    res = run(["pfctl", "-a", "omxpatch", "-f", PF_ANCHOR], 30)
    if not res.ok and "pf already enabled" not in res.out.lower():
        raise FirewallError(res.out)


def block(op: dict) -> dict:
    name = _name(op["name"])
    fam = platform_family()
    if op["op"] == "firewall_block_port":
        kind, value, proto = "port", str(_port(op["port"])), (op.get("proto") or "tcp").lower()
        if proto not in ("tcp", "udp"):
            raise FirewallError("Protocolo inválido")
    else:
        kind, value, proto = "ioc", _ip(op["ioc"]), "tcp"
    rules = _load()
    if fam == "windows":
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}",
               f"dir={'in' if kind == 'port' else 'out'}", "action=block"]
        cmd += [f"protocol={proto.upper()}", f"localport={value}"] if kind == "port" else [f"remoteip={value}"]
        r = run(cmd, 60)
        if not r.ok:
            raise FirewallError(r.out)
        backend = "netsh"
    elif fam == "macos":
        rules[name] = {"kind": kind, "value": value, "proto": proto}
        _pf_apply(rules)
        backend = "pf"
    else:
        backend = _linux_add(name, kind, value, proto)
    rules[name] = {"kind": kind, "value": value, "proto": proto}
    _save(rules)
    return {"verified": verify(name), "detail": f"Regra {name} aplicada ({backend})"}


def remove(op: dict) -> dict:
    name = _name(op["name"])
    rules = _load()
    r = rules.pop(name, None)
    fam = platform_family()
    if fam == "windows":
        run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"], 60)
    elif fam == "macos":
        _pf_apply(rules)
    elif r:
        _linux_remove(name, r["kind"], r["value"], r["proto"])
    _save(rules)
    return {"detail": f"Regra {name} removida"}


def verify(name: str) -> bool:
    fam = platform_family()
    if fam == "windows":
        return run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"], 60).ok
    if fam == "macos":
        return name in _load()
    if shutil.which("nft") and name in run(["nft", "list", "table", "inet", "omxpatch"], 30).out:
        return True
    return bool(shutil.which("iptables")) and run(["iptables", "-S"], 30).out.count(name) > 0
