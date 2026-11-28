"""Controlos compensatórios nas FIREWALLS DE PERÍMETRO (Check Point, FortiGate, Palo Alto): bloquear um IP/rede ou isolar um ativo na rede,
enquanto o patch não é aplicado («patch virtual» ao nível da rede).

Desenho seguro (só altera a PERTENÇA a um grupo; nunca cria nem reordena regras):
* o administrador cria **uma vez** em cada firewall um grupo (por omissão OMX-BLOCK e OMX-ISOLATE) e uma regra de negação que o referencia;
* o OMXPatch acrescenta/retira objetos desse grupo (FortiGate: grupo de endereços · Palo Alto: etiqueta de um grupo dinâmico, sem *commit* e com
  validade nativa · Check Point: grupo + publicar + instalar a política);
* fluxo igual ao dos restantes controlos: **simular → aprovar → aplicar → verificar → reverter** (validade máxima e reversão automática);
* recusa IP protegidos (o próprio servidor, as firewalls, loopback, redes demasiado largas) e é desligado por omissão (NETCONTROL_ENABLED)."""
from __future__ import annotations

import ipaddress
import json
import re
import time
from datetime import timedelta
from urllib.parse import quote

import requests
from flask import current_app

from ..extensions import db
from ..models import Asset, ControlAction, Tenant, utcnow

NET_ACTIONS = ("fw_block_ip", "fw_isolate")
PLATFORMS = ("fortios", "panos", "checkpoint")
OPT_KEYS = ("group_block", "group_isolate", "vsys", "cp_package", "cp_targets", "cp_domain", "tag_block", "tag_isolate")
TIMEOUT = 20


class FWError(RuntimeError):
    pass


# --------------------------------------------------------------------------- validação do alvo


def _protected_nets(tenant: Tenant) -> list:
    cfg = current_app.config
    nets = []
    raw = [p.strip() for p in re.split(r"[,\s;]+", str(cfg.get("NETCONTROL_PROTECTED") or "")) if p.strip()]
    raw += [x.strip() for x in str(cfg.get("AGENT_SERVER_IP") or "").split(",") if x.strip()]
    for a in Asset.query.filter(Asset.tenant_id == tenant.id, Asset.platform.isnot(None), Asset.platform != ""):     # as próprias firewalls/equipamentos de rede
        if a.ip:
            raw.append(a.ip)
    for r in raw:
        try:
            nets.append(ipaddress.ip_network(r, strict=False))
        except ValueError:
            continue
    return nets


def validate_target(tenant: Tenant, target: str, isolate: bool = False) -> ipaddress._BaseNetwork:
    try:
        net = ipaddress.ip_network(str(target).strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"Endereço/rede inválido: {target}") from exc
    if net.is_loopback or net.is_multicast or net.is_unspecified or net.is_link_local or net.is_reserved:
        raise ValueError(f"{net} não pode ser bloqueado (loopback, multicast, reservado ou link-local).")
    maxp = int(current_app.config.get("NETCONTROL_MAX_BLOCK_PREFIX", 24))
    if net.version == 4 and net.prefixlen < maxp or net.version == 6 and net.prefixlen < max(maxp + 24, 48):
        raise ValueError(f"A rede {net} é demasiado larga (mínimo /{maxp} em IPv4): bloquear tanto pode cortar serviços inteiros.")
    if isolate and net.num_addresses != 1:
        raise ValueError("O isolamento na firewall aplica-se a um único endereço.")
    for p in _protected_nets(tenant):
        if p.version == net.version and net.overlaps(p):
            raise ValueError(f"{net} sobrepõe-se a um endereço protegido ({p}: o servidor OMXPatch, uma firewall/equipamento de rede ou NETCONTROL_PROTECTED).")
    return net


# --------------------------------------------------------------------------- controladores por fabricante


class Driver:
    name = ""

    def __init__(self, host: str, port: int, token: str, verify: bool, opts: dict):
        self.host, self.port, self.token, self.verify, self.opts = host, int(port or 443), token, verify, opts

    def _http(self, method: str, url: str, **kw):
        try:
            return requests.request(method, url, headers=kw.pop("headers", {}), timeout=TIMEOUT, verify=self.verify, **kw)
        except requests.exceptions.SSLError as exc:
            raise FWError("certificado HTTPS da firewall não confiável (instale a CA ou desative a validação na credencial)") from exc
        except requests.RequestException as exc:
            raise FWError(f"sem ligação à firewall: {exc.__class__.__name__}") from exc

    def group(self, kind: str) -> str:
        return self.opts.get("group_isolate" if kind == "isolate" else "group_block") or ("OMX-ISOLATE" if kind == "isolate" else "OMX-BLOCK")

    # a implementar
    def check(self, kind: str) -> tuple[bool, str]: raise NotImplementedError
    def add(self, kind: str, net, comment: str, ttl_s: int) -> None: raise NotImplementedError
    def remove(self, kind: str, net) -> None: raise NotImplementedError
    def present(self, kind: str, net) -> bool: raise NotImplementedError


def _obj(net) -> str:
    return "OMX-" + str(net).replace("/", "_").replace(":", "-")


class FortiGate(Driver):
    name = "FortiGate"

    def _api(self, method, path, **kw):
        return self._http(method, f"https://{self.host}:{self.port}/api/v2/{path}", headers={"Authorization": f"Bearer {self.token}"}, **kw)

    def _members(self, kind):
        r = self._api("GET", f"cmdb/firewall/addrgrp/{quote(self.group(kind))}")
        if r.status_code == 404:
            return None
        if r.status_code in (401, 403):
            raise FWError("token da API recusado ou sem permissão (perfil de administrador com escrita em «Firewall»)")
        r.raise_for_status()
        return [m.get("name") for m in (r.json().get("results") or [{}])[0].get("member", [])]

    def check(self, kind):
        m = self._members(kind)
        if m is None:
            return False, f"o grupo de endereços «{self.group(kind)}» não existe: crie-o e uma regra de negação que o use (ver manual 19.9)"
        return True, f"grupo «{self.group(kind)}» com {len(m)} membro(s)"

    def add(self, kind, net, comment, ttl_s):
        name, members = _obj(net), self._members(kind)
        if members is None:
            raise FWError(f"o grupo «{self.group(kind)}» não existe")
        if self._api("GET", f"cmdb/firewall/address/{quote(name)}").status_code != 200:
            mask = net.netmask if net.version == 4 else None
            body = {"name": name, "type": "ipmask", "subnet": f"{net.network_address} {mask}", "comment": comment[:250]} if net.version == 4 else \
                   {"name": name, "type": "ipmask", "subnet": str(net), "comment": comment[:250]}
            r = self._api("POST", "cmdb/firewall/address" if net.version == 4 else "cmdb/firewall/address6", json=body)
            if r.status_code not in (200, 424) and not r.ok:
                raise FWError(f"não foi possível criar o objeto {name}: HTTP {r.status_code}")
        if name not in members:
            r = self._api("PUT", f"cmdb/firewall/addrgrp/{quote(self.group(kind))}", json={"member": [{"name": m} for m in members + [name]]})
            if not r.ok:
                raise FWError(f"não foi possível acrescentar ao grupo: HTTP {r.status_code}")

    def remove(self, kind, net):
        name, members = _obj(net), self._members(kind) or []
        if name in members:
            r = self._api("PUT", f"cmdb/firewall/addrgrp/{quote(self.group(kind))}", json={"member": [{"name": m} for m in members if m != name]})
            if not r.ok:
                raise FWError(f"não foi possível retirar do grupo: HTTP {r.status_code}")
        self._api("DELETE", f"cmdb/firewall/address/{quote(name)}")                  # só se já não estiver referenciado (ignora falhas)

    def present(self, kind, net):
        return _obj(net) in (self._members(kind) or [])


class PaloAlto(Driver):
    """Etiquetas de endereço registadas por API (User-ID): sem *commit*, efeito imediato e validade nativa (``timeout``)."""
    name = "Palo Alto"

    def _call(self, params):
        r = self._http("GET", f"https://{self.host}:{self.port}/api/", params=params, headers={"X-PAN-KEY": self.token})
        if r.status_code in (401, 403):
            raise FWError("chave da API recusada ou sem permissão")
        r.raise_for_status()
        if 'status="error"' in r.text:
            msg = re.search(r"<msg>(.*?)</msg>|<line>(.*?)</line>", r.text, re.S)
            raise FWError("PAN-OS: " + ((msg.group(1) or msg.group(2)) if msg else r.text[:150]).strip()[:150])
        return r.text

    def _tag(self, kind):
        return self.opts.get("tag_isolate" if kind == "isolate" else "tag_block") or ("omx-isolate" if kind == "isolate" else "omx-block")

    def check(self, kind):
        vsys = self.opts.get("vsys") or "vsys1"
        xp = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']/address-group/entry[@name='{self.group(kind)}']"
        out = self._call({"type": "config", "action": "get", "xpath": xp})
        if 'count="0"' in out or "<entry" not in out:
            return False, f"o grupo de endereços dinâmico «{self.group(kind)}» (critério de correspondência: etiqueta '{self._tag(kind)}') não existe em {vsys}: crie-o e uma regra de negação (ver manual 19.9)"
        return True, f"grupo dinâmico «{self.group(kind)}» (etiqueta '{self._tag(kind)}')"

    def _uid(self, op, net, ttl_s=0):
        if net.num_addresses != 1:
            raise FWError("o Palo Alto (etiquetas User-ID) só aceita endereços individuais, não redes")
        timeout = f' timeout="{int(ttl_s)}"' if op == "register" and ttl_s else ""
        cmd = (f'<uid-message><version>2.0</version><type>update</type><payload><{op}><entry ip="{net.network_address}"><tag>'
               f'<member{timeout}>{self._tag(self._kind)}</member></tag></entry></{op}></payload></uid-message>')
        self._call({"type": "user-id", "cmd": cmd})

    def add(self, kind, net, comment, ttl_s):
        self._kind = kind
        self._uid("register", net, ttl_s)

    def remove(self, kind, net):
        self._kind = kind
        self._uid("unregister", net)

    def present(self, kind, net):
        out = self._call({"type": "op", "cmd": "<show><object><registered-ip><all/></registered-ip></object></show>"})
        for m in re.finditer(r'<entry ip="([^"]+)"[^>]*>(.*?)</entry>', out, re.S):
            if m.group(1) == str(net.network_address) and self._tag(kind) in m.group(2):
                return True
        return False


class CheckPoint(Driver):
    """API de gestão: objeto + grupo + publicar + instalar a política (pacote e gateways definidos na credencial)."""
    name = "Check Point"

    def _call(self, cmd, body=None, sid=None):
        h = {"Content-Type": "application/json"}
        if sid:
            h["X-chkp-sid"] = sid
        r = self._http("POST", f"https://{self.host}:{self.port}/web_api/{cmd}", headers=h, json=body or {})
        if r.status_code in (401, 403):
            raise FWError("chave da API da gestão Check Point recusada")
        if r.status_code >= 400:
            try:
                msg = r.json().get("message", r.text[:120])
            except ValueError:
                msg = r.text[:120]
            raise FWError(f"Check Point {cmd}: {msg}")
        return r.json()

    def _login(self):
        body = {"api-key": self.token}
        if self.opts.get("cp_domain"):
            body["domain"] = self.opts["cp_domain"]
        return self._call("login", body)["sid"]

    def _session(self):
        sid = self._login()
        return sid

    def _group_ok(self, sid, kind):
        try:
            self._call("show-group", {"name": self.group(kind)}, sid)
            return True
        except FWError:
            return False

    def check(self, kind):
        sid = self._login()
        try:
            if not self._group_ok(sid, kind):
                return False, f"o grupo «{self.group(kind)}» não existe: crie-o e uma regra de negação que o use (ver manual 19.9)"
            if not self.opts.get("cp_package") or not self.opts.get("cp_targets"):
                return False, "defina na credencial o pacote de política (cp_package) e os gateways (cp_targets) onde a política é instalada"
            return True, f"grupo «{self.group(kind)}»; pacote «{self.opts['cp_package']}» → {self.opts['cp_targets']}"
        finally:
            self._call("logout", {}, sid)

    def _install(self, sid):
        t = self._call("install-policy", {"policy-package": self.opts["cp_package"], "targets": [x.strip() for x in str(self.opts["cp_targets"]).split(",") if x.strip()], "access": True}, sid)
        tid = t.get("task-id")
        for _ in range(60):
            if not tid:
                return
            tasks = self._call("show-task", {"task-id": tid}, sid).get("tasks") or [{}]
            st = tasks[0].get("status", "")
            if st == "succeeded":
                return
            if st in ("failed", "partially succeeded"):
                raise FWError(f"instalação da política falhou ({st})")
            time.sleep(5)
        raise FWError("tempo excedido na instalação da política")

    def add(self, kind, net, comment, ttl_s):
        sid, name = self._login(), _obj(net)
        try:
            if not self._group_ok(sid, kind):
                raise FWError(f"o grupo «{self.group(kind)}» não existe")
            if net.num_addresses == 1:
                self._call("add-host", {"name": name, "ip-address": str(net.network_address), "comments": comment[:200]}, sid)
            else:
                self._call("add-network", {"name": name, "subnet": str(net.network_address), "mask-length": net.prefixlen, "comments": comment[:200]}, sid)
            self._call("set-group", {"name": self.group(kind), "members": {"add": name}}, sid)
            self._call("publish", {}, sid)
            self._install(sid)
        except FWError:
            try:
                self._call("discard", {}, sid)
            except FWError:
                pass
            raise
        finally:
            self._call("logout", {}, sid)

    def remove(self, kind, net):
        sid, name = self._login(), _obj(net)
        try:
            self._call("set-group", {"name": self.group(kind), "members": {"remove": name}}, sid)
            self._call("publish", {}, sid)
            self._install(sid)
            try:
                self._call("delete-host" if net.num_addresses == 1 else "delete-network", {"name": name}, sid)
                self._call("publish", {}, sid)
            except FWError:
                pass
        finally:
            self._call("logout", {}, sid)

    def present(self, kind, net):
        sid = self._login()
        try:
            g = self._call("show-group", {"name": self.group(kind)}, sid)
            return _obj(net) in [m.get("name") for m in g.get("members", [])]
        finally:
            self._call("logout", {}, sid)


DRIVERS = {"fortios": FortiGate, "panos": PaloAlto, "checkpoint": CheckPoint}


# --------------------------------------------------------------------------- orquestração


def enforcers(tenant: Tenant) -> list[Asset]:
    return Asset.query.filter(Asset.tenant_id == tenant.id, Asset.platform.in_(PLATFORMS), Asset.fw_enforce.is_(True)).order_by(Asset.name).all()


def driver_for(asset: Asset) -> Driver:
    from . import ansible_engine as eng
    v = eng.build_inventory([asset])["all"]["hosts"][f"asset{asset.id}"]
    token = v.get("omx_api_token", "")
    if not token:
        raise FWError("falta a credencial de API (token/chave) no ativo")
    host = v.get("ansible_host") or asset.fqdn or asset.ip
    default_port = 443
    return DRIVERS[asset.platform](host, int(v.get("ansible_port") or default_port), token, bool(v.get("omx_validate_certs", True)), v.get("omx_fw_opts") or {})


def target_of(c: ControlAction):
    """(tipo, rede) do controlo: «block» (IP/rede indicado) ou «isolate» (endereço do ativo)."""
    p = c.params_data
    if c.action == "fw_block_ip":
        return "block", p.get("cidr", "")
    if c.asset is None or not c.asset.ip:
        raise ValueError("O ativo não tem endereço IP: não é possível isolá-lo na firewall.")
    return "isolate", c.asset.ip


def _gate(tenant: Tenant) -> list[Asset]:
    if not current_app.config.get("NETCONTROL_ENABLED"):
        raise ValueError("Os controlos nas firewalls estão desativados (Sistema → Configuração → NETCONTROL_ENABLED).")
    fws = enforcers(tenant)
    if not fws:
        raise ValueError("Nenhuma firewall está marcada para aplicar controlos (ativo com plataforma Check Point/FortiGate/Palo Alto e «Aplicar controlos compensatórios»).")
    return fws


def simulate(c: ControlAction, tenant: Tenant) -> dict:
    """Só lê: ligação, grupo existente, estado atual e o que seria feito em cada firewall. Guarda o resultado (válido 24 h)."""
    kind, tgt = target_of(c)
    net = validate_target(tenant, tgt, isolate=(kind == "isolate"))
    out = []
    for fw in _gate(tenant):
        row = {"firewall": fw.name, "platform": fw.platform, "ok": False, "detail": "", "actions": []}
        try:
            d = driver_for(fw)
            ok, detail = d.check(kind)
            row["ok"], row["detail"] = ok, detail
            if ok:
                already = d.present(kind, net)
                row["actions"] = [f"{net} já está no grupo/etiqueta: nada a fazer" if already else f"acrescentar {net} ao grupo/etiqueta «{d.group(kind)}»"]
                if fw.platform == "checkpoint" and not already:
                    row["actions"] += ["publicar a sessão", f"instalar a política «{d.opts.get('cp_package')}» em {d.opts.get('cp_targets')}"]
        except FWError as exc:
            row["detail"] = str(exc)
        out.append(row)
    res = {"at": utcnow().isoformat(), "target": str(net), "kind": kind, "firewalls": out, "ok": bool(out) and all(r["ok"] for r in out)}
    p = c.params_data
    p["simulation"] = res
    c.params = json.dumps(p)
    return res


def _fresh_sim(c: ControlAction) -> bool:
    s = c.params_data.get("simulation") or {}
    try:
        from datetime import datetime
        return bool(s.get("ok")) and datetime.fromisoformat(s["at"]) > utcnow() - timedelta(hours=24)
    except (KeyError, ValueError):
        return False


def apply(c: ControlAction, tenant: Tenant) -> ControlAction:
    kind, tgt = target_of(c)
    net = validate_target(tenant, tgt, isolate=(kind == "isolate"))
    fws = _gate(tenant)
    if not _fresh_sim(c):
        raise ValueError("Faça primeiro a simulação (últimas 24 h) e confirme que todas as firewalls estão prontas.")
    p = c.params_data
    ttl_min = max(5, min(int(p.get("ttl_minutes") or current_app.config.get("NETCONTROL_DEFAULT_TTL_MINUTES", 1440)), 10080))
    done, errs = [], []
    for fw in fws:
        try:
            d = driver_for(fw)
            d.add(kind, net, f"OMXPatch {c.cve_id or 'controlo'} #{c.id}", ttl_min * 60)
            if not d.present(kind, net):
                raise FWError("a firewall não confirmou o objeto no grupo")
            done.append(fw)
        except FWError as exc:
            errs.append(f"{fw.name}: {exc}")
    if errs:                                                          # tudo-ou-nada: desfaz o que já tinha sido aplicado
        for fw in done:
            try:
                driver_for(fw).remove(kind, net)
            except FWError as exc:
                errs.append(f"{fw.name} (reversão): {exc}")
        c.status, c.detail = "failed", ("Falhou e foi revertido: " + "; ".join(errs))[:500]
        return c
    p.update(applied_on=[f.id for f in done], expires_at=(utcnow() + timedelta(minutes=ttl_min)).isoformat(), ttl_minutes=ttl_min)
    c.params = json.dumps(p)
    c.status, c.via, c.applied_at, c.verified_at = "verified", "firewall", utcnow(), utcnow()
    c.detail = f"{net} em «{kind}» em {', '.join(f.name for f in done)} (validade {ttl_min} min; confirmado)"
    return c


def revert(c: ControlAction, tenant: Tenant) -> ControlAction:
    kind, tgt = target_of(c)
    net = ipaddress.ip_network(tgt, strict=False)
    errs = []
    for aid in c.params_data.get("applied_on") or []:
        fw = db.session.get(Asset, aid)
        if fw is None:
            continue
        try:
            driver_for(fw).remove(kind, net)
        except FWError as exc:
            errs.append(f"{fw.name}: {exc}")
    if errs:
        c.detail = ("Reversão incompleta: " + "; ".join(errs))[:500]
        return c
    c.status, c.detail = "reverted", "Retirado das firewalls"
    return c


def expire(tenant: Tenant) -> int:
    """Reverte os controlos cuja validade terminou (a firewall pode ter já retirado, no Palo Alto, pela validade nativa)."""
    n = 0
    for c in ControlAction.query.filter(ControlAction.tenant_id == tenant.id, ControlAction.action.in_(NET_ACTIONS), ControlAction.status.in_(("applied", "verified"))):
        try:
            from datetime import datetime
            exp = datetime.fromisoformat(c.params_data.get("expires_at", ""))
        except ValueError:
            continue
        if exp < utcnow():
            revert(c, tenant)
            n += 1
    return n
