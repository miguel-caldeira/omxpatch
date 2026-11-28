"""Firewalls simuladas (FortiGate REST, PAN-OS XML, Check Point Management API) em HTTPS local, com estado, para testar os controlos de rede."""
from __future__ import annotations

import datetime
import http.server
import json
import re
import ssl
import threading
from urllib.parse import parse_qs, unquote, urlparse


def _cert(tmp):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(datetime.datetime(2020, 1, 1)) \
        .not_valid_after(datetime.datetime(2035, 1, 1)).sign(key, hashes.SHA256())
    (tmp / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return str(tmp / "c.pem"), str(tmp / "k.pem")


class Fake:
    """kind: forti | pan | cp. ``state`` guarda o que a «firewall» tem."""

    def __init__(self, kind, tmp, token="TOK", groups=("OMX-BLOCK", "OMX-ISOLATE"), fail=None):
        self.kind, self.token, self.fail, self.calls = kind, token, fail or {}, []
        self.addr, self.groups, self.tags, self.sessions = {}, {g: [] for g in groups}, {}, {}
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body, ct="application/json"):
                data = (json.dumps(body) if not isinstance(body, str) else body).encode()
                self.send_response(code)
                self.send_header("Content-Type", ct)
                self.end_headers()
                self.wfile.write(data)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n) or b"{}") if n else {}

            def do_GET(self):
                outer.handle(self, "GET", None)

            def do_POST(self):
                outer.handle(self, "POST", self._body())

            def do_PUT(self):
                outer.handle(self, "PUT", self._body())

            def do_DELETE(self):
                outer.handle(self, "DELETE", None)
        self.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        c, k = _cert(tmp)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(c, k)
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()

    # ------------------------------------------------------------------------------------------------------ protocolos
    def handle(self, h, method, body):
        u = urlparse(h.path)
        path, q = unquote(u.path), {k: v[0] for k, v in parse_qs(u.query).items()}
        self.calls.append((method, path + ("?" + u.query if u.query else ""), body))
        if self.fail.get(method + " " + path.rsplit("/", 1)[-1]):
            return h._send(500, {"error": "falha simulada"})
        return {"forti": self.forti, "pan": self.pan, "cp": self.cp}[self.kind](h, method, path, q, body)

    def forti(self, h, method, path, q, body):
        if h.headers.get("Authorization") != f"Bearer {self.token}":
            return h._send(403, {"status": "error"})
        m = re.match(r"/api/v2/cmdb/firewall/(addrgrp|address6?)(?:/(.+))?$", path)
        if not m:
            return h._send(404, {})
        kind, name = m.groups()
        if kind == "addrgrp":
            if name not in self.groups:
                return h._send(404, {"status": "error"})
            if method == "PUT":
                self.groups[name] = [x["name"] for x in body.get("member", [])]
            return h._send(200, {"results": [{"name": name, "member": [{"name": x} for x in self.groups[name]]}]})
        if method == "GET":
            return h._send(200 if name in self.addr else 404, {"results": [self.addr.get(name)]})
        if method == "POST":
            self.addr[body["name"]] = body
            return h._send(200, {"status": "success"})
        if method == "DELETE":
            if any(name in g for g in self.groups.values()):
                return h._send(424, {})
            self.addr.pop(name, None)
            return h._send(200, {"status": "success"})
        return h._send(400, {})

    def pan(self, h, method, path, q, body):
        if h.headers.get("X-PAN-KEY") != self.token:
            return h._send(403, "<response status='error'/>", "application/xml")
        t = q.get("type")
        if t == "config":
            g = re.search(r"address-group/entry\[@name='([^']+)'\]", q.get("xpath", ""))
            found = bool(g) and g.group(1) in self.groups
            ent = '<entry name="%s"/>' % g.group(1) if found else ""
            return h._send(200, '<response status="success"><result total-count="%d" count="%d">%s</result></response>' % (int(found), int(found), ent), "application/xml")
        if t == "user-id":
            cmd = q["cmd"]
            ip, tag = re.search(r'ip="([^"]+)"', cmd).group(1), re.search(r"<member[^>]*>([^<]+)</member>", cmd).group(1)
            if "<register>" in cmd:
                self.tags.setdefault(ip, set()).add(tag)
                self.last_timeout = re.search(r'timeout="(\d+)"', cmd).group(1) if "timeout=" in cmd else None
            else:
                self.tags.get(ip, set()).discard(tag)
            return h._send(200, "<response status=\"success\"/>", "application/xml")
        if t == "op":
            ents = "".join(f'<entry ip="{ip}"><tag>' + "".join(f"<member>{x}</member>" for x in ts) + "</tag></entry>" for ip, ts in self.tags.items() if ts)
            return h._send(200, f"<response status=\"success\"><result>{ents}</result></response>", "application/xml")
        return h._send(400, "<response status='error'/>", "application/xml")

    def cp(self, h, method, path, q, body):
        cmd = path.rsplit("/", 1)[-1]
        if cmd == "login":
            if body.get("api-key") != self.token:
                return h._send(401, {"message": "bad key"})
            self.sessions["sid1"] = []
            return h._send(200, {"sid": "sid1"})
        if h.headers.get("X-chkp-sid") != "sid1":
            return h._send(401, {"message": "no session"})
        if cmd == "show-group":
            if body["name"] not in self.groups:
                return h._send(404, {"message": "Requested object not found"})
            return h._send(200, {"name": body["name"], "members": [{"name": x} for x in self.groups[body["name"]]]})
        if cmd in ("add-host", "add-network"):
            self.addr[body["name"]] = body
            return h._send(200, {"name": body["name"]})
        if cmd == "set-group":
            g, mem = body["name"], body["members"]
            if "add" in mem and mem["add"] not in self.groups[g]:
                self.groups[g].append(mem["add"])
            if "remove" in mem and mem["remove"] in self.groups[g]:
                self.groups[g].remove(mem["remove"])
            return h._send(200, {})
        if cmd in ("delete-host", "delete-network"):
            self.addr.pop(body["name"], None)
            return h._send(200, {})
        if cmd == "install-policy":
            self.installed = (body["policy-package"], body["targets"])
            return h._send(200, {"task-id": "T1"})
        if cmd == "show-task":
            return h._send(200, {"tasks": [{"status": "succeeded"}]})
        return h._send(200, {})
