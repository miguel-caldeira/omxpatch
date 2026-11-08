from __future__ import annotations

import re
from datetime import timedelta

import pytest

from omxpatch import create_app
from omxpatch.extensions import db
from omxpatch.models import Asset, AssetSoftware, CveIntel, Tenant, User, utcnow


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.delenv("OMXPATCH_CONFIG", raising=False)
    monkeypatch.setattr("omxpatch.models.PASSWORD_HASH_METHOD", "pbkdf2:sha256:1000")      # testes rápidos
    monkeypatch.chdir(tmp_path)
    from omxpatch import ratelimit, metrics
    ratelimit.reset()
    metrics.reset()
    app = create_app({"DATA_DIR": str(tmp_path), "TESTING": True, "KEV_ENABLED": False, "NVD_ENABLED": False,
                      "EPSS_ENABLED": False, "MITRE_ENABLED": False, "ANSIBLE_ENABLED": False,
                      "DATABASE_URL": f"sqlite:///{tmp_path}/t.db", "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path}/t.db",
                      "BASE_URL": "https://omxpatch.test"}, start_worker=False)
    with app.app_context():
        a, b = Tenant(name="Alpha", slug="alpha"), Tenant(name="Beta", slug="beta")
        db.session.add_all([a, b])
        db.session.flush()
        for email, tid, role, sa in [("admin@alpha.example", a.id, "admin", False), ("user@alpha.example", a.id, "user", False),
                                     ("auditor@alpha.example", a.id, "auditor", False), ("admin@beta.example", b.id, "admin", False),
                                     ("root@omx.example", None, "admin", True)]:
            u = User(email=email, tenant_id=tid, role=role, is_superadmin=sa)
            u.set_password("Passw0rd!Strong")
            db.session.add(u)
        db.session.commit()
    with app.app_context():
        yield app


def _fresh_g():
    """Os testes mantêm um contexto de aplicação aberto (para usar a BD); o Flask reutiliza-o nos pedidos e o Flask-Login
    guarda o utilizador em ``g``. Limpa essa cache para cada pedido se comportar como numa execução real."""
    from flask import g
    try:
        g.pop("_login_user", None)
        g.pop("api_user", None)
    except RuntimeError:
        pass


class Client:
    def __init__(self, c):
        self.c = c

    def csrf(self):
        with self.c.session_transaction() as s:
            s.setdefault("_csrf", "test-token")
            return s["_csrf"]

    def get(self, *a, **kw):
        _fresh_g()
        return self.c.get(*a, **kw)

    def post(self, url, data=None, **kw):
        data = dict(data or {})
        data.setdefault("_csrf", self.csrf())
        _fresh_g()
        return self.c.post(url, data=data, **kw)

    def login(self, email, password="Passw0rd!Strong"):
        return self.post("/login", {"email": email, "password": password})


@pytest.fixture()
def client(app):
    return Client(app.test_client())


def login_as(app, email):
    c = Client(app.test_client())
    r = c.login(email)
    assert r.status_code == 302, r.data
    return c


@pytest.fixture()
def alpha_admin(app):
    return login_as(app, "admin@alpha.example")


@pytest.fixture()
def alpha_user(app):
    return login_as(app, "user@alpha.example")


@pytest.fixture()
def tenant(app):
    return Tenant.query.filter_by(slug="alpha").first()


def make_cve(cve_id="CVE-2026-0001", cvss=9.8, kev=False, epss=None, maturity="none", end_excl="1.1.1w", product="openssl",
             vendor="openssl", cwe="", fixed_pkg=None, ransomware=False, advisories=None):
    row = CveIntel(cve_id=cve_id, cvss=cvss, kev=kev, epss=epss, exploit_maturity=maturity, cwe=cwe, ransomware=ransomware,
                   description="teste", published=utcnow() - timedelta(days=3))
    import json
    row.affected = json.dumps([{"vendor": vendor, "product": product, "end_excl": end_excl, "fixed": end_excl}])
    if advisories is not None:
        row.advisories = json.dumps(advisories)
    db.session.add(row)
    db.session.flush()
    return row


def make_asset(tenant, name="srv1", software=(("OpenSSL", "1.1.1k"),), os_family="linux", ip="10.0.0.5", **kw):
    a = Asset(tenant_id=tenant.id, uid=name.lower(), name=name, ip=ip, os_family=os_family, managed=True, **kw)
    db.session.add(a)
    db.session.flush()
    for n, v in software:
        db.session.add(AssetSoftware(tenant_id=tenant.id, asset_id=a.id, name=n, version=v))
    db.session.flush()
    return a


def extract(pattern, html):
    m = re.search(pattern, html)
    return m.group(1) if m else None
