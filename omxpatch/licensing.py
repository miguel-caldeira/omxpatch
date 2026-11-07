"""Licenciamento por organização (tenant) com data de expiração.

* **Válida** até ao fim do dia de expiração (``Tenant.license_expires_on``); nos últimos
  ``LICENSE_WARN_DAYS`` dias os administradores da organização veem um aviso.
* **Período de tolerância** (``LICENSE_GRACE_DAYS``, 15 dias por omissão) após a expiração: a
  organização continua a funcionar, mas cada login mostra um aviso (popup) com a data de suspensão.
* **Suspensa** após o período de tolerância: o login dos utilizadores da organização é recusado com uma
  mensagem própria, as sessões abertas terminam, os tokens da API deixam de funcionar e os scans
  agendados não correm. Só um super-administrador a reativa, indicando uma nova data de expiração
  posterior à data atual. Os dados são mantidos.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta

from flask import current_app, has_app_context

STATES = {
    "unlimited": "Sem data de expiração",
    "valid": "Válida",
    "expiring": "A expirar",
    "grace": "Expirada — período de tolerância",
    "suspended": "Suspensa (licença expirada)",
}
DEFAULT_GRACE_DAYS = 15
DEFAULT_WARN_DAYS = 30


def _cfg(key: str, default: int) -> int:
    if has_app_context():
        return int(current_app.config.get(key, default))
    return default


def grace_days() -> int:
    return _cfg("LICENSE_GRACE_DAYS", DEFAULT_GRACE_DAYS)


def today() -> date:
    return datetime.now().date()


def status(tenant, on: date | None = None) -> dict:
    """Estado da licença de ``tenant`` no dia ``on`` (omissão: hoje, hora local do servidor)."""
    on = on or today()
    expires = getattr(tenant, "license_expires_on", None)
    if isinstance(expires, datetime):
        expires = expires.date()
    if expires is None:
        return {"state": "unlimited", "label": STATES["unlimited"], "expires": None, "grace_end": None,
                "days_left": None, "grace_days_left": None, "blocked": False}
    grace_end = expires + timedelta(days=grace_days())
    days_left = (expires - on).days               # 0 = expira hoje (ainda válida)
    if days_left >= 0:
        state = "expiring" if days_left < _cfg("LICENSE_WARN_DAYS", DEFAULT_WARN_DAYS) else "valid"
    elif on <= grace_end:
        state = "grace"
    else:
        state = "suspended"
    return {"state": state, "label": STATES[state], "expires": expires, "grace_end": grace_end,
            "days_left": days_left, "grace_days_left": (grace_end - on).days if state == "grace" else None,
            "blocked": state == "suspended"}


def is_suspended(tenant, on: date | None = None) -> bool:
    return tenant is not None and status(tenant, on)["blocked"]


def suspended_message(tenant) -> str:
    st = status(tenant)
    return (f"A licença da organização «{tenant.name}» expirou em {st['expires']:%d/%m/%Y} e o período de "
            f"tolerância terminou em {st['grace_end']:%d/%m/%Y}: o acesso está suspenso. Contacte o "
            "administrador da plataforma para renovar a licença.")


def grace_message(tenant) -> str:
    st = status(tenant)
    n = st["grace_days_left"]
    when = "termina hoje" if n == 0 else ("termina amanhã" if n == 1 else f"termina daqui a {n} dias")
    return (f"A licença da organização «{tenant.name}» expirou em {st['expires']:%d/%m/%Y}. O período de "
            f"tolerância de {grace_days()} dias {when} ({st['grace_end']:%d/%m/%Y}); a partir do dia seguinte o "
            "acesso fica suspenso. Contacte o administrador da plataforma para renovar a licença.")


def validate_new_expiry(tenant, value: date | None) -> str | None:
    """Erro (texto) se a nova data não for aceitável; uma organização suspensa ou em tolerância só é
    reativada com uma data posterior à atual."""
    if value is None:
        if tenant is not None and getattr(tenant, "license_expires_on", None) is not None:
            return "Indique a data de expiração da licença."
        return None
    if value <= today():
        return "A data de expiração da licença tem de ser posterior à data atual."
    return None
