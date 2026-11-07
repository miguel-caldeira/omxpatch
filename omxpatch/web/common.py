from __future__ import annotations

from flask import flash, redirect, url_for
from flask_login import current_user

from ..security import current_tenant


def tenant_or_select():
    """Super-administradores sem organização selecionada vão para a lista de organizações."""
    if current_tenant() is None:
        if current_user.is_superadmin:
            flash("Selecione ou crie uma organização.", "info")
            return redirect(url_for("admin.tenants"))
    return None


def parse_date(text: str):
    from datetime import datetime
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(text.strip(), fmt)
        except (ValueError, AttributeError):
            continue
    return None
