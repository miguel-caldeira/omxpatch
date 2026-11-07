"""Migração automática do esquema ao arrancar: ``create_all`` cria tabelas novas; aqui acrescentam-se colunas em falta."""
from __future__ import annotations

import logging

from sqlalchemy import inspect, text

from .extensions import db

log = logging.getLogger("omxpatch.migrations")


def _add_missing_columns() -> list[str]:
    engine = db.engine
    insp = inspect(engine)
    dialect = engine.dialect.name
    added = []
    for table in db.metadata.sorted_tables:
        if not insp.has_table(table.name):
            continue
        existing = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in existing:
                continue
            coltype = col.type.compile(dialect=engine.dialect)
            kw = "ADD" if dialect == "mssql" else "ADD COLUMN"
            with engine.begin() as conn:
                conn.execute(text(f'ALTER TABLE {table.name} {kw} {col.name} {coltype}'))
                default = col.default.arg if col.default is not None and col.default.is_scalar else None
                if default is not None:
                    conn.execute(text(f"UPDATE {table.name} SET {col.name} = :v"), {"v": default})
            added.append(f"{table.name}.{col.name}")
    return added


def upgrade() -> None:
    added = _add_missing_columns()
    if added:
        log.info("Colunas adicionadas: %s", ", ".join(added))
