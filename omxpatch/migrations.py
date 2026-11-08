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
                    conn.execute(text(f"UPDATE {table.name} SET {col.name} = :v"), {"v": default})  # nosec B608 - nomes do próprio modelo, valor por parâmetro
            added.append(f"{table.name}.{col.name}")
    return added


# --------------------------------------------------------------------------- migrações versionadas
#
# Cada migração tem um identificador único e ordenado e corre uma única vez (fica registada em ``schema_migrations``), dentro de uma
# transação. Para alterar/remover colunas ou índices acrescente uma entrada ao fim de ``MIGRATIONS`` — nunca edite as já publicadas.
# Antes de aplicar migrações pendentes faz-se uma cópia de segurança (SQLite) para ``<dados>/backups``.


from contextlib import contextmanager


@contextmanager
def _transaction():
    """Transação com DDL transacional. O pysqlite não abre transação antes de DDL (a falha a meio deixaria o esquema alterado):
    em SQLite desliga-se esse comportamento e faz-se BEGIN/COMMIT/ROLLBACK explícitos."""
    if db.engine.dialect.name != "sqlite":
        with db.engine.begin() as conn:
            yield conn
        return
    with db.engine.connect() as conn:
        raw = conn.connection.driver_connection
        old = raw.isolation_level
        raw.isolation_level = None
        conn.exec_driver_sql("BEGIN")
        try:
            yield conn
            conn.exec_driver_sql("COMMIT")
        except BaseException:
            conn.exec_driver_sql("ROLLBACK")
            raise
        finally:
            raw.isolation_level = old


def _run(conn, sql: str) -> None:
    conn.execute(text(sql))


def _index(conn, name: str, table: str, cols: str) -> None:
    _run(conn, f"CREATE INDEX IF NOT EXISTS {name} ON {table} ({cols})")


def rename_column(conn, table: str, old: str, new: str) -> None:
    _run(conn, f"ALTER TABLE {table} RENAME COLUMN {old} TO {new}")          # SQLite ≥ 3.25, PostgreSQL, MySQL 8


def drop_column(conn, table: str, col: str) -> None:
    _run(conn, f"ALTER TABLE {table} DROP COLUMN {col}")                      # SQLite ≥ 3.35, PostgreSQL, MySQL


def _m0001_baseline(conn) -> None:
    pass                                                                      # colunas em falta: tratadas por _add_missing_columns


def _m0002_poll_indexes(conn) -> None:
    _index(conn, "ix_tasks_poll", "tasks", "tenant_id, asset_id, status")     # contacto dos agentes: tarefas em fila por ativo
    _index(conn, "ix_agents_last_seen", "agents", "last_seen")


MIGRATIONS: list[tuple[str, str, object]] = [
    ("0001_baseline", "Esquema inicial (colunas em falta acrescentadas automaticamente)", _m0001_baseline),
    ("0002_poll_indexes", "Índices para o contacto dos agentes", _m0002_poll_indexes),
]


def _ensure_table() -> None:
    with db.engine.begin() as conn:
        conn.execute(text("CREATE TABLE IF NOT EXISTS schema_migrations (id VARCHAR(100) PRIMARY KEY, description VARCHAR(300), applied_at VARCHAR(40))"))


def applied() -> list[str]:
    _ensure_table()
    with db.engine.connect() as conn:
        return [r[0] for r in conn.execute(text("SELECT id FROM schema_migrations ORDER BY id"))]


def pending() -> list[str]:
    done = set(applied())
    return [m[0] for m in MIGRATIONS if m[0] not in done]


def status() -> dict:
    return {"applied": applied(), "pending": pending(), "latest": MIGRATIONS[-1][0]}


def upgrade(backup_dir=None) -> list[str]:
    """Aplica as migrações pendentes, por ordem. Devolve os identificadores aplicados. Se uma falhar, as anteriores ficam registadas,
    a falhada é revertida (transação) e a exceção sobe com o identificador — o arranque pára em vez de funcionar com um esquema a meio."""
    from datetime import datetime, timezone
    added = _add_missing_columns()
    if added:
        log.info("Colunas adicionadas: %s", ", ".join(added))
    todo = [m for m in MIGRATIONS if m[0] in pending()]
    if not todo:
        return []
    if backup_dir is not None and db.engine.dialect.name == "sqlite":
        try:
            from .engine import backup
            backup.sqlite_copy(db.engine.url.database, backup_dir, f"pre-migration-{todo[0][0]}")
        except Exception as exc:  # noqa: BLE001 - a cópia nunca impede a migração, mas fica no registo
            log.warning("Cópia antes da migração falhou: %s", exc)
    done = []
    for mid, desc, fn in todo:
        try:
            with _transaction() as conn:
                fn(conn)
                conn.execute(text("INSERT INTO schema_migrations (id, description, applied_at) VALUES (:i, :d, :a)"),
                             {"i": mid, "d": desc, "a": datetime.now(timezone.utc).isoformat()})
        except Exception as exc:
            raise RuntimeError(f"Migração {mid} falhou e foi revertida: {exc}") from exc
        done.append(mid)
        log.info("Migração aplicada: %s — %s", mid, desc)
    return done
