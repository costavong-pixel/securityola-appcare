"""Database engine, session, schema bootstrap, and readiness boundaries."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .models import Base


def create_engine_for_url(database_url: str) -> Engine:
    """Create an engine with SQLite isolated-test safety defaults."""

    options: dict[str, Any] = {"future": True, "pool_pre_ping": True}
    if database_url.startswith("sqlite"):
        options["connect_args"] = {"check_same_thread": False}
        if ":memory:" in database_url:
            options["poolclass"] = StaticPool
    engine = create_engine(database_url, **options)

    if engine.dialect.name == "sqlite":

        @event.listens_for(engine, "connect")
        def _enable_sqlite_foreign_keys(dbapi_connection: Any, _connection_record: Any) -> None:
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
            finally:
                cursor.close()

    return engine


def install_audit_immutability(engine: Engine) -> None:
    """Install a database-level update/delete guard, failing closed if unsupported."""

    with engine.begin() as connection:
        if engine.dialect.name == "sqlite":
            connection.execute(
                text(
                    """
                    CREATE TRIGGER IF NOT EXISTS appcare_audit_no_update
                    BEFORE UPDATE ON audit_events
                    BEGIN
                        SELECT RAISE(ABORT, 'audit events are immutable');
                    END
                    """
                )
            )
            connection.execute(
                text(
                    """
                    CREATE TRIGGER IF NOT EXISTS appcare_audit_no_delete
                    BEFORE DELETE ON audit_events
                    BEGIN
                        SELECT RAISE(ABORT, 'audit events are immutable');
                    END
                    """
                )
            )
        elif engine.dialect.name == "postgresql":
            connection.execute(
                text(
                    """
                    CREATE OR REPLACE FUNCTION appcare_reject_audit_mutation()
                    RETURNS trigger
                    LANGUAGE plpgsql
                    AS $$
                    BEGIN
                        RAISE EXCEPTION 'audit events are immutable';
                    END;
                    $$
                    """
                )
            )
            connection.execute(
                text(
                    """
                    DROP TRIGGER IF EXISTS appcare_audit_immutable ON audit_events
                    """
                )
            )
            connection.execute(
                text(
                    """
                    CREATE TRIGGER appcare_audit_immutable
                    BEFORE UPDATE OR DELETE ON audit_events
                    FOR EACH ROW EXECUTE FUNCTION appcare_reject_audit_mutation()
                    """
                )
            )
        else:
            raise RuntimeError("audit immutability is unavailable for this database dialect")


class Database:
    """Own the AppCare engine and session factory for one isolated runtime."""

    def __init__(self, database_url: str) -> None:
        self.engine = create_engine_for_url(database_url)
        self.session_factory = sessionmaker(
            bind=self.engine, autoflush=False, expire_on_commit=False, class_=Session
        )

    def initialize(self) -> None:
        Base.metadata.create_all(self.engine)
        install_audit_immutability(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def ready(self) -> bool:
        try:
            with self.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except Exception:
            return False
        return True

    def dispose(self) -> None:
        self.engine.dispose()
