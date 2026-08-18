"""Safe LangGraph checkpoint construction for AppCare environments."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import urlsplit

import psycopg
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from psycopg.rows import dict_row

from ..config import Settings
from .contracts import WorkflowConfigurationError


def _validate_postgres_target(
    database_url: str,
    *,
    environment: str | None,
    allowed_hosts: tuple[str, ...] | None,
) -> None:
    parsed = urlsplit(database_url)
    if parsed.scheme not in {"postgres", "postgresql"} and not parsed.scheme.startswith(
        "postgresql+"
    ):
        raise WorkflowConfigurationError("workflow checkpoints require PostgreSQL")
    selected_environment = environment or os.getenv("APPCARE_ENVIRONMENT") or "staging"
    try:
        Settings(
            database_url=database_url,
            environment=selected_environment,
            allowed_hosts=allowed_hosts,
        ).validate()
    except ValueError as exc:
        raise WorkflowConfigurationError(
            "PostgreSQL checkpoint target is outside AppCare scope"
        ) from exc


@contextmanager
def postgres_checkpointer(
    database_url: str,
    *,
    environment: str | None = None,
    allowed_hosts: tuple[str, ...] | None = None,
) -> Iterator[PostgresSaver]:
    """Yield a strict, PostgreSQL-backed checkpointer and create its tables."""

    _validate_postgres_target(database_url, environment=environment, allowed_hosts=allowed_hosts)
    try:
        with psycopg.connect(database_url, autocommit=True, row_factory=dict_row) as connection:
            serializer = JsonPlusSerializer(
                pickle_fallback=False,
                allowed_msgpack_modules=[],
            )
            saver = PostgresSaver(connection, serde=serializer)
            saver.setup()
            yield saver
    except WorkflowConfigurationError:
        raise
    except Exception as exc:
        raise WorkflowConfigurationError("PostgreSQL checkpoint initialization failed") from exc


def build_in_memory_checkpointer() -> InMemorySaver:
    """Return an explicitly test-only checkpointer; runtime uses PostgreSQL."""

    return InMemorySaver()


__all__ = ["build_in_memory_checkpointer", "postgres_checkpointer"]
