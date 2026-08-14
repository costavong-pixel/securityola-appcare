"""Shared isolated AppCare test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI

from appcare.api import create_app
from appcare.config import Settings


@pytest.fixture
def isolated_app(tmp_path: Path) -> FastAPI:
    database_url = f"sqlite+pysqlite:///{(tmp_path / 'fixture.db').as_posix()}"
    return create_app(settings=Settings(database_url=database_url, environment="test"))
