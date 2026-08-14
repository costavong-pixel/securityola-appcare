"""Application factory for the isolated AppCare control plane."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError

from .config import Settings
from .db import Database
from .routes import audit, auth, health, jobs, operations, resources


def create_app(
    settings: Settings | None = None,
    *,
    database: Database | None = None,
    database_url: str | None = None,
) -> FastAPI:
    resolved_settings = settings or Settings.from_env()
    if database_url is not None:
        resolved_settings = Settings(
            database_url=database_url,
            environment=resolved_settings.environment,
            token_ttl_seconds=resolved_settings.token_ttl_seconds,
            max_page_size=resolved_settings.max_page_size,
            audit_metadata_max_bytes=resolved_settings.audit_metadata_max_bytes,
        )
    resolved_settings.validate()
    resolved_database = database or Database(resolved_settings.database_url)
    resolved_database.initialize()

    app = FastAPI(title="SecurityOla AppCare Control Plane", version="0.0.0")
    app.state.settings = resolved_settings
    app.state.database = resolved_database
    app.include_router(auth.router)
    app.include_router(health.router)
    app.include_router(resources.router)
    app.include_router(operations.router)
    app.include_router(jobs.router)
    app.include_router(audit.router)

    @app.exception_handler(IntegrityError)
    async def persistence_constraint_error(_request: Request, _exc: IntegrityError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": "persistence constraint failed"})

    return app


app = create_app()
