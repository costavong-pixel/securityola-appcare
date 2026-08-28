"""Application factory for the isolated AppCare control plane."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.exc import IntegrityError

from .config import Settings
from .connectors import ConnectorRegistry
from .db import Database
from .routes import (
    audit,
    auth,
    connectors,
    dashboard,
    health,
    jobs,
    operations,
    readiness,
    resources,
)


def create_app(
    settings: Settings | None = None,
    *,
    database: Database | None = None,
    database_url: str | None = None,
    connector_registry: ConnectorRegistry | None = None,
) -> FastAPI:
    resolved_settings = settings or Settings.from_env()
    if database_url is not None:
        resolved_settings = Settings(
            database_url=database_url,
            environment=resolved_settings.environment,
            token_ttl_seconds=resolved_settings.token_ttl_seconds,
            max_page_size=resolved_settings.max_page_size,
            audit_metadata_max_bytes=resolved_settings.audit_metadata_max_bytes,
            allowed_hosts=resolved_settings.allowed_hosts,
        )
    resolved_settings.validate()
    resolved_database = database or Database(resolved_settings.database_url)
    resolved_database.initialize()

    app = FastAPI(title="SecurityOla AppCare Control Plane", version="0.0.0")
    app.state.settings = resolved_settings
    app.state.database = resolved_database
    app.state.connector_registry = connector_registry or ConnectorRegistry()

    web_directory = Path(__file__).with_name("web")
    app.mount("/static", StaticFiles(directory=web_directory), name="appcare-static")

    @app.get("/", include_in_schema=False)
    def public_site() -> FileResponse:
        return FileResponse(web_directory / "index.html")

    @app.get("/dashboard", include_in_schema=False)
    def dashboard_shell() -> FileResponse:
        return FileResponse(web_directory / "dashboard.html")

    app.include_router(auth.router)
    app.include_router(health.router)
    app.include_router(resources.router)
    app.include_router(operations.router)
    app.include_router(connectors.router)
    app.include_router(jobs.router)
    app.include_router(audit.router)
    app.include_router(dashboard.router)
    app.include_router(readiness.router)

    @app.exception_handler(IntegrityError)
    async def persistence_constraint_error(_request: Request, _exc: IntegrityError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": "persistence constraint failed"})

    @app.exception_handler(RequestValidationError)
    async def request_validation_error(
        _request: Request, _exc: RequestValidationError
    ) -> JSONResponse:
        # FastAPI's default validation payload includes submitted input values.
        # BETA-01 accepts bearer material only at the auth boundary, so never echo
        # arbitrary request data back to a caller.
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={"detail": "invalid input"},
        )

    return app


app = create_app()
