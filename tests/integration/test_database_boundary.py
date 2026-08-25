"""Database bootstrap and readiness boundary tests."""

from sqlalchemy import text

from appcare.db import Database


def test_sqlite_database_bootstrap_installs_audit_triggers() -> None:
    database = Database("sqlite+pysqlite:///:memory:")
    database.initialize()
    assert database.ready()
    with database.engine.connect() as connection:
        names = {
            row[0]
            for row in connection.execute(
                text("SELECT name FROM sqlite_master WHERE type = 'trigger'")
            )
        }
    assert names == {
        "appcare_audit_no_update",
        "appcare_audit_no_delete",
        "appcare_deployment_evidence_no_update",
        "appcare_deployment_evidence_no_delete",
        "appcare_monitoring_events_no_update",
        "appcare_monitoring_events_no_delete",
    }
