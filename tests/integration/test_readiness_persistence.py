"""Durable Spec 013 persistence and tenant-boundary tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from appcare.db import Database
from appcare.models import (
    Application,
    CapabilityEvidenceRecord,
    ReadinessDowngradeRecord,
    Tenant,
)
from appcare.readiness import (
    CapabilityEvidence,
    CapabilityStatus,
    EvidenceClass,
    ReadinessDowngrade,
    ReadinessStatus,
    ReadinessTier,
    ReadinessValidationError,
    SqlAlchemyReadinessStore,
)

STAMP = datetime(2026, 8, 27, tzinfo=UTC)


def _database() -> Database:
    database = Database("sqlite+pysqlite:///:memory:")
    database.initialize()
    return database


def _scope(database: Database) -> tuple[Tenant, Application, Tenant, Application]:
    with database.session_factory() as session:
        tenant_a = Tenant(name="Tenant A")
        tenant_b = Tenant(name="Tenant B")
        session.add_all((tenant_a, tenant_b))
        session.flush()
        app_a = Application(
            tenant_id=tenant_a.id,
            name="Application A",
            repository_url="https://example.test/a",
            environment="development",
        )
        app_b = Application(
            tenant_id=tenant_b.id,
            name="Application B",
            repository_url="https://example.test/b",
            environment="development",
        )
        session.add_all((app_a, app_b))
        session.commit()
        return tenant_a, app_a, tenant_b, app_b


def _evidence(tenant_id: str, application_id: str) -> CapabilityEvidence:
    return CapabilityEvidence(
        tenant_id=tenant_id,
        application_id=application_id,
        stack_id="linux-ssh",
        capability="inventory",
        status=CapabilityStatus.SUPPORTED,
        evidence_class=EvidenceClass.FIXTURE,
        evidence_ref="spec013-inventory",
        observed_at=STAMP,
    )


def test_readiness_store_persists_and_is_idempotent() -> None:
    database = _database()
    tenant, application, _, _ = _scope(database)
    evidence = _evidence(tenant.id, application.id)
    with database.session_factory() as session:
        store = SqlAlchemyReadinessStore(session)
        first = store.save_capability_evidence(evidence)
        second = store.save_capability_evidence(evidence)
        session.commit()
        assert first.id == second.id
        persisted = session.scalar(
            select(CapabilityEvidenceRecord).where(CapabilityEvidenceRecord.id == first.id)
        )
        assert persisted is not None
        assert persisted.evidence_digest == evidence.evidence_digest


def test_readiness_store_rejects_cross_tenant_application_scope() -> None:
    database = _database()
    tenant_a, _, _, application_b = _scope(database)
    with database.session_factory() as session:
        with pytest.raises(ReadinessValidationError):
            SqlAlchemyReadinessStore(session).save_capability_evidence(
                _evidence(tenant_a.id, application_b.id)
            )


def test_readiness_downgrade_is_database_immutable() -> None:
    database = _database()
    tenant, application, _, _ = _scope(database)
    event = ReadinessDowngrade(
        previous_level=ReadinessTier.STACK,
        previous_status=ReadinessStatus.READY,
        new_status=ReadinessStatus.BLOCKED,
        trigger_capability="inventory",
        trigger_evidence_ref="target-inventory",
        affected_scopes=("tenant-a", "application-a"),
        reason_code="MISSING_MANDATORY_CAPABILITY",
        recorded_at=STAMP,
        tenant_id=tenant.id,
        application_id=application.id,
        stack_id="linux-ssh",
    )
    with database.session_factory() as session:
        store = SqlAlchemyReadinessStore(session)
        store.append(event)
        session.commit()
        with pytest.raises(IntegrityError):
            session.execute(
                update(ReadinessDowngradeRecord)
                .where(ReadinessDowngradeRecord.event_digest == event.event_digest)
                .values(reason_code="tampered")
            )
            session.commit()
        session.rollback()
        with pytest.raises(IntegrityError):
            session.execute(
                delete(ReadinessDowngradeRecord).where(
                    ReadinessDowngradeRecord.event_digest == event.event_digest
                )
            )
            session.commit()
