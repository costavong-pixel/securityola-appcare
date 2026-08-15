"""Audit hash-chain, sanitization, and mutation-failure tests."""

from __future__ import annotations

import pytest
from sqlalchemy import delete, update
from sqlalchemy.exc import IntegrityError

from appcare.models import AuditEvent
from appcare.services.audit import MetadataError, append_event, verify_event_hash
from tests.control_plane_helpers import new_test_app, seed_user


def test_audit_chain_is_tenant_scoped_and_each_event_is_verifiable() -> None:
    app = new_test_app()
    tenant_a = seed_user(app, "AuditA")
    tenant_b = seed_user(app, "AuditB")
    with app.state.database.session_factory() as session:
        first_a = append_event(
            session,
            tenant_id=tenant_a.tenant_id,
            actor_user_id=tenant_a.user_id,
            action="fixture.first",
            subject_type="test",
            subject_id=None,
            outcome="success",
            metadata={"safe": "one"},
        )
        second_a = append_event(
            session,
            tenant_id=tenant_a.tenant_id,
            actor_user_id=tenant_a.user_id,
            action="fixture.second",
            subject_type="test",
            subject_id=None,
            outcome="success",
            metadata={"safe": "two"},
        )
        first_b = append_event(
            session,
            tenant_id=tenant_b.tenant_id,
            actor_user_id=tenant_b.user_id,
            action="fixture.other-tenant",
            subject_type="test",
            subject_id=None,
            outcome="success",
            metadata={"safe": "other"},
        )
        session.commit()

    assert second_a.previous_event_hash == first_a.event_hash
    assert first_b.previous_event_hash is None
    assert verify_event_hash(first_a)
    assert verify_event_hash(second_a)
    assert verify_event_hash(first_b)


def test_audit_metadata_rejects_unsafe_shapes_and_secret_like_values() -> None:
    app = new_test_app()
    user = seed_user(app, "Audit")
    with app.state.database.session_factory() as session:
        with pytest.raises(MetadataError):
            append_event(
                session,
                tenant_id=user.tenant_id,
                actor_user_id=user.user_id,
                action="fixture.secret",
                subject_type="test",
                subject_id=None,
                outcome="failure",
                metadata={"note": "Bearer fake-fixture-token-12345678901234567890"},
            )
        with pytest.raises(MetadataError):
            append_event(
                session,
                tenant_id=user.tenant_id,
                actor_user_id=user.user_id,
                action="fixture.deep",
                subject_type="test",
                subject_id=None,
                outcome="failure",
                metadata={"nested": {"a": {"b": {"c": {"d": {"e": {"f": "too deep"}}}}}}},
            )


def test_database_rejects_direct_audit_update_and_delete() -> None:
    app = new_test_app()
    user = seed_user(app, "Audit")
    database = app.state.database
    with database.session_factory() as session:
        event = append_event(
            session,
            tenant_id=user.tenant_id,
            actor_user_id=user.user_id,
            action="fixture.immutable",
            subject_type="test",
            subject_id=None,
            outcome="success",
            metadata={"safe": "value"},
        )
        session.commit()
        event_id = event.id
        with pytest.raises(IntegrityError):
            session.execute(
                update(AuditEvent).where(AuditEvent.id == event_id).values(outcome="tampered")
            )
            session.commit()
        session.rollback()
        with pytest.raises(IntegrityError):
            session.execute(delete(AuditEvent).where(AuditEvent.id == event_id))
            session.commit()
        session.rollback()
        persisted = session.get(AuditEvent, event_id)
        assert persisted is not None
        assert persisted.outcome == "success"
