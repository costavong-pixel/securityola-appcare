"""No-network adversarial fixtures for BETA-10 readiness tests."""

from __future__ import annotations

from .contracts import DrillEvidence
from .gate import REQUIRED_DRILLS


def run_adversarial_fixtures() -> tuple[DrillEvidence, ...]:
    """Return sanitized, deterministic pass evidence for controlled local drills."""

    return tuple(
        DrillEvidence(
            name=name,
            status="passed",
            evidence_ref=f"fixture:{name}:pass",
            summary="Controlled no-network fixture completed.",
        )
        for name in REQUIRED_DRILLS
    )


__all__ = ["run_adversarial_fixtures"]
