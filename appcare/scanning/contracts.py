"""Provider-neutral scanner adapter contracts."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Protocol

from .models import AdapterKind, AdapterResult, SanitizedTargetInput, ScanContext


class ScannerAdapter(Protocol):
    """Read-only adapter boundary for one deterministic scanner family."""

    @property
    def adapter_kind(self) -> AdapterKind:
        """Identify the scanner family implemented by this adapter."""
        ...

    def scan(self, context: ScanContext, target: SanitizedTargetInput) -> AdapterResult:
        """Return normalized observations or a scanner failure, never a finding."""


ScannerCallable = Callable[
    [ScanContext, SanitizedTargetInput],
    Iterable[object],
]
