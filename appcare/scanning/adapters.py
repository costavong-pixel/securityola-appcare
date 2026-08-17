"""Safe, read-only adapter wrappers for source, secret, and dependency scanners."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from .contracts import ScannerCallable
from .models import (
    AdapterKind,
    AdapterResult,
    FailureCode,
    SanitizedTargetInput,
    ScanContext,
    ScannerFailure,
    ScannerObservation,
)
from .scope import ScopeError, validate_scope, validate_target_input


def _failure(
    context: ScanContext,
    adapter_kind: AdapterKind,
    code: FailureCode,
    message: str,
    *,
    retryable: bool = False,
) -> ScannerFailure:
    return ScannerFailure(
        failure_id=f"{adapter_kind}-failure",
        code=code,
        adapter_kind=adapter_kind,
        message=message,
        tenant_id=context.tenant_id,
        target_id=context.target_id,
        retryable=retryable,
    )


@dataclass(frozen=True, slots=True)
class FunctionalScannerAdapter:
    """Wrap a bounded scanner callback without permitting persistence or writes."""

    adapter_kind: AdapterKind
    scan_callable: ScannerCallable
    name: str = "scanner"

    def scan(self, context: ScanContext, target: SanitizedTargetInput) -> AdapterResult:
        try:
            validate_target_input(context, target)
            validate_scope(
                context,
                tenant_id=context.tenant_id,
                target_id=target.target_id,
                adapter_kind=self.adapter_kind,
            )
            raw_observations = tuple(self.scan_callable(context, target))
            if any(not isinstance(item, ScannerObservation) for item in raw_observations):
                return AdapterResult.failed(
                    self.adapter_kind,
                    _failure(
                        context,
                        self.adapter_kind,
                        "malformed_output",
                        "scanner returned malformed observations",
                    ),
                )
            return AdapterResult.success(
                self.adapter_kind,
                cast(tuple[ScannerObservation, ...], raw_observations),
            )
        except ScopeError:
            return AdapterResult.failed(
                self.adapter_kind,
                _failure(
                    context,
                    self.adapter_kind,
                    "out_of_scope",
                    "scanner scope validation failed",
                ),
            )
        except TimeoutError:
            return AdapterResult.failed(
                self.adapter_kind,
                _failure(
                    context,
                    self.adapter_kind,
                    "timeout",
                    "scanner timed out",
                    retryable=True,
                ),
            )
        except FileNotFoundError:
            return AdapterResult.failed(
                self.adapter_kind,
                _failure(
                    context,
                    self.adapter_kind,
                    "unavailable",
                    "scanner executable unavailable",
                ),
            )
        except OSError:
            return AdapterResult.failed(
                self.adapter_kind,
                _failure(context, self.adapter_kind, "unavailable", "scanner unavailable"),
            )
        except ValueError:
            return AdapterResult.failed(
                self.adapter_kind,
                _failure(
                    context,
                    self.adapter_kind,
                    "validation_error",
                    "scanner output failed validation",
                ),
            )
        except Exception:
            return AdapterResult.failed(
                self.adapter_kind,
                _failure(
                    context,
                    self.adapter_kind,
                    "execution_error",
                    "scanner execution failed",
                ),
            )


class SourceScannerAdapter(FunctionalScannerAdapter):
    """Adapter boundary for source and configuration scanners."""

    def __init__(self, scan_callable: ScannerCallable, name: str = "source-scanner") -> None:
        super().__init__("source", scan_callable, name)


class SecretScannerAdapter(FunctionalScannerAdapter):
    """Adapter boundary for secret scanners."""

    def __init__(self, scan_callable: ScannerCallable, name: str = "secret-scanner") -> None:
        super().__init__("secret", scan_callable, name)


class DependencyScannerAdapter(FunctionalScannerAdapter):
    """Adapter boundary for dependency scanners."""

    def __init__(self, scan_callable: ScannerCallable, name: str = "dependency-scanner") -> None:
        super().__init__("dependency", scan_callable, name)
