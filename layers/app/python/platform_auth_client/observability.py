from __future__ import annotations

import json
import logging
import re
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger("platform_auth_client.latency")

LatencySink = Callable[[dict[str, Any]], None]

_SAFE_LABEL = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_OPERATIONS = {
    "client_confirm",
    "client_decision",
    "client_release",
    "client_settle",
    "m2m_transport",
}
_PHASES = {
    "http_request",
    "m2m_token_acquisition",
    "retry_backoff",
    "transport_attempt",
}
_OUTCOMES = {"allowed", "denied", "error", "success"}


def _json_log_sink(payload: dict[str, Any]) -> None:
    # Lambda captures stdout as CloudWatch Logs. A direct JSON line avoids
    # depending on application logger levels or framework logging setup.
    print(json.dumps(payload, separators=(",", ":"), sort_keys=True), flush=True)


class AuthorizationMetrics:
    """Creates low-cardinality, request-scoped authorization latency records.

    The default sink writes one bounded JSON summary per operation. Callers may
    inject a sink for tests or their own telemetry pipeline. Sink failures are
    deliberately best-effort and never change an authorization outcome.
    """

    def __init__(
        self,
        *,
        sink: LatencySink | None = None,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        self._sink = sink or _json_log_sink
        self._clock = clock
        self._cold = True
        self._lock = threading.Lock()

    def start(self, operation: str) -> OperationMetrics:
        if operation not in _OPERATIONS:
            raise ValueError("Unsupported authorization metrics operation")
        with self._lock:
            cold_start = self._cold
            self._cold = False
        return OperationMetrics(
            operation=operation,
            cold_start=cold_start,
            sink=self._sink,
            clock=self._clock,
        )


class OperationMetrics:
    def __init__(
        self,
        *,
        operation: str,
        cold_start: bool,
        sink: LatencySink,
        clock: Callable[[], float],
    ) -> None:
        self.operation = operation
        self.cold_start = cold_start
        self._sink = sink
        self._clock = clock
        self._started_at = clock()
        self._phase_durations: dict[str, float] = {}
        self._finished = False
        self._authentication_method = "unknown"
        self._contract_version = "unknown"
        self._subject_type = "unknown"
        self._usage_mode = "none"
        self._attempts = 1

    def set_dimensions(
        self,
        *,
        authentication_method: str | None = None,
        contract_version: str | None = None,
        subject_type: str | None = None,
        usage_mode: str | None = None,
        attempts: int | None = None,
    ) -> None:
        if authentication_method is not None:
            self._authentication_method = _safe_label(authentication_method)
        if contract_version is not None:
            self._contract_version = (
                contract_version if contract_version == "4" else "other"
            )
        if subject_type is not None:
            self._subject_type = subject_type if subject_type in {"user", "service"} else "other"
        if usage_mode is not None:
            self._usage_mode = usage_mode if usage_mode in {"none", "check", "reserve"} else "other"
        if attempts is not None:
            self._attempts = min(3, max(1, int(attempts)))

    @contextmanager
    def measure(self, phase: str) -> Iterator[None]:
        if phase not in _PHASES:
            raise ValueError("Unsupported authorization metrics phase")
        started_at = self._clock()
        try:
            yield
        finally:
            elapsed = max(0.0, self._clock() - started_at)
            self._phase_durations[phase] = self._phase_durations.get(phase, 0.0) + elapsed

    def finish(self, *, outcome: str, reason_code: str) -> None:
        if self._finished:
            return
        self._finished = True
        safe_outcome = outcome if outcome in _OUTCOMES else "error"
        payload = {
            "event": "platform_auth_client.authorization_latency",
            "schemaVersion": 1,
            "operation": self.operation,
            "durationMs": _milliseconds(max(0.0, self._clock() - self._started_at)),
            "phaseDurationsMs": {
                phase: _milliseconds(duration)
                for phase, duration in sorted(self._phase_durations.items())
            },
            "outcome": safe_outcome,
            "reasonCode": _safe_label(reason_code),
            "authenticationMethod": self._authentication_method,
            "contractVersion": self._contract_version,
            "subjectType": self._subject_type,
            "usageMode": self._usage_mode,
            "attempts": self._attempts,
            "coldStart": self.cold_start,
        }
        try:
            self._sink(payload)
        except Exception:  # pragma: no cover - defensive telemetry boundary
            logger.warning("Authorization latency sink failed", exc_info=False)


@contextmanager
def measured(metrics: OperationMetrics | None, phase: str) -> Iterator[None]:
    if metrics is None:
        yield
        return
    with metrics.measure(phase):
        yield


def _safe_label(value: str) -> str:
    return value if _SAFE_LABEL.fullmatch(value) else "other"


def _milliseconds(seconds: float) -> float:
    return round(seconds * 1000, 3)
