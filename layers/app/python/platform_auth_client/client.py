from __future__ import annotations

import json
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from platform_auth_client.config import RemoteClientConfig
from platform_auth_client.contracts import (
    Decision,
    DerivedDecisionRequest,
    UsageOperationResult,
)
from platform_auth_client.errors import (
    AuthConfigurationError,
    M2MTokenError,
    PlatformAuthError,
    RemoteCallerAuthenticationError,
    RemoteCallerScopeError,
    RemoteTransportError,
)
from platform_auth_client.m2m import AccessTokenProvider
from platform_auth_client.observability import AuthorizationMetrics, OperationMetrics, measured
from platform_auth_client.redaction import redact_metadata

_MAX_RESPONSE_BYTES = 1_048_576


class Transport(Protocol):
    def request(self, method: str, path: str, payload: dict[str, Any] | None) -> dict[str, Any]: ...


@dataclass
class HttpTransport:
    config: RemoteClientConfig
    default_headers: dict[str, str] | None = field(default=None, repr=False)

    def request(self, method: str, path: str, payload: dict[str, Any] | None) -> dict[str, Any]:
        return self._request_with_headers(method, path, payload, self.default_headers or {})

    def _request_with_headers(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
        additional_headers: dict[str, str],
    ) -> dict[str, Any]:
        body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
        headers = {"content-type": "application/json", **additional_headers}
        if self.config.local_dev and self.config.service_id:
            headers["x-local-service-id"] = self.config.service_id
        request = Request(  # noqa: S310 - endpoint schemes are validated by config
            f"{self.config.endpoint}{path}",
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with urlopen(request, timeout=self.config.timeout_seconds) as response:  # noqa: S310
                return _decode_response(response.read(_MAX_RESPONSE_BYTES + 1))
        except HTTPError as exc:
            response_payload = _response_json(exc)
            try:
                _raise_response_error(exc.code, response_payload)
            except PlatformAuthError as error:
                raise error from exc
        except (TimeoutError, URLError) as exc:
            raise RemoteTransportError(
                "Platform authorization service is unavailable", retryable=True
            ) from exc


class BearerHttpTransport(HttpTransport):
    """Standard-library transport for approved external Cognito M2M callers."""

    def __init__(
        self,
        config: RemoteClientConfig,
        token_provider: AccessTokenProvider,
        *,
        metrics: AuthorizationMetrics | None = None,
    ) -> None:
        super().__init__(config)
        self._token_provider = token_provider
        self._metrics = metrics

    def request(self, method: str, path: str, payload: dict[str, Any] | None) -> dict[str, Any]:
        metrics = self._metrics.start("m2m_transport") if self._metrics else None
        if metrics:
            metrics.set_dimensions(authentication_method="cognito_m2m", subject_type="service")
        try:
            with measured(metrics, "m2m_token_acquisition"):
                token = self._token_provider.get_token()
            try:
                with measured(metrics, "http_request"):
                    response = self._request_with_headers(
                        method,
                        path,
                        payload,
                        {"authorization": f"Bearer {token}"},
                    )
            except RemoteCallerAuthenticationError:
                # A raw edge 401 means the service token was rejected before the
                # decision Lambda ran, so refreshing and replaying once is safe.
                self._token_provider.invalidate(token)
                with measured(metrics, "m2m_token_acquisition"):
                    refreshed = self._token_provider.get_token()
                with measured(metrics, "http_request"):
                    response = self._request_with_headers(
                        method,
                        path,
                        payload,
                        {"authorization": f"Bearer {refreshed}"},
                    )
        except BaseException as exc:
            _finish_client_error(metrics, exc)
            raise
        if metrics:
            metrics.finish(outcome="success", reason_code="COMPLETED")
        return response


class SigV4HttpTransport(HttpTransport):
    def __init__(
        self,
        config: RemoteClientConfig,
        *,
        region: str,
        service: str = "execute-api",
        credentials: Any | None = None,
    ) -> None:
        super().__init__(config)
        try:
            from botocore.session import get_session
        except ImportError as exc:
            raise AuthConfigurationError(
                "The aws client extra (botocore) is required for SigV4 transport"
            ) from exc
        self.region = region
        self.service = service
        self.credentials = credentials or get_session().get_credentials()
        if self.credentials is None:
            raise AuthConfigurationError("AWS credentials are required for SigV4 transport")

    def request(self, method: str, path: str, payload: dict[str, Any] | None) -> dict[str, Any]:
        try:
            from botocore.auth import SigV4Auth
            from botocore.awsrequest import AWSRequest
        except ImportError as exc:  # pragma: no cover
            raise AuthConfigurationError("botocore SigV4 support is unavailable") from exc
        body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else b""
        url = f"{self.config.endpoint}{path}"
        aws_request = AWSRequest(
            method=method,
            url=url,
            data=body,
            headers={"content-type": "application/json"},
        )
        credentials = self.credentials.get_frozen_credentials()
        SigV4Auth(credentials, self.service, self.region).add_auth(aws_request)
        return self._request_with_headers(
            method,
            path,
            payload,
            dict(aws_request.headers.items()),
        )


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 2
    base_delay_seconds: float = 0.1
    max_delay_seconds: float = 0.5
    jitter_ratio: float = 0.2

    def __post_init__(self) -> None:
        if self.max_attempts < 1 or self.max_attempts > 3:
            raise AuthConfigurationError("Retry max_attempts must be between 1 and 3")
        if self.base_delay_seconds < 0 or self.max_delay_seconds < self.base_delay_seconds:
            raise AuthConfigurationError("Retry delays are invalid")
        if self.max_delay_seconds > 2:
            raise AuthConfigurationError("Retry max delay must be <= 2 seconds")
        if self.jitter_ratio < 0 or self.jitter_ratio > 1:
            raise AuthConfigurationError("Retry jitter ratio must be between 0 and 1")

    def delay(self, failed_attempt: int, *, random_value: float) -> float:
        base = min(
            self.max_delay_seconds,
            self.base_delay_seconds * (2 ** max(0, failed_attempt - 1)),
        )
        jitter = base * self.jitter_ratio * ((random_value * 2) - 1)
        return max(0.0, base + jitter)


class RemoteAuthorizationClient:
    def __init__(
        self,
        transport: Transport,
        *,
        retry_policy: RetryPolicy | None = None,
        sleep: Callable[[float], None] = time.sleep,
        random_source: Callable[[], float] = random.random,  # noqa: S311
        metrics: AuthorizationMetrics | None = None,
    ) -> None:
        self.transport = transport
        self.retry_policy = retry_policy or RetryPolicy()
        self._sleep = sleep
        self._random_source = random_source
        self._metrics = metrics

    @classmethod
    def local_from_env(cls) -> RemoteAuthorizationClient:
        config = RemoteClientConfig.from_env()
        if not config.local_dev:
            raise AuthConfigurationError("local_from_env requires AUTH_LOCAL_DEV_MODE=true")
        return cls(HttpTransport(config))

    def decide(self, request: DerivedDecisionRequest) -> Decision:
        if not isinstance(request, DerivedDecisionRequest):
            raise AuthConfigurationError("Only decision contract v4 is supported")
        try:
            return Decision.from_dict(
                self._request(
                    "POST",
                    "/api/authorization/decisions",
                    request.to_dict(),
                    safe_to_retry=_decision_is_safe_to_retry(request),
                    operation="client_decision",
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RemoteTransportError(
                "Platform authorization service returned an invalid decision",
                retryable=False,
            ) from exc

    def confirm_usage(self, operation_id: str) -> UsageOperationResult:
        return _usage_transition_result(
            self._request(
                "POST",
                _usage_operation_path(operation_id, "confirm"),
                None,
                safe_to_retry=True,
                operation="client_confirm",
            ),
            operation_id=operation_id,
            expected_state="settled",
            expected_quota_type="allocation",
        )

    def settle_usage(self, operation_id: str) -> UsageOperationResult:
        return _usage_transition_result(
            self._request(
                "POST",
                _usage_operation_path(operation_id, "settle"),
                None,
                safe_to_retry=True,
                operation="client_settle",
            ),
            operation_id=operation_id,
            expected_state="settled",
            expected_quota_type="metered",
        )

    def release_usage(self, operation_id: str) -> UsageOperationResult:
        return _usage_transition_result(
            self._request(
                "POST",
                _usage_operation_path(operation_id, "release"),
                None,
                safe_to_retry=True,
                operation="client_release",
            ),
            operation_id=operation_id,
            expected_state="released",
        )

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
        *,
        safe_to_retry: bool,
        operation: str,
    ) -> dict[str, Any]:
        metrics = self._metrics.start(operation) if self._metrics else None
        for attempt in range(1, self.retry_policy.max_attempts + 1):
            if metrics:
                metrics.set_dimensions(attempts=attempt)
            try:
                with measured(metrics, "transport_attempt"):
                    response = self.transport.request(method, path, payload)
            except (RemoteTransportError, M2MTokenError) as exc:
                retryable = bool((exc.details or {}).get("retryable"))
                if not safe_to_retry or not retryable or attempt >= self.retry_policy.max_attempts:
                    _finish_client_error(metrics, exc)
                    raise
                with measured(metrics, "retry_backoff"):
                    self._sleep(
                        self.retry_policy.delay(
                            attempt,
                            random_value=self._random_source(),
                        )
                    )
            except BaseException as exc:
                _finish_client_error(metrics, exc)
                raise
            else:
                if metrics:
                    metrics.finish(outcome="success", reason_code="COMPLETED")
                return response
        raise AssertionError("unreachable")


def _finish_client_error(metrics: OperationMetrics | None, exc: BaseException) -> None:
    if metrics is None:
        return
    reason_code = exc.code if isinstance(exc, PlatformAuthError) else "INTERNAL_ERROR"
    metrics.finish(outcome="error", reason_code=reason_code)


def _response_json(exc: HTTPError) -> dict[str, Any]:
    try:
        return _decode_response(exc.read(_MAX_RESPONSE_BYTES + 1))
    except RemoteTransportError:
        return {}


def _decode_response(body: bytes) -> dict[str, Any]:
    if len(body) > _MAX_RESPONSE_BYTES:
        raise RemoteTransportError(
            "Platform authorization response exceeded the size limit",
            retryable=False,
        )
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RemoteTransportError(
            "Platform authorization service returned invalid JSON",
            retryable=False,
        ) from exc
    if not isinstance(payload, dict):
        raise RemoteTransportError(
            "Platform authorization service returned an invalid response",
            retryable=False,
        )
    return payload


def _raise_response_error(status_code: int, payload: dict[str, Any]) -> None:
    detail = payload.get("detail", payload)
    if isinstance(detail, dict) and detail.get("error"):
        raise PlatformAuthError(
            str(detail["error"]),
            "Platform authorization request was denied",
            status_code,
            redact_metadata(detail.get("details")),
        )
    if status_code == 401:
        raise RemoteCallerAuthenticationError()
    if status_code == 403:
        raise RemoteCallerScopeError()
    raise RemoteTransportError(
        "Platform authorization request failed",
        retryable=status_code >= 500,
        status_code=status_code,
    )


def _usage_operation_result(payload: dict[str, Any]) -> UsageOperationResult:
    try:
        return UsageOperationResult.from_dict(payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise RemoteTransportError(
            "Platform authorization service returned an invalid usage operation",
            retryable=False,
        ) from exc


def _usage_transition_result(
    payload: dict[str, Any],
    *,
    operation_id: str,
    expected_state: str,
    expected_quota_type: str | None = None,
) -> UsageOperationResult:
    operation = _usage_operation_result(payload)
    if (
        operation.operation_id != operation_id
        or operation.state != expected_state
        or (
            expected_quota_type is not None
            and operation.quota_type != expected_quota_type
        )
    ):
        raise RemoteTransportError(
            "Platform authorization service returned an inconsistent usage transition",
            retryable=False,
        )
    return operation


def _usage_operation_path(operation_id: str, transition: str) -> str:
    if not isinstance(operation_id, str) or not operation_id or len(operation_id) > 200:
        raise AuthConfigurationError("Usage transition requires a bounded operation ID")
    return f'/api/authorization/usage/{quote(operation_id, safe="")}/{transition}'


def _decision_is_safe_to_retry(request: DerivedDecisionRequest) -> bool:
    invocation = request.usage_invocation
    return invocation is None or bool(invocation.operation_id or invocation.resource_id)
