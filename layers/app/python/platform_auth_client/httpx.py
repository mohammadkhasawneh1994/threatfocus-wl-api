from __future__ import annotations

import asyncio
import random
from collections.abc import Callable
from typing import Any, Protocol

try:
    import httpx
except ImportError as exc:  # pragma: no cover - exercised by isolated import test
    raise ImportError(
        "The http-client extra is required: install platform-auth[http-client]"
    ) from exc

from platform_auth_client.client import (
    RetryPolicy,
    _decision_is_safe_to_retry,
    _decode_response,
    _raise_response_error,
    _usage_operation_path,
    _usage_transition_result,
)
from platform_auth_client.config import RemoteClientConfig
from platform_auth_client.contracts import Decision, DerivedDecisionRequest, UsageOperationResult
from platform_auth_client.errors import (
    AuthConfigurationError,
    M2MTokenError,
    PlatformAuthError,
    RemoteCallerAuthenticationError,
    RemoteTransportError,
)
from platform_auth_client.m2m import AccessTokenProvider
from platform_auth_client.observability import AuthorizationMetrics, OperationMetrics, measured


class AsyncTransport(Protocol):
    async def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
    ) -> dict[str, Any]: ...


class PooledHttpxTransport:
    """Connection-pooled transport for local or separately authenticated callers."""

    def __init__(
        self,
        config: RemoteClientConfig,
        *,
        default_headers: dict[str, str] | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.config = config
        self._default_headers = dict(default_headers or {})
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=config.timeout_seconds)

    def request(self, method: str, path: str, payload: dict[str, Any] | None) -> dict[str, Any]:
        headers = dict(self._default_headers)
        if self.config.local_dev and self.config.service_id:
            headers["x-local-service-id"] = self.config.service_id
        try:
            response = self._client.request(
                method,
                f"{self.config.endpoint}{path}",
                json=payload,
                headers=headers,
                timeout=self.config.timeout_seconds,
            )
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise RemoteTransportError(
                "Platform authorization service is unavailable",
                retryable=True,
            ) from exc
        if response.status_code >= 400:
            _raise_response_error(response.status_code, _error_payload(response.content))
        return _decode_response(response.content)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> PooledHttpxTransport:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class BearerHttpxTransport:
    """Connection-pooled synchronous transport from the optional httpx extra."""

    def __init__(
        self,
        config: RemoteClientConfig,
        token_provider: AccessTokenProvider,
        *,
        client: httpx.Client | None = None,
        metrics: AuthorizationMetrics | None = None,
    ) -> None:
        self.config = config
        self._token_provider = token_provider
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=config.timeout_seconds)
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
                    response = self._send(method, path, payload, token)
            except RemoteCallerAuthenticationError:
                self._token_provider.invalidate(token)
                with measured(metrics, "m2m_token_acquisition"):
                    refreshed = self._token_provider.get_token()
                with measured(metrics, "http_request"):
                    response = self._send(method, path, payload, refreshed)
        except BaseException as exc:
            _finish_error(metrics, exc)
            raise
        if metrics:
            metrics.finish(outcome="success", reason_code="COMPLETED")
        return response

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> BearerHttpxTransport:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _send(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
        token: str,
    ) -> dict[str, Any]:
        try:
            response = self._client.request(
                method,
                f"{self.config.endpoint}{path}",
                json=payload,
                headers={"authorization": f"Bearer {token}"},
                timeout=self.config.timeout_seconds,
            )
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise RemoteTransportError(
                "Platform authorization service is unavailable",
                retryable=True,
            ) from exc
        if response.status_code >= 400:
            response_payload = _error_payload(response.content)
            _raise_response_error(response.status_code, response_payload)
        return _decode_response(response.content)


class AsyncBearerHttpxTransport:
    """Connection-pooled async transport from the optional httpx extra."""

    def __init__(
        self,
        config: RemoteClientConfig,
        token_provider: AccessTokenProvider,
        *,
        client: httpx.AsyncClient | None = None,
        metrics: AuthorizationMetrics | None = None,
    ) -> None:
        self.config = config
        self._token_provider = token_provider
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=config.timeout_seconds)
        self._metrics = metrics

    async def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
    ) -> dict[str, Any]:
        metrics = self._metrics.start("m2m_transport") if self._metrics else None
        if metrics:
            metrics.set_dimensions(authentication_method="cognito_m2m", subject_type="service")
        try:
            with measured(metrics, "m2m_token_acquisition"):
                token = await asyncio.to_thread(self._token_provider.get_token)
            try:
                with measured(metrics, "http_request"):
                    response = await self._send(method, path, payload, token)
            except RemoteCallerAuthenticationError:
                self._token_provider.invalidate(token)
                with measured(metrics, "m2m_token_acquisition"):
                    refreshed = await asyncio.to_thread(self._token_provider.get_token)
                with measured(metrics, "http_request"):
                    response = await self._send(method, path, payload, refreshed)
        except BaseException as exc:
            _finish_error(metrics, exc)
            raise
        if metrics:
            metrics.finish(outcome="success", reason_code="COMPLETED")
        return response

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> AsyncBearerHttpxTransport:
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.aclose()

    async def _send(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
        token: str,
    ) -> dict[str, Any]:
        try:
            response = await self._client.request(
                method,
                f"{self.config.endpoint}{path}",
                json=payload,
                headers={"authorization": f"Bearer {token}"},
                timeout=self.config.timeout_seconds,
            )
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise RemoteTransportError(
                "Platform authorization service is unavailable",
                retryable=True,
            ) from exc
        if response.status_code >= 400:
            response_payload = _error_payload(response.content)
            _raise_response_error(response.status_code, response_payload)
        return _decode_response(response.content)


class AsyncRemoteAuthorizationClient:
    def __init__(
        self,
        transport: AsyncTransport,
        *,
        retry_policy: RetryPolicy | None = None,
        sleep: Callable[[float], Any] = asyncio.sleep,
        random_source: Callable[[], float] = random.random,  # noqa: S311
        metrics: AuthorizationMetrics | None = None,
    ) -> None:
        self.transport = transport
        self.retry_policy = retry_policy or RetryPolicy()
        self._sleep = sleep
        self._random_source = random_source
        self._metrics = metrics

    async def decide(self, request: DerivedDecisionRequest) -> Decision:
        if not isinstance(request, DerivedDecisionRequest):
            raise AuthConfigurationError("Only decision contract v4 is supported")
        try:
            payload = await self._request(
                "POST",
                "/api/authorization/decisions",
                request.to_dict(),
                safe_to_retry=_decision_is_safe_to_retry(request),
                operation="client_decision",
            )
            return Decision.from_dict(payload)
        except (KeyError, TypeError, ValueError) as exc:
            raise RemoteTransportError(
                "Platform authorization service returned an invalid decision",
                retryable=False,
            ) from exc

    async def confirm_usage(self, operation_id: str) -> UsageOperationResult:
        return _usage_transition_result(
            await self._request(
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

    async def settle_usage(self, operation_id: str) -> UsageOperationResult:
        return _usage_transition_result(
            await self._request(
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

    async def release_usage(self, operation_id: str) -> UsageOperationResult:
        return _usage_transition_result(
            await self._request(
                "POST",
                _usage_operation_path(operation_id, "release"),
                None,
                safe_to_retry=True,
                operation="client_release",
            ),
            operation_id=operation_id,
            expected_state="released",
        )

    async def _request(
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
                    response = await self.transport.request(method, path, payload)
            except (RemoteTransportError, M2MTokenError) as exc:
                retryable = bool((exc.details or {}).get("retryable"))
                if not safe_to_retry or not retryable or attempt >= self.retry_policy.max_attempts:
                    _finish_error(metrics, exc)
                    raise
                with measured(metrics, "retry_backoff"):
                    await self._sleep(
                        self.retry_policy.delay(
                            attempt,
                            random_value=self._random_source(),
                        )
                    )
            except BaseException as exc:
                _finish_error(metrics, exc)
                raise
            else:
                if metrics:
                    metrics.finish(outcome="success", reason_code="COMPLETED")
                return response
        raise AssertionError("unreachable")


def _finish_error(metrics: OperationMetrics | None, exc: BaseException) -> None:
    if metrics is None:
        return
    reason_code = exc.code if isinstance(exc, PlatformAuthError) else "INTERNAL_ERROR"
    metrics.finish(outcome="error", reason_code=reason_code)


def _error_payload(body: bytes) -> dict[str, Any]:
    try:
        return _decode_response(body)
    except RemoteTransportError:
        return {}
