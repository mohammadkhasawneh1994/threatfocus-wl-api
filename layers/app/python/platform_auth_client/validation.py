from __future__ import annotations

from typing import overload

from platform_auth_client.contracts import UsageInvocationRequest, UsageOperationResult
from platform_auth_client.errors import AuthConfigurationError, RemoteTransportError


def validate_usage_invocation(invocation: UsageInvocationRequest) -> None:
    """Require one retry-safe usage identity without accepting policy semantics."""

    if not isinstance(invocation, UsageInvocationRequest):
        raise AuthConfigurationError("Usage invocation must use UsageInvocationRequest")
    if (
        not isinstance(invocation.amount, int)
        or isinstance(invocation.amount, bool)
        or invocation.amount <= 0
    ):
        raise AuthConfigurationError("Usage invocation amount must be a positive integer")
    if invocation.operation_id is not None and (
        not isinstance(invocation.operation_id, str) or not invocation.operation_id.strip()
    ):
        raise AuthConfigurationError("Metered operation ID must not be blank")
    if invocation.resource_id is not None and (
        not isinstance(invocation.resource_id, str) or not invocation.resource_id.strip()
    ):
        raise AuthConfigurationError("Allocation resource ID must not be blank")
    if (invocation.operation_id is None) == (invocation.resource_id is None):
        raise AuthConfigurationError(
            "Usage invocation requires exactly one operation ID or resource ID"
        )


@overload
def validate_usage_decision(
    invocation: None,
    operation: UsageOperationResult | None,
) -> None: ...


@overload
def validate_usage_decision(
    invocation: UsageInvocationRequest,
    operation: UsageOperationResult | None,
) -> UsageOperationResult: ...


def validate_usage_decision(
    invocation: UsageInvocationRequest | None,
    operation: UsageOperationResult | None,
) -> UsageOperationResult | None:
    """Return correlated usage or fail closed on an inconsistent decision."""

    if invocation is None:
        if operation is not None:
            raise _invalid_usage_decision()
        return None

    validate_usage_invocation(invocation)
    if operation is None or operation.state != "reserved" or operation.amount != invocation.amount:
        raise _invalid_usage_decision()
    if invocation.resource_id is not None:
        if (
            operation.quota_type != "allocation"
            or operation.resource_id != invocation.resource_id
        ):
            raise _invalid_usage_decision()
        return operation
    if (
        operation.quota_type != "metered"
        or operation.operation_id != invocation.operation_id
        or operation.resource_id is not None
    ):
        raise _invalid_usage_decision()
    return operation


def _invalid_usage_decision() -> RemoteTransportError:
    return RemoteTransportError(
        "Platform authorization returned usage that does not match the invocation",
        retryable=False,
        code="INVALID_DECISION",
    )
