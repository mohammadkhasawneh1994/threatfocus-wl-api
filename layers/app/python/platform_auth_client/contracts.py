from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, cast

AuthorizationScope = Literal["tenant", "platform"]
QuotaType = Literal["metered", "allocation"]
SubjectType = Literal["user", "caller_service"]
UsageOperationState = Literal["reserved", "settled", "released", "expired"]


@dataclass(frozen=True, repr=False)
class SubjectRequest:
    type: SubjectType
    access_token: str | None = None
    local_user_id: str | None = None

    def __repr__(self) -> str:
        access_token = "[REDACTED]" if self.access_token is not None else None
        return (
            f"SubjectRequest(type={self.type!r}, access_token={access_token!r}, "
            f"local_user_id={self.local_user_id!r})"
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"type": self.type}
        if self.access_token is not None:
            payload["accessToken"] = self.access_token
        if self.local_user_id is not None:
            payload["localUserId"] = self.local_user_id
        return payload


@dataclass(frozen=True)
class ResourceRequest:
    type: str
    id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "id": self.id}


@dataclass(frozen=True)
class UsageInvocationRequest:
    """Invocation facts for a registry-derived contract-v4 operation."""

    amount: int = 1
    operation_id: str | None = None
    resource_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"amount": self.amount}
        if self.operation_id is not None:
            payload["operationId"] = self.operation_id
        if self.resource_id is not None:
            payload["resourceId"] = self.resource_id
        return payload


@dataclass(frozen=True)
class DerivedDecisionRequest:
    """Contract-v4 request containing no caller-supplied operation semantics."""

    tenant_id: str | None
    subject: SubjectRequest
    resource: ResourceRequest
    action: str
    usage_invocation: UsageInvocationRequest | None = None
    request_id: str | None = None
    contract_version: Literal["4"] = field(default="4", init=False)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "contractVersion": self.contract_version,
            "subject": self.subject.to_dict(),
            "resource": self.resource.to_dict(),
            "action": self.action,
            "requestContext": {"requestId": self.request_id},
        }
        if self.tenant_id is not None:
            payload["tenantId"] = self.tenant_id
        if self.usage_invocation is not None:
            payload["usageInput"] = self.usage_invocation.to_dict()
        return payload


@dataclass(frozen=True)
class TrustedPrincipal:
    type: Literal["user", "service"]
    id: str


@dataclass(frozen=True)
class UsageOperationResult:
    operation_id: str
    state: UsageOperationState
    amount: int
    period: str
    quota_type: QuotaType
    resource_id: str | None = None

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> UsageOperationResult:
        operation_id = payload.get("operationId")
        state = payload.get("state")
        amount = payload.get("amount")
        period = payload.get("period")
        quota_type = payload.get("quotaType")
        resource_id = payload.get("resourceId")
        if not isinstance(operation_id, str) or not operation_id:
            raise ValueError("Usage operation is missing an operation ID")
        if state not in {"reserved", "settled", "released", "expired"}:
            raise ValueError("Usage operation has an invalid state")
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
            raise ValueError("Usage operation has an invalid amount")
        if not isinstance(period, str) or not period:
            raise ValueError("Usage operation has an invalid period")
        if quota_type not in {"metered", "allocation"}:
            raise ValueError("Usage operation has an invalid quota type")
        if quota_type == "allocation":
            if not isinstance(resource_id, str) or not resource_id or period != "current":
                raise ValueError("Allocation operation has invalid resource or period fields")
        elif resource_id is not None or period == "current":
            raise ValueError("Metered operation has allocation-only fields")
        return cls(
            operation_id=operation_id,
            state=cast(UsageOperationState, state),
            amount=amount,
            period=period,
            quota_type=cast(QuotaType, quota_type),
            resource_id=resource_id,
        )


@dataclass(frozen=True)
class Decision:
    decision_id: str
    allowed: bool
    reason_code: str
    caller_service_id: str | None = None
    principal: TrustedPrincipal | None = None
    tenant_id: str | None = None
    tenant_role: str | None = None
    platform_role: str | None = None
    plan_id: str | None = None
    subscription_status: str | None = None
    action: str | None = None
    feature: str | None = None
    usage_operation: UsageOperationResult | None = None
    policy_revision: str = "1"
    valid_until: str | None = None
    request_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    authorization_scope: AuthorizationScope = "tenant"
    required_permission: str | None = None

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Decision:
        if not isinstance(payload.get("decisionId"), str) or not payload["decisionId"]:
            raise ValueError("Decision response is missing a decision ID")
        if not isinstance(payload.get("allowed"), bool):
            raise ValueError("Decision response has an invalid allowed value")
        if not isinstance(payload.get("reasonCode"), str) or not payload["reasonCode"]:
            raise ValueError("Decision response is missing a reason code")
        principal_payload = payload.get("principal")
        usage_payload = payload.get("usageOperation")
        if isinstance(principal_payload, dict) and principal_payload.get("type") not in {
            "user",
            "service",
        }:
            raise ValueError("Decision response has an invalid principal type")
        if isinstance(principal_payload, dict) and not isinstance(principal_payload.get("id"), str):
            raise ValueError("Decision response has an invalid principal ID")
        if usage_payload is not None and not isinstance(usage_payload, dict):
            raise ValueError("Decision response has an invalid usage operation")
        authorization_scope = payload.get("authorizationScope", "tenant")
        if authorization_scope not in {"tenant", "platform"}:
            raise ValueError("Decision response has an invalid authorization scope")
        required_permission = payload.get("requiredPermission")
        if required_permission is not None and not isinstance(required_permission, str):
            raise ValueError("Decision response has an invalid required permission")
        return cls(
            decision_id=str(payload["decisionId"]),
            allowed=payload["allowed"],
            reason_code=str(payload["reasonCode"]),
            caller_service_id=payload.get("callerServiceId"),
            principal=(
                TrustedPrincipal(
                    cast(Literal["user", "service"], str(principal_payload["type"])),
                    str(principal_payload["id"]),
                )
                if isinstance(principal_payload, dict)
                else None
            ),
            tenant_id=payload.get("tenantId"),
            tenant_role=payload.get("tenantRole"),
            platform_role=payload.get("platformRole"),
            plan_id=payload.get("planId"),
            subscription_status=payload.get("subscriptionStatus"),
            action=payload.get("action"),
            feature=payload.get("feature"),
            authorization_scope=cast(AuthorizationScope, authorization_scope),
            required_permission=required_permission,
            usage_operation=(
                UsageOperationResult.from_dict(usage_payload)
                if isinstance(usage_payload, dict)
                else None
            ),
            policy_revision=str(payload.get("policyRevision", "1")),
            valid_until=payload.get("validUntil"),
            request_id=payload.get("requestId"),
            details=dict(payload.get("details") or {}),
        )
