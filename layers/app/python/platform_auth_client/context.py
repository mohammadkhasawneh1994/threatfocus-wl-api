from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from platform_auth_client.contracts import UsageOperationResult

PrincipalType = Literal["user", "service"]


@dataclass(frozen=True)
class AuthContext:
    user_id: str
    tenant_id: str | None
    role: str | None = None
    platform_role: str | None = None
    plan_id: str | None = None
    subscription_status: str | None = None
    permissions: list[str] = field(default_factory=list)
    request_id: str | None = None
    claims: dict[str, Any] = field(default_factory=dict)
    principal_type: PrincipalType = "user"
    principal_id: str | None = None
    caller_service_id: str | None = None
    decision_id: str | None = None
    usage_operation: UsageOperationResult | None = None


@dataclass(frozen=True, kw_only=True)
class UsageAuthContext(AuthContext):
    """Trusted context returned when the dependency requested usage."""

    usage_operation: UsageOperationResult
