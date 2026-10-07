from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Literal, overload

from fastapi import Header, HTTPException, Request

from platform_auth_client.client import RemoteAuthorizationClient
from platform_auth_client.config import local_dev_mode, warn_local_identity_input
from platform_auth_client.context import AuthContext, UsageAuthContext
from platform_auth_client.contracts import (
    Decision,
    DerivedDecisionRequest,
    ResourceRequest,
    SubjectRequest,
    UsageInvocationRequest,
)
from platform_auth_client.errors import (
    AuthConfigurationError,
    PlatformAuthError,
    RemoteTransportError,
)
from platform_auth_client.validation import validate_usage_decision, validate_usage_invocation

TenantMode = Literal["resolved", "path", "none"]
UsageInvocationFactory = Callable[[Request], UsageInvocationRequest]


@overload
def require_remote_access(
    client: RemoteAuthorizationClient,
    *,
    action: str,
    resource_type: str,
    tenant_mode: TenantMode = "resolved",
    tenant_path_parameter: str | None = None,
    resource_id_path_parameter: str | None = None,
    usage_invocation_factory: None = None,
) -> Callable[..., AuthContext]: ...


@overload
def require_remote_access(
    client: RemoteAuthorizationClient,
    *,
    action: str,
    resource_type: str,
    tenant_mode: TenantMode = "resolved",
    tenant_path_parameter: str | None = None,
    resource_id_path_parameter: str | None = None,
    usage_invocation_factory: UsageInvocationFactory,
) -> Callable[..., UsageAuthContext]: ...


def require_remote_access(
    client: RemoteAuthorizationClient,
    *,
    action: str,
    resource_type: str,
    tenant_mode: TenantMode = "resolved",
    tenant_path_parameter: str | None = None,
    resource_id_path_parameter: str | None = None,
    usage_invocation_factory: UsageInvocationFactory | None = None,
) -> Callable[..., AuthContext]:
    """Build a contract-v4 decision dependency from HTTP invocation facts.

    This helper forwards the original bearer access token for independent central
    validation. Platform Auth derives access, permission, feature, quota, and
    usage semantics from the registered action. ``tenant_mode`` describes only
    how this HTTP operation supplies tenant context; it is never serialized as
    authorization policy. A configured usage factory requires one stable
    invocation identity and returns a ``UsageAuthContext`` only after the
    reserved usage result is correlated with that identity.
    """

    if not action.strip():
        raise ValueError("action must not be blank")
    if not resource_type.strip():
        raise ValueError("resource_type must not be blank")
    if tenant_mode not in {"resolved", "path", "none"}:
        raise ValueError("tenant_mode must be resolved, path, or none")
    if tenant_mode == "path":
        if tenant_path_parameter is None or not tenant_path_parameter.strip():
            raise ValueError("tenant_path_parameter is required for tenant_mode=path")
    elif tenant_path_parameter is not None:
        raise ValueError("tenant_path_parameter requires tenant_mode=path")
    if resource_id_path_parameter is not None and not resource_id_path_parameter.strip():
        raise ValueError("resource_id_path_parameter must not be blank")

    def dependency(
        request: Request,
        authorization: str | None = Header(default=None, alias="Authorization"),
        local_user_id: str | None = Header(default=None, alias="X-User-Id"),
    ) -> AuthContext:
        try:
            local_identity_enabled = local_dev_mode()
            token = _subject_access_token(authorization, request) if authorization else None
            use_local_user = bool(local_identity_enabled and local_user_id and not token)
            if not token and not use_local_user:
                raise HTTPException(status_code=401, detail={"error": "UNAUTHORIZED"})
            if use_local_user:
                warn_local_identity_input("X-User-Id")
            tenant_selector = _tenant_selector(
                request,
                tenant_mode=tenant_mode,
                tenant_path_parameter=tenant_path_parameter,
            )
            resource_id = _path_parameter(
                request,
                resource_id_path_parameter,
                error="RESOURCE_SELECTOR_MISSING",
            )
            usage_invocation = None
            if usage_invocation_factory is not None:
                usage_invocation = usage_invocation_factory(request)
                try:
                    validate_usage_invocation(usage_invocation)
                except AuthConfigurationError as exc:
                    raise HTTPException(
                        status_code=500,
                        detail={"error": "INVALID_USAGE_INVOCATION"},
                    ) from exc
            decision = client.decide(
                DerivedDecisionRequest(
                    tenant_id=tenant_selector,
                    subject=SubjectRequest(
                        type="user",
                        access_token=token,
                        local_user_id=local_user_id if use_local_user else None,
                    ),
                    resource=ResourceRequest(type=resource_type, id=resource_id),
                    action=action,
                    usage_invocation=usage_invocation,
                    request_id=request.headers.get("x-request-id"),
                )
            )
            if not decision.allowed:
                status_code = 429 if decision.reason_code == "QUOTA_EXCEEDED" else 403
                if decision.reason_code in {"UNAUTHORIZED", "SUBJECT_UNAUTHENTICATED"}:
                    status_code = 401
                raise HTTPException(
                    status_code=status_code,
                    detail={
                        "error": decision.reason_code,
                        "decisionId": decision.decision_id,
                        "details": decision.details,
                    },
                )
            if not _allowed_decision_matches_request(
                decision,
                action=action,
                tenant_mode=tenant_mode,
                tenant_selector=tenant_selector,
            ):
                raise HTTPException(status_code=503, detail={"error": "INVALID_DECISION"})
            try:
                usage_operation = validate_usage_decision(
                    usage_invocation,
                    decision.usage_operation,
                )
            except RemoteTransportError as exc:
                raise HTTPException(
                    status_code=503,
                    detail={"error": "INVALID_DECISION"},
                ) from exc
            assert decision.principal is not None
            context_type = UsageAuthContext if usage_invocation is not None else AuthContext
            return context_type(
                user_id=decision.principal.id,
                tenant_id=decision.tenant_id,
                role=decision.tenant_role,
                platform_role=decision.platform_role,
                plan_id=decision.plan_id,
                subscription_status=decision.subscription_status,
                request_id=decision.request_id,
                principal_type=decision.principal.type,
                principal_id=decision.principal.id,
                caller_service_id=decision.caller_service_id,
                decision_id=decision.decision_id,
                usage_operation=usage_operation,
            )
        except PlatformAuthError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.to_response()) from exc

    return dependency


def _allowed_decision_matches_request(
    decision: Decision,
    *,
    action: str,
    tenant_mode: TenantMode,
    tenant_selector: str | None,
) -> bool:
    """Reject an allowed response that does not describe the request made."""

    principal = decision.principal
    tenant_id = decision.tenant_id
    return bool(
        principal is not None
        and principal.type == "user"
        and principal.id
        and decision.action == action
        and (
            decision.authorization_scope == "platform" and tenant_id is None
            if tenant_mode == "none"
            else decision.authorization_scope == "tenant"
            and bool(tenant_id)
            and (tenant_selector is None or tenant_id == tenant_selector)
        )
    )


def _tenant_selector(
    request: Request,
    *,
    tenant_mode: TenantMode,
    tenant_path_parameter: str | None,
) -> str | None:
    if tenant_mode != "path":
        return None
    assert tenant_path_parameter is not None
    return _path_parameter(
        request,
        tenant_path_parameter,
        error="TENANT_SELECTOR_MISSING",
    )


def _path_parameter(request: Request, name: str | None, *, error: str) -> str | None:
    if name is None:
        return None
    value = request.path_params.get(name)
    if value is None or not str(value).strip():
        raise HTTPException(status_code=400, detail={"error": error})
    return str(value)


def _bearer_token(value: str | None) -> str:
    if not value:
        raise HTTPException(status_code=401, detail={"error": "UNAUTHORIZED"})
    scheme, separator, token = value.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=401, detail={"error": "UNAUTHORIZED"})
    return token.strip()


def _subject_access_token(value: str, request: Request) -> str:
    try:
        return _bearer_token(value)
    except HTTPException:
        if _has_rest_cognito_authorizer_claims(request) and _looks_like_raw_jwt(value):
            return value.strip()
        raise


def _has_rest_cognito_authorizer_claims(request: Request) -> bool:
    event = request.scope.get("aws.event")
    if not isinstance(event, Mapping):
        return False
    request_context = event.get("requestContext")
    if not isinstance(request_context, Mapping):
        return False
    authorizer = request_context.get("authorizer")
    if not isinstance(authorizer, Mapping):
        return False
    claims = authorizer.get("claims")
    return isinstance(claims, Mapping) and bool(claims)


def _looks_like_raw_jwt(value: str) -> bool:
    token = value.strip()
    return (
        not any(char.isspace() for char in token)
        and all(token.split("."))
        and token.count(".") == 2
    )
