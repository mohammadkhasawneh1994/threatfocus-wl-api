from platform_auth_client._version import __version__
from platform_auth_client.client import RemoteAuthorizationClient
from platform_auth_client.context import AuthContext, UsageAuthContext
from platform_auth_client.contracts import (
    Decision,
    DerivedDecisionRequest,
    UsageInvocationRequest,
    UsageOperationResult,
)
from platform_auth_client.errors import PlatformAuthError
from platform_auth_client.m2m import (
    CognitoClientCredentialsTokenProvider,
    CognitoM2MConfig,
    M2MClientCredentials,
)
from platform_auth_client.observability import AuthorizationMetrics
from platform_auth_client.validation import validate_usage_decision

__all__ = [
    "AuthContext",
    "UsageAuthContext",
    "PlatformAuthError",
    "Decision",
    "DerivedDecisionRequest",
    "UsageInvocationRequest",
    "UsageOperationResult",
    "RemoteAuthorizationClient",
    "CognitoClientCredentialsTokenProvider",
    "CognitoM2MConfig",
    "M2MClientCredentials",
    "AuthorizationMetrics",
    "validate_usage_decision",
    "__version__",
]
