from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class PlatformAuthError(Exception):
    code: str
    message: str
    status_code: int = 403
    details: dict[str, Any] | None = None

    def to_response(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"error": self.code, "message": self.message}
        if self.details:
            payload["details"] = self.details
        return payload


class AuthConfigurationError(PlatformAuthError):
    def __init__(self, message: str) -> None:
        super().__init__("AUTH_CONFIGURATION_ERROR", message, 500)


class M2MTokenError(PlatformAuthError):
    def __init__(self, message: str, *, retryable: bool) -> None:
        super().__init__("M2M_TOKEN_UNAVAILABLE", message, 503, {"retryable": retryable})


class M2MCredentialsRejectedError(M2MTokenError):
    def __init__(self) -> None:
        super().__init__("Cognito M2M credentials were rejected", retryable=False)


class RemoteTransportError(PlatformAuthError):
    def __init__(
        self,
        message: str,
        *,
        retryable: bool,
        code: str = "DECISION_SERVICE_UNAVAILABLE",
        status_code: int = 503,
    ) -> None:
        super().__init__(code, message, status_code, {"retryable": retryable})


class RemoteCallerAuthenticationError(RemoteTransportError):
    def __init__(self) -> None:
        super().__init__(
            "Platform authorization rejected the calling service credential",
            retryable=False,
            code="CALLER_UNAUTHENTICATED",
            status_code=401,
        )


class RemoteCallerScopeError(RemoteTransportError):
    def __init__(self) -> None:
        super().__init__(
            "Platform authorization rejected the calling service scope",
            retryable=False,
            code="CALLER_SCOPE_DENIED",
            status_code=403,
        )
