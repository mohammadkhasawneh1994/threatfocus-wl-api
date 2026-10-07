from __future__ import annotations

import os
import warnings
from dataclasses import dataclass
from urllib.parse import urlparse

from platform_auth_client.errors import AuthConfigurationError

ALLOWED_ENVIRONMENTS = frozenset({"local", "dev", "test", "staging", "prod"})
LOCAL_AWS_ENVIRONMENTS = frozenset({"local", "test"})
LOCAL_ENDPOINT_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "localstack"})


class LocalIdentityHeaderWarning(UserWarning):
    """Warn when deprecated mock identity input is used locally."""


def platform_environment() -> str:
    value = os.getenv("PLATFORM_ENV", "local").strip().lower()
    if value not in ALLOWED_ENVIRONMENTS:
        allowed = ", ".join(sorted(ALLOWED_ENVIRONMENTS))
        raise AuthConfigurationError(f"PLATFORM_ENV must be one of: {allowed}")
    return value


def _boolean_env(name: str, default: str = "false") -> bool:
    value = os.getenv(name, default).strip().lower()
    if value not in {"true", "false"}:
        raise AuthConfigurationError(f"{name} must be true or false")
    return value == "true"


def local_dev_mode() -> bool:
    environment = platform_environment()
    enabled = _boolean_env("AUTH_LOCAL_DEV_MODE")
    if enabled and environment != "local":
        raise AuthConfigurationError(
            "AUTH_LOCAL_DEV_MODE=true requires explicit PLATFORM_ENV=local"
        )
    return enabled


def warn_local_identity_input(name: str) -> None:
    warnings.warn(
        f"{name} is a deprecated local-only identity input and must not be used "
        "by deployed services",
        LocalIdentityHeaderWarning,
        stacklevel=2,
    )


def validate_local_endpoint(name: str, endpoint: str) -> None:
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in LOCAL_ENDPOINT_HOSTS:
        raise AuthConfigurationError(
            f"{name} must use a loopback or LocalStack HTTP(S) endpoint in local/test environments"
        )


def required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise AuthConfigurationError(f"{name} is required")
    return value


@dataclass(frozen=True)
class RemoteClientConfig:
    endpoint: str
    timeout_seconds: float = 5.0
    local_dev: bool = False
    service_id: str | None = None

    def __post_init__(self) -> None:
        parsed = urlparse(self.endpoint)
        environment = platform_environment()
        local_network = environment in LOCAL_AWS_ENVIRONMENTS
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise AuthConfigurationError("PLATFORM_AUTH_ENDPOINT must be an absolute HTTP(S) URL")
        if local_network:
            validate_local_endpoint("PLATFORM_AUTH_ENDPOINT", self.endpoint)
        elif parsed.scheme != "https":
            raise AuthConfigurationError(
                "PLATFORM_AUTH_ENDPOINT must use HTTPS outside local/test environments"
            )
        if self.timeout_seconds <= 0 or self.timeout_seconds > 10:
            raise AuthConfigurationError("PLATFORM_AUTH_TIMEOUT_SECONDS must be > 0 and <= 10")
        if self.local_dev and environment != "local":
            raise AuthConfigurationError(
                "local_dev=True requires explicit PLATFORM_ENV=local"
            )
        if self.local_dev and not self.service_id:
            raise AuthConfigurationError("Local mode requires PLATFORM_AUTH_LOCAL_SERVICE_ID")

    @classmethod
    def from_env(cls) -> RemoteClientConfig:
        endpoint = required_env("PLATFORM_AUTH_ENDPOINT")
        local = local_dev_mode()
        try:
            timeout = float(os.getenv("PLATFORM_AUTH_TIMEOUT_SECONDS", "5"))
        except ValueError as exc:
            raise AuthConfigurationError("PLATFORM_AUTH_TIMEOUT_SECONDS must be numeric") from exc
        service_id = os.getenv("PLATFORM_AUTH_LOCAL_SERVICE_ID") or None
        return cls(endpoint.rstrip("/"), timeout, local, service_id)
