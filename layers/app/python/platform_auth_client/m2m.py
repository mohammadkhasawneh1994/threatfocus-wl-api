from __future__ import annotations

import json
import math
import os
import re
import threading
import time
from base64 import b64encode
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from platform_auth_client.config import (
    LOCAL_AWS_ENVIRONMENTS,
    platform_environment,
    required_env,
    validate_local_endpoint,
)
from platform_auth_client.errors import (
    AuthConfigurationError,
    M2MCredentialsRejectedError,
    M2MTokenError,
)

_MAX_TOKEN_BYTES = 16_384
_MAX_RESPONSE_BYTES = 65_536
_COGNITO_CLIENT_ID = re.compile(r"^[A-Za-z0-9]{8,128}$")


@dataclass(frozen=True, repr=False)
class M2MClientCredentials:
    """One confidential Cognito app-client credential.

    Production callers should construct this value inside their secret-provider
    callback. The custom representation prevents accidental secret disclosure.
    """

    client_id: str
    client_secret: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.client_id, str) or not _COGNITO_CLIENT_ID.fullmatch(self.client_id):
            raise AuthConfigurationError("Cognito M2M client ID is invalid")
        if (
            not isinstance(self.client_secret, str)
            or not self.client_secret
            or len(self.client_secret) > 4096
        ):
            raise AuthConfigurationError("Cognito M2M client secret is invalid")
        if any(ord(character) < 32 for character in self.client_id + self.client_secret):
            raise AuthConfigurationError("Cognito M2M credentials contain invalid characters")

    def __repr__(self) -> str:
        return f"M2MClientCredentials(client_id={self.client_id!r}, " "client_secret='[REDACTED]')"


CredentialProvider = Callable[[], M2MClientCredentials | Sequence[M2MClientCredentials]]


@dataclass(frozen=True)
class CognitoM2MConfig:
    token_endpoint: str
    scopes: tuple[str, ...] = ()
    timeout_seconds: float = 5.0
    refresh_skew_seconds: float = 30.0

    def __post_init__(self) -> None:
        parsed = urlparse(self.token_endpoint)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or not parsed.path.endswith("/oauth2/token")
        ):
            raise AuthConfigurationError(
                "PLATFORM_AUTH_M2M_TOKEN_ENDPOINT must be an absolute HTTP(S) URL "
                "ending in /oauth2/token and without credentials, query, or fragment"
            )
        environment = platform_environment()
        if environment in LOCAL_AWS_ENVIRONMENTS:
            validate_local_endpoint("PLATFORM_AUTH_M2M_TOKEN_ENDPOINT", self.token_endpoint)
        elif parsed.scheme != "https":
            raise AuthConfigurationError(
                "PLATFORM_AUTH_M2M_TOKEN_ENDPOINT must use HTTPS outside local/test environments"
            )
        if self.timeout_seconds <= 0 or self.timeout_seconds > 10:
            raise AuthConfigurationError("M2M token timeout must be > 0 and <= 10 seconds")
        if self.refresh_skew_seconds < 0 or self.refresh_skew_seconds > 300:
            raise AuthConfigurationError("M2M refresh skew must be between 0 and 300 seconds")
        if any(
            not scope or len(scope) > 256 or any(char.isspace() for char in scope)
            for scope in self.scopes
        ):
            raise AuthConfigurationError("Cognito M2M scopes are invalid")

    @classmethod
    def from_env(cls) -> CognitoM2MConfig:
        endpoint = required_env("PLATFORM_AUTH_M2M_TOKEN_ENDPOINT")
        scopes = tuple(
            value
            for value in os.getenv("PLATFORM_AUTH_M2M_SCOPES", "").replace(",", " ").split()
            if value
        )
        try:
            timeout = float(os.getenv("PLATFORM_AUTH_M2M_TOKEN_TIMEOUT_SECONDS", "5"))
            refresh_skew = float(os.getenv("PLATFORM_AUTH_M2M_REFRESH_SKEW_SECONDS", "30"))
        except ValueError as exc:
            raise AuthConfigurationError(
                "M2M token timeout and refresh skew must be numeric"
            ) from exc
        return cls(
            token_endpoint=endpoint,
            scopes=scopes,
            timeout_seconds=timeout,
            refresh_skew_seconds=refresh_skew,
        )


@dataclass(frozen=True, repr=False)
class TokenEndpointResponse:
    access_token: str = field(repr=False)
    expires_in: float

    def __repr__(self) -> str:
        return (
            "TokenEndpointResponse(access_token='[REDACTED]', " f"expires_in={self.expires_in!r})"
        )


class TokenEndpoint(Protocol):
    def exchange(
        self,
        config: CognitoM2MConfig,
        credentials: M2MClientCredentials,
    ) -> TokenEndpointResponse: ...


class AccessTokenProvider(Protocol):
    def get_token(self) -> str: ...

    def invalidate(self, token: str | None = None) -> None: ...


class CognitoTokenEndpoint:
    """Dependency-neutral Cognito OAuth2 client-credentials exchange."""

    def exchange(
        self,
        config: CognitoM2MConfig,
        credentials: M2MClientCredentials,
    ) -> TokenEndpointResponse:
        encoded_credentials = b64encode(
            f"{credentials.client_id}:{credentials.client_secret}".encode()
        ).decode("ascii")
        values = {"grant_type": "client_credentials"}
        if config.scopes:
            values["scope"] = " ".join(config.scopes)
        request = Request(  # noqa: S310 - endpoint is validated by CognitoM2MConfig
            config.token_endpoint,
            data=urlencode(values).encode(),
            headers={
                "authorization": f"Basic {encoded_credentials}",
                "content-type": "application/x-www-form-urlencoded",
                "accept": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=config.timeout_seconds) as response:  # noqa: S310
                payload = _bounded_json(response)
        except HTTPError as exc:
            payload = _bounded_json(exc)
            oauth_error = payload.get("error")
            if oauth_error == "invalid_client":
                raise M2MCredentialsRejectedError() from exc
            if oauth_error in {"server_error", "temporarily_unavailable"} or exc.code >= 500:
                raise M2MTokenError(
                    "Cognito M2M token service is unavailable",
                    retryable=True,
                ) from exc
            raise M2MTokenError(
                "Cognito M2M token request was rejected",
                retryable=False,
            ) from exc
        except (TimeoutError, URLError) as exc:
            raise M2MTokenError(
                "Cognito M2M token service is unavailable",
                retryable=True,
            ) from exc

        token = payload.get("access_token")
        token_type = payload.get("token_type")
        expires_in = payload.get("expires_in")
        if (
            not isinstance(token, str)
            or not token
            or len(token.encode()) > _MAX_TOKEN_BYTES
            or not isinstance(token_type, str)
            or token_type.lower() != "bearer"
            or isinstance(expires_in, bool)
            or not isinstance(expires_in, int | float)
            or not math.isfinite(expires_in)
            or expires_in <= 0
            or expires_in > 86_400
        ):
            raise M2MTokenError(
                "Cognito M2M token service returned an invalid response",
                retryable=False,
            )
        return TokenEndpointResponse(token, float(expires_in))


@dataclass(frozen=True, repr=False)
class _CachedAccessToken:
    value: str = field(repr=False)
    refresh_at: float


class CognitoClientCredentialsTokenProvider:
    """Thread-safe, rotation-aware in-memory Cognito access-token cache."""

    def __init__(
        self,
        config: CognitoM2MConfig,
        credentials_provider: CredentialProvider,
        *,
        endpoint: TokenEndpoint | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not callable(credentials_provider):
            raise AuthConfigurationError("A Cognito M2M credentials provider is required")
        self.config = config
        self._credentials_provider = credentials_provider
        self._validate_initial_credentials()
        self._endpoint = endpoint or CognitoTokenEndpoint()
        self._clock = clock
        self._condition = threading.Condition()
        self._cached: _CachedAccessToken | None = None
        self._refreshing = False
        self._refresh_generation = 0
        self._last_failure_generation: int | None = None

    def get_token(self) -> str:
        with self._condition:
            cached = self._valid_cached_token()
            if cached:
                return cached
            observed_generation = self._refresh_generation
            if self._refreshing:
                while self._refreshing:
                    self._condition.wait()
                cached = self._valid_cached_token()
                if cached:
                    return cached
                if self._last_failure_generation != observed_generation:
                    raise M2MTokenError(
                        "Cognito M2M token refresh failed",
                        retryable=True,
                    )
            self._refreshing = True

        try:
            response = self._refresh()
        except BaseException:
            with self._condition:
                self._refreshing = False
                self._refresh_generation += 1
                self._last_failure_generation = self._refresh_generation
                self._condition.notify_all()
            raise

        refresh_in = max(0.0, response.expires_in - self.config.refresh_skew_seconds)
        cached = _CachedAccessToken(response.access_token, self._clock() + refresh_in)
        with self._condition:
            self._cached = cached
            self._refreshing = False
            self._refresh_generation += 1
            self._last_failure_generation = None
            self._condition.notify_all()
            return cached.value

    def invalidate(self, token: str | None = None) -> None:
        with self._condition:
            if token is None or (self._cached and self._cached.value == token):
                self._cached = None

    def _valid_cached_token(self) -> str | None:
        if self._cached and self._clock() < self._cached.refresh_at:
            return self._cached.value
        return None

    def _refresh(self) -> TokenEndpointResponse:
        credentials = self._load_credentials()
        for candidate in credentials:
            try:
                return self._endpoint.exchange(self.config, candidate)
            except M2MCredentialsRejectedError:
                continue
        raise M2MCredentialsRejectedError()

    def _validate_initial_credentials(self) -> None:
        try:
            _credential_candidates(self._credentials_provider())
        except AuthConfigurationError:
            raise
        except Exception:
            raise AuthConfigurationError(
                "Cognito M2M credentials provider failed during startup validation"
            ) from None

    def _load_credentials(self) -> tuple[M2MClientCredentials, ...]:
        try:
            return _credential_candidates(self._credentials_provider())
        except AuthConfigurationError:
            raise M2MTokenError(
                "Cognito M2M credentials provider returned invalid credentials",
                retryable=False,
            ) from None
        except Exception:
            raise M2MTokenError(
                "Cognito M2M credentials provider is unavailable",
                retryable=True,
            ) from None


def _credential_candidates(
    value: M2MClientCredentials | Sequence[M2MClientCredentials],
) -> tuple[M2MClientCredentials, ...]:
    candidates = (value,) if isinstance(value, M2MClientCredentials) else tuple(value)
    if not candidates or len(candidates) > 2:
        raise AuthConfigurationError(
            "Cognito M2M credentials provider must return one or two credentials"
        )
    if any(not isinstance(candidate, M2MClientCredentials) for candidate in candidates):
        raise AuthConfigurationError("Cognito M2M credentials provider returned an invalid value")
    return candidates


def _bounded_json(response: Any) -> dict[str, Any]:
    try:
        body = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(body) > _MAX_RESPONSE_BYTES:
            return {}
        payload = json.loads(body.decode("utf-8"))
        return payload if isinstance(payload, dict) else {}
    except (UnicodeDecodeError, json.JSONDecodeError, OSError):
        return {}
