"""Regression tests for transient GitHub token verification failures."""

from unittest.mock import patch

import httpx2
import pytest
from key_value.aio.stores.memory import MemoryStore
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend
from starlette.requests import HTTPConnection

from fastmcp.server.auth.oauth_proxy import OAuthProxy
from fastmcp.server.auth.providers.github import GitHubProvider, GitHubTokenVerifier


def _user_response(request: httpx2.Request) -> httpx2.Response:
    return httpx2.Response(
        200,
        json={
            "id": 12345,
            "login": "testuser",
            "name": "Test User",
            "email": "test@example.com",
            "avatar_url": "https://github.com/testuser.png",
        },
        request=request,
    )


async def test_unauthorized_token_is_still_invalid():
    """An explicit GitHub 401 remains an invalid credential."""

    async def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(401, json={"message": "Bad credentials"}, request=request)

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        verifier = GitHubTokenVerifier(http_client=client)
        assert await verifier.verify_token("invalid-token") is None


async def test_user_endpoint_5xx_is_transient_failure():
    """A GitHub user API outage must not be reported as an invalid token."""

    async def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            503,
            json={"message": "Service unavailable"},
            request=request,
        )

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        verifier = GitHubTokenVerifier(http_client=client)
        with pytest.raises(httpx2.HTTPStatusError) as exc_info:
            await verifier.verify_token("valid-but-unverifiable")

    assert exc_info.value.response.status_code == 503


async def test_scope_endpoint_5xx_is_transient_failure():
    """A scope lookup outage must not become a false missing-scope result."""

    async def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/user":
            return _user_response(request)
        return httpx2.Response(
            503,
            json={"message": "Service unavailable"},
            request=request,
        )

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        verifier = GitHubTokenVerifier(
            required_scopes=["repo"],
            http_client=client,
        )
        with pytest.raises(httpx2.HTTPStatusError) as exc_info:
            await verifier.verify_token("valid-but-unverifiable")

    assert exc_info.value.response.status_code == 503


async def test_network_error_is_transient_failure():
    """Network failures propagate instead of invalidating the credential."""

    async def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("GitHub unavailable", request=request)

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        verifier = GitHubTokenVerifier(http_client=client)
        with pytest.raises(httpx2.RequestError):
            await verifier.verify_token("valid-but-unverifiable")


async def test_bearer_backend_does_not_convert_5xx_to_invalid_token():
    """Standalone verifier outages remain exceptions through bearer auth."""

    async def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            503,
            json={"message": "Service unavailable"},
            request=request,
        )

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        backend = BearerAuthBackend(GitHubTokenVerifier(http_client=client))
        connection = HTTPConnection(
            {
                "type": "http",
                "headers": [(b"authorization", b"Bearer still-valid")],
            }
        )
        with pytest.raises(httpx2.HTTPStatusError):
            await backend.authenticate(connection)


async def test_github_provider_restores_transient_error_swallowed_by_oauth_proxy():
    """GitHubProvider must not let OAuthProxy turn a 503 into invalid_token."""

    async def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            503,
            json={"message": "Service unavailable"},
            request=request,
        )

    async def oauth_proxy_swallowing_verifier_error(
        self: OAuthProxy, token: str
    ) -> None:
        try:
            await self._token_validator.verify_token("upstream-token")
        except Exception:
            return None
        return None

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        provider = GitHubProvider(
            client_id="client-id",
            client_secret="client-secret",
            base_url="https://mcp.example.com",
            jwt_signing_key="test-signing-key",
            client_storage=MemoryStore(),
            http_client=client,
        )
        with patch.object(
            OAuthProxy,
            "load_access_token",
            oauth_proxy_swallowing_verifier_error,
        ):
            with pytest.raises(httpx2.HTTPStatusError) as exc_info:
                await provider.load_access_token("fastmcp-token")

    assert exc_info.value.response.status_code == 503


async def test_github_provider_keeps_invalid_token_as_none():
    """The provider-specific recovery must not turn a real 401 into an error."""

    async def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(401, json={"message": "Bad credentials"}, request=request)

    async def oauth_proxy_invalid_token(self: OAuthProxy, token: str) -> None:
        return await self._token_validator.verify_token("upstream-token")

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        provider = GitHubProvider(
            client_id="client-id",
            client_secret="client-secret",
            base_url="https://mcp.example.com",
            jwt_signing_key="test-signing-key",
            client_storage=MemoryStore(),
            http_client=client,
        )
        with patch.object(OAuthProxy, "load_access_token", oauth_proxy_invalid_token):
            assert await provider.load_access_token("fastmcp-token") is None
