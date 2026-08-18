"""Regression tests for transient GitHub token verification failures."""

from unittest.mock import patch

import httpx2
import pytest
from key_value.aio.stores.memory import MemoryStore

from fastmcp.server.auth.oauth_proxy import OAuthProxy
from fastmcp.server.auth.providers.github import GitHubProvider, GitHubTokenVerifier


def _user_response(request: httpx2.Request) -> httpx2.Response:
    return httpx2.Response(
        200,
        json={"id": 12345, "login": "testuser"},
        request=request,
    )


async def test_user_endpoint_5xx_is_transient_failure():
    async def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(503, request=request)

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        verifier = GitHubTokenVerifier(http_client=client)
        with pytest.raises(httpx2.HTTPStatusError) as exc_info:
            await verifier.verify_token("valid-but-unverifiable")

    assert exc_info.value.response.status_code == 503


async def test_scope_endpoint_5xx_is_transient_failure():
    async def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/user":
            return _user_response(request)
        return httpx2.Response(503, request=request)

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        verifier = GitHubTokenVerifier(required_scopes=["repo"], http_client=client)
        with pytest.raises(httpx2.HTTPStatusError):
            await verifier.verify_token("valid-but-unverifiable")


async def test_network_error_is_transient_failure():
    async def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("GitHub unavailable", request=request)

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        verifier = GitHubTokenVerifier(http_client=client)
        with pytest.raises(httpx2.RequestError):
            await verifier.verify_token("valid-but-unverifiable")


async def test_github_provider_restores_error_swallowed_by_oauth_proxy():
    async def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(503, request=request)

    async def swallowing_load_access_token(self: OAuthProxy, token: str):
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
        with patch.object(OAuthProxy, "load_access_token", swallowing_load_access_token):
            with pytest.raises(httpx2.HTTPStatusError) as exc_info:
                await provider.load_access_token("fastmcp-token")

    assert exc_info.value.response.status_code == 503
