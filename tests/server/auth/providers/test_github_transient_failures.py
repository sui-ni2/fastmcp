"""Regression tests for transient GitHub token verification failures."""

import time
from unittest.mock import patch

import httpx2
import pytest
from key_value.aio.stores.memory import MemoryStore

from fastmcp.server.auth.oauth_proxy import OAuthProxy
from fastmcp.server.auth.oauth_proxy.models import JTIMapping, UpstreamTokenSet
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


async def test_user_endpoint_rate_limit_is_transient_failure():
    async def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(429, request=request)

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        verifier = GitHubTokenVerifier(http_client=client)
        with pytest.raises(httpx2.HTTPStatusError) as exc_info:
            await verifier.verify_token("valid-but-unverifiable")

    assert exc_info.value.response.status_code == 429


async def test_standalone_scope_endpoint_401_rejects_token():
    calls = 0

    async def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        if request.url.path == "/user":
            return _user_response(request)
        return httpx2.Response(401, request=request)

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        verifier = GitHubTokenVerifier(
            required_scopes=["user"],
            cache_ttl_seconds=300,
            http_client=client,
        )
        result1 = await verifier.verify_token("revoked-between-requests")
        result2 = await verifier.verify_token("revoked-between-requests")

    assert result1 is None
    assert result2 is None
    assert calls == 4  # invalid results are not cached


async def test_standalone_scope_endpoint_5xx_does_not_synthesize_scope():
    calls = 0

    async def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        if request.url.path == "/user":
            return _user_response(request)
        return httpx2.Response(503, request=request)

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        verifier = GitHubTokenVerifier(
            required_scopes=["user"],
            cache_ttl_seconds=300,
            http_client=client,
        )
        result1 = await verifier.verify_token("valid-during-scope-degradation")
        result2 = await verifier.verify_token("valid-during-scope-degradation")

    assert result1 is None
    assert result2 is None
    assert calls == 4  # rejected results are not cached


async def test_standalone_scope_transport_error_does_not_synthesize_scope():
    calls = 0

    async def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        if request.url.path == "/user":
            return _user_response(request)
        raise httpx2.ConnectError("scope endpoint unavailable", request=request)

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        verifier = GitHubTokenVerifier(
            required_scopes=["user"],
            cache_ttl_seconds=300,
            http_client=client,
        )
        result = await verifier.verify_token("valid-during-scope-network-outage")

    assert result is None
    assert calls == 2


async def test_scope_endpoint_failure_does_not_grant_unverified_required_scope():
    async def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/user":
            return _user_response(request)
        return httpx2.Response(503, request=request)

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        verifier = GitHubTokenVerifier(required_scopes=["repo"], http_client=client)
        result = await verifier.verify_token("missing-verifiable-repo-scope")

    assert result is None


async def test_provider_uses_trusted_grant_when_scope_endpoint_fails_and_caches():
    calls = 0

    async def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        if request.url.path == "/user":
            return _user_response(request)
        return httpx2.Response(503, request=request)

    storage = MemoryStore()
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        provider = GitHubProvider(
            client_id="client-id",
            client_secret="client-secret",
            base_url="https://mcp.example.com",
            required_scopes=["user"],
            cache_ttl_seconds=300,
            jwt_signing_key="test-signing-key",
            client_storage=storage,
            http_client=client,
        )

        upstream_token_id = "trusted-upstream-token"
        jti = "fastmcp-access-jti"
        await provider._upstream_token_store.put(
            key=upstream_token_id,
            value=UpstreamTokenSet(
                upstream_token_id=upstream_token_id,
                access_token="github-access-token",
                refresh_token=None,
                refresh_token_expires_at=None,
                expires_at=time.time() + 3600,
                token_type="Bearer",
                scope="user",
                client_id="mcp-client",
                created_at=time.time(),
            ),
            ttl=3600,
        )
        await provider._jti_mapping_store.put(
            key=jti,
            value=JTIMapping(
                jti=jti,
                upstream_token_id=upstream_token_id,
                created_at=time.time(),
            ),
            ttl=3600,
        )
        fastmcp_token = provider.jwt_issuer.issue_access_token(
            client_id="mcp-client",
            scopes=["user"],
            jti=jti,
            expires_in=3600,
        )

        result1 = await provider.load_access_token(fastmcp_token)
        result2 = await provider.load_access_token(fastmcp_token)

    assert result1 is not None
    assert result1.scopes == ["user"]
    assert result2 is not None
    assert result2.scopes == ["user"]
    assert calls == 2  # second provider validation is served by verifier cache


async def test_provider_scope_401_rejects_even_with_trusted_grant():
    calls = 0

    async def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        if request.url.path == "/user":
            return _user_response(request)
        return httpx2.Response(401, request=request)

    storage = MemoryStore()
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        provider = GitHubProvider(
            client_id="client-id",
            client_secret="client-secret",
            base_url="https://mcp.example.com",
            required_scopes=["user"],
            cache_ttl_seconds=300,
            jwt_signing_key="test-signing-key",
            client_storage=storage,
            http_client=client,
        )

        upstream_token_id = "trusted-upstream-token"
        jti = "fastmcp-access-jti"
        await provider._upstream_token_store.put(
            key=upstream_token_id,
            value=UpstreamTokenSet(
                upstream_token_id=upstream_token_id,
                access_token="github-access-token",
                refresh_token=None,
                refresh_token_expires_at=None,
                expires_at=time.time() + 3600,
                token_type="Bearer",
                scope="user",
                client_id="mcp-client",
                created_at=time.time(),
            ),
            ttl=3600,
        )
        await provider._jti_mapping_store.put(
            key=jti,
            value=JTIMapping(
                jti=jti,
                upstream_token_id=upstream_token_id,
                created_at=time.time(),
            ),
            ttl=3600,
        )
        fastmcp_token = provider.jwt_issuer.issue_access_token(
            client_id="mcp-client",
            scopes=["user"],
            jti=jti,
            expires_in=3600,
        )

        result1 = await provider.load_access_token(fastmcp_token)
        result2 = await provider.load_access_token(fastmcp_token)

    assert result1 is None
    assert result2 is None
    assert calls == 4  # revoked credentials are never cached


async def test_provider_trusted_grant_does_not_widen_required_scopes():
    async def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/user":
            return _user_response(request)
        return httpx2.Response(503, request=request)

    storage = MemoryStore()
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        provider = GitHubProvider(
            client_id="client-id",
            client_secret="client-secret",
            base_url="https://mcp.example.com",
            required_scopes=["repo"],
            jwt_signing_key="test-signing-key",
            client_storage=storage,
            http_client=client,
        )

        upstream_token_id = "trusted-upstream-token"
        jti = "fastmcp-access-jti"
        await provider._upstream_token_store.put(
            key=upstream_token_id,
            value=UpstreamTokenSet(
                upstream_token_id=upstream_token_id,
                access_token="github-access-token",
                refresh_token=None,
                refresh_token_expires_at=None,
                expires_at=time.time() + 3600,
                token_type="Bearer",
                scope="user",
                client_id="mcp-client",
                created_at=time.time(),
            ),
            ttl=3600,
        )
        await provider._jti_mapping_store.put(
            key=jti,
            value=JTIMapping(
                jti=jti,
                upstream_token_id=upstream_token_id,
                created_at=time.time(),
            ),
            ttl=3600,
        )
        fastmcp_token = provider.jwt_issuer.issue_access_token(
            client_id="mcp-client",
            scopes=["user"],
            jti=jti,
            expires_in=3600,
        )

        result = await provider.load_access_token(fastmcp_token)

    assert result is None


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
        with patch.object(
            OAuthProxy, "load_access_token", swallowing_load_access_token
        ):
            with pytest.raises(httpx2.HTTPStatusError) as exc_info:
                await provider.load_access_token("fastmcp-token")

    assert exc_info.value.response.status_code == 503
