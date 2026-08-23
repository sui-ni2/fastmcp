"""Regression baseline for OAuthProxy token round-tripping (#4850)."""

import time

from mcp.server.auth.provider import AuthorizationCode
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl

from fastmcp import settings
from fastmcp.server.auth.oauth_proxy import OAuthProxy
from fastmcp.server.auth.oauth_proxy.models import ClientCode
from tests.server.auth.oauth_proxy.conftest import MockTokenVerifier


def _make_proxy() -> OAuthProxy:
    return OAuthProxy(
        upstream_authorization_endpoint="https://idp.example.com/authorize",
        upstream_token_endpoint="https://idp.example.com/token",
        upstream_client_id="upstream-client",
        upstream_client_secret="upstream-secret",
        token_verifier=MockTokenVerifier(required_scopes=["read"]),
        base_url="https://mcp.example.com/my-service",
        jwt_signing_key="test-signing-key",
    )


async def test_issued_token_is_immediately_accepted_with_default_storage(
    tmp_path, monkeypatch
):
    """A freshly issued wrapper token survives the full default-storage lookup path."""
    monkeypatch.setattr(settings, "home", tmp_path)

    proxy = _make_proxy()
    proxy.set_mcp_path("/mcp")

    client = OAuthClientInformationFull(
        client_id="test-client",
        client_secret="test-client-secret",
        redirect_uris=[AnyUrl("http://localhost:12345/callback")],
    )
    code = ClientCode(
        code="test-auth-code",
        client_id="test-client",
        redirect_uri="http://localhost:12345/callback",
        code_challenge="",
        code_challenge_method="S256",
        scopes=["read"],
        idp_tokens={
            "access_token": "upstream-access-token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": "read",
        },
        expires_at=time.time() + 300,
        created_at=time.time(),
    )
    await proxy._code_store.put(key=code.code, value=code)

    authorization_code = AuthorizationCode(
        code=code.code,
        scopes=["read"],
        expires_at=code.expires_at,
        client_id="test-client",
        code_challenge="",
        redirect_uri=AnyUrl("http://localhost:12345/callback"),
        redirect_uri_provided_explicitly=True,
    )
    issued = await proxy.exchange_authorization_code(
        client=client,
        authorization_code=authorization_code,
    )

    validated = await proxy.load_access_token(issued.access_token)

    assert validated is not None
    assert validated.token == "upstream-access-token"


async def test_issued_token_survives_proxy_reconstruction_with_default_storage(
    tmp_path, monkeypatch
):
    """Default encrypted FileTree storage preserves JTI/upstream records across instances."""
    monkeypatch.setattr(settings, "home", tmp_path)

    first = _make_proxy()
    first.set_mcp_path("/mcp")

    client = OAuthClientInformationFull(
        client_id="test-client",
        client_secret="test-client-secret",
        redirect_uris=[AnyUrl("http://localhost:12345/callback")],
    )
    code = ClientCode(
        code="test-auth-code",
        client_id="test-client",
        redirect_uri="http://localhost:12345/callback",
        code_challenge="",
        code_challenge_method="S256",
        scopes=["read"],
        idp_tokens={
            "access_token": "upstream-access-token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": "read",
        },
        expires_at=time.time() + 300,
        created_at=time.time(),
    )
    await first._code_store.put(key=code.code, value=code)

    authorization_code = AuthorizationCode(
        code=code.code,
        scopes=["read"],
        expires_at=code.expires_at,
        client_id="test-client",
        code_challenge="",
        redirect_uri=AnyUrl("http://localhost:12345/callback"),
        redirect_uri_provided_explicitly=True,
    )
    issued = await first.exchange_authorization_code(
        client=client,
        authorization_code=authorization_code,
    )

    second = _make_proxy()
    second.set_mcp_path("/mcp")
    validated = await second.load_access_token(issued.access_token)

    assert validated is not None
    assert validated.token == "upstream-access-token"
