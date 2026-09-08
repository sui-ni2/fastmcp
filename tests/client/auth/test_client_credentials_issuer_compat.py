"""Compatibility tests for MCP 2.2+ client-credentials issuer binding."""

import inspect
import warnings

import httpx2
import pytest
from mcp.client.auth.extensions.client_credentials import (
    ClientCredentialsOAuthProvider as SDKClientCredentialsOAuthProvider,
)
from mcp.client.auth.extensions.client_credentials import (
    PrivateKeyJWTOAuthProvider as SDKPrivateKeyJWTOAuthProvider,
)
from mcp.shared.exceptions import MCPDeprecationWarning

from fastmcp.client.auth import (
    ClientCredentialsOAuthProvider,
    PrivateKeyJWTOAuthProvider,
)

SERVER_URL = "https://mcp.example.com/mcp"
AUTH_SERVER_URL = "https://auth.example.com"

CLIENT_CREDENTIALS_SUPPORTS_ISSUER = (
    "issuer"
    in inspect.signature(SDKClientCredentialsOAuthProvider.__init__).parameters
)
PRIVATE_KEY_JWT_SUPPORTS_ISSUER = (
    "issuer" in inspect.signature(SDKPrivateKeyJWTOAuthProvider.__init__).parameters
)


@pytest.mark.skipif(
    not CLIENT_CREDENTIALS_SUPPORTS_ISSUER,
    reason="issuer was added by MCP 2.2",
)
def test_client_credentials_forwards_issuer_without_warning():
    with warnings.catch_warnings():
        warnings.simplefilter("error", MCPDeprecationWarning)
        provider = ClientCredentialsOAuthProvider(
            SERVER_URL,
            client_id="cid",
            client_secret="secret",
            issuer=AUTH_SERVER_URL,
        )

    assert provider._issuer == AUTH_SERVER_URL


@pytest.mark.skipif(
    not PRIVATE_KEY_JWT_SUPPORTS_ISSUER,
    reason="issuer was added by MCP 2.2",
)
def test_private_key_jwt_forwards_issuer_without_warning():
    async def assertion_provider(audience: str) -> str:
        return audience

    with warnings.catch_warnings():
        warnings.simplefilter("error", MCPDeprecationWarning)
        provider = PrivateKeyJWTOAuthProvider(
            SERVER_URL,
            client_id="cid",
            assertion_provider=assertion_provider,
            issuer=AUTH_SERVER_URL,
        )

    assert provider._issuer == AUTH_SERVER_URL


@pytest.mark.skipif(
    not CLIENT_CREDENTIALS_SUPPORTS_ISSUER,
    reason="issuer warning was added by MCP 2.2",
)
async def test_missing_issuer_warning_is_deferred_until_auth_use():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", MCPDeprecationWarning)
        provider = ClientCredentialsOAuthProvider(
            SERVER_URL,
            client_id="cid",
            client_secret="secret",
        )

    assert not any(issubclass(item.category, MCPDeprecationWarning) for item in caught)

    with pytest.warns(MCPDeprecationWarning, match="Omitting `issuer` is deprecated"):
        flow = provider.async_auth_flow(httpx2.Request("POST", SERVER_URL))
    await flow.aclose()


def test_explicit_issuer_fails_closed_on_pre_2_2_sdk():
    if CLIENT_CREDENTIALS_SUPPORTS_ISSUER:
        pytest.skip("pre-2.2 compatibility path only")

    with pytest.raises(RuntimeError, match="requires mcp>=2.2.0"):
        ClientCredentialsOAuthProvider(
            SERVER_URL,
            client_id="cid",
            client_secret="secret",
            issuer=AUTH_SERVER_URL,
        )
