"""Regression tests for symmetric OIDC token verification."""

import time
from unittest.mock import patch

from joserfc import jwk, jwt
from key_value.aio.stores.memory import MemoryStore
from mcp.server.auth.provider import AuthorizationCode
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl

from fastmcp.server.auth.oauth_proxy.models import ClientCode
from fastmcp.server.auth.oidc_proxy import OIDCConfiguration, OIDCProxy
from fastmcp.server.auth.providers.jwt import JWTVerifier

ISSUER = "https://idp.example.com/application/o/my-app/"
SECRET = "authentik-client-secret"
CONFIG_URL = "https://idp.example.com/application/o/my-app/.well-known/openid-configuration"


def config(algs: list[str]) -> OIDCConfiguration:
    return OIDCConfiguration.model_validate({
        "issuer": ISSUER,
        "authorization_endpoint": "https://idp.example.com/application/o/authorize/",
        "token_endpoint": "https://idp.example.com/application/o/token/",
        "jwks_uri": "https://idp.example.com/application/o/my-app/jwks/",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": algs,
    })


def make_proxy(algs: list[str], algorithm: str | None = None) -> OIDCProxy:
    with patch.object(OIDCConfiguration, "get_oidc_configuration", return_value=config(algs)):
        return OIDCProxy(
            config_url=CONFIG_URL, client_id="my-app", client_secret=SECRET,
            base_url="https://mcp.example.com/my-service", algorithm=algorithm,
            client_storage=MemoryStore(),
        )


async def exchange(proxy: OIDCProxy, upstream_token: str) -> str:
    proxy.set_mcp_path("/mcp")
    client = OAuthClientInformationFull(
        client_id="mcp-client", client_secret="mcp-secret",
        redirect_uris=[AnyUrl("http://localhost/callback")],
    )
    await proxy.register_client(client)
    now = time.time()
    await proxy._code_store.put(
        key="code", ttl=300, value=ClientCode(
            code="code", client_id="mcp-client", redirect_uri="http://localhost/callback",
            code_challenge=None, code_challenge_method="S256", scopes=["read"],
            idp_tokens={"access_token": upstream_token, "expires_in": 3600, "scope": "read", "token_type": "Bearer"},
            expires_at=now + 300, created_at=now,
        ),
    )
    result = await proxy.exchange_authorization_code(
        client, AuthorizationCode(
            code="code", client_id="mcp-client", redirect_uri=AnyUrl("http://localhost/callback"),
            redirect_uri_provided_explicitly=True, scopes=["read"],
            expires_at=now + 300, code_challenge="",
        ),
    )
    return result.access_token


async def test_discovered_hs256_validates_with_client_secret():
    proxy = make_proxy(["HS256"])
    assert isinstance(proxy._token_validator, JWTVerifier)
    assert proxy._token_validator.algorithm == "HS256"
    assert proxy._token_validator.jwks_uri is None
    now = int(time.time())
    upstream = jwt.encode(
        {"alg": "HS256"},
        {"sub": "user-1", "iss": ISSUER, "iat": now, "exp": now + 3600, "scope": "read"},
        jwk.import_key(SECRET, "oct"), algorithms=["HS256"],
    )
    loaded = await proxy.verify_token(await exchange(proxy, upstream))
    assert loaded is not None
    assert loaded.token == upstream


def test_explicit_hs256_uses_client_secret_instead_of_jwks():
    proxy = make_proxy(["RS256", "HS256"], algorithm="HS256")
    assert isinstance(proxy._token_validator, JWTVerifier)
    assert proxy._token_validator.algorithm == "HS256"
    assert proxy._token_validator.jwks_uri is None
