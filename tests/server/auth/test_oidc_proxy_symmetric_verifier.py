"""Regression coverage for symmetric upstream JWT verification in OIDCProxy."""

import time
from unittest.mock import patch

import pytest
from joserfc import jwk as jose_jwk
from joserfc import jwt

from fastmcp.server.auth.oidc_proxy import OIDCConfiguration, OIDCProxy
from fastmcp.server.auth.providers.jwt import JWTVerifier

CONFIG_URL = "https://idp.example.com/.well-known/openid-configuration"
ISSUER = "https://idp.example.com/application/o/test/"
JWKS_URI = "https://idp.example.com/application/o/test/jwks/"
CLIENT_ID = "test-client"
CLIENT_SECRET = "test-client-secret"
AUDIENCE = "test-audience"
BASE_URL = "https://mcp.example.com/service"


def _oidc_configuration() -> OIDCConfiguration:
    return OIDCConfiguration.model_validate(
        {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}authorize/",
            "token_endpoint": f"{ISSUER}token/",
            "jwks_uri": JWKS_URI,
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["HS256"],
        }
    )


def _make_proxy(
    *, algorithm: str, client_secret: str | None = CLIENT_SECRET
) -> OIDCProxy:
    with patch(
        "fastmcp.server.auth.oidc_proxy.OIDCConfiguration.get_oidc_configuration",
        return_value=_oidc_configuration(),
    ):
        return OIDCProxy(
            config_url=CONFIG_URL,
            client_id=CLIENT_ID,
            client_secret=client_secret,
            audience=AUDIENCE,
            algorithm=algorithm,
            required_scopes=["openid"],
            base_url=BASE_URL,
            jwt_signing_key="fastmcp-wrapper-signing-key",
        )


async def test_explicit_hs256_uses_upstream_client_secret_and_verifies_token() -> None:
    """Explicit HS256 must verify with the configured upstream client secret."""
    proxy = _make_proxy(algorithm="HS256")

    verifier = proxy._token_validator
    assert isinstance(verifier, JWTVerifier)
    assert verifier.algorithm == "HS256"
    assert verifier.public_key == CLIENT_SECRET
    assert verifier.jwks_uri is None

    now = int(time.time())
    signing_key = jose_jwk.import_key(CLIENT_SECRET, "oct")
    token = jwt.encode(
        {"alg": "HS256"},
        {
            "sub": "authentik-user",
            "iss": ISSUER,
            "aud": AUDIENCE,
            "scope": "openid profile",
            "iat": now,
            "exp": now + 300,
        },
        signing_key,
        algorithms=["HS256"],
    )

    access_token = await verifier.verify_token(token)

    assert access_token is not None
    assert access_token.client_id == "authentik-user"
    assert access_token.scopes == ["openid", "profile"]


def test_explicit_hs256_without_client_secret_fails_closed() -> None:
    """Never invent a shared key when symmetric verification is requested."""
    with pytest.raises(
        ValueError,
        match=r"Symmetric HS\* token verification requires client_secret",
    ):
        _make_proxy(algorithm="HS256", client_secret=None)


def test_asymmetric_algorithm_keeps_using_discovery_jwks() -> None:
    """The symmetric-key path must not change existing asymmetric verification."""
    proxy = _make_proxy(algorithm="RS256")

    verifier = proxy._token_validator
    assert isinstance(verifier, JWTVerifier)
    assert verifier.algorithm == "RS256"
    assert verifier.public_key is None
    assert verifier.jwks_uri == JWKS_URI
