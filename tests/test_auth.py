"""Tests for JWT authentication module."""

import json
import os
import time
from typing import Any, Callable, Dict
from unittest import mock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt import PyJWKClientError
from mcp.server.auth.provider import AccessToken

from imap_mcp.auth import (
    OIDCJWTVerifier,
    _extract_scopes,
    discover_jwks_uri,
)

# --- Fixtures ---


@pytest.fixture
def rsa_keypair() -> tuple[bytes, RSAPublicKey]:
    """Generate an RSA key pair for test JWT signing/verification."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return private_pem, public_key


@pytest.fixture
def valid_jwt_claims() -> Dict[str, Any]:
    """Standard valid JWT claims."""
    return {
        "iss": "https://auth.example.com/application/o/test-app/",
        "sub": "user-uuid-123",
        "azp": "test-client-id",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        "scope": "openid email profile",
    }


@pytest.fixture
def make_signed_jwt(rsa_keypair: tuple[bytes, RSAPublicKey], valid_jwt_claims: Dict[str, Any]) -> Callable[..., str]:
    """Factory fixture to create signed JWTs."""
    private_pem, _ = rsa_keypair

    def _make(
        claims_override: Dict[str, Any] | None = None, kid: str = "test-key-1"
    ) -> str:
        claims = {**valid_jwt_claims, **(claims_override or {})}
        return jwt.encode(
            claims,
            private_pem,
            algorithm="RS256",
            headers={"kid": kid},
        )

    return _make


# --- Tests for _extract_scopes ---


class TestExtractScopes:
    """Tests for scope extraction from JWT claims."""

    def test_space_delimited_string(self) -> None:
        """Test standard OAuth 2.0 space-delimited scope string."""
        assert _extract_scopes({"scope": "openid email profile"}) == [
            "openid",
            "email",
            "profile",
        ]

    def test_list_format(self) -> None:
        """Test list-formatted scope claim."""
        assert _extract_scopes({"scope": ["openid", "email"]}) == [
            "openid",
            "email",
        ]

    def test_empty_string(self) -> None:
        """Test empty scope string."""
        assert _extract_scopes({"scope": ""}) == []

    def test_missing_scope(self) -> None:
        """Test missing scope claim."""
        assert _extract_scopes({"sub": "user"}) == []

    def test_single_scope(self) -> None:
        """Test single scope."""
        assert _extract_scopes({"scope": "openid"}) == ["openid"]


# --- Tests for OIDCJWTVerifier ---


class TestOIDCJWTVerifier:
    """Tests for OIDC JWT verification."""

    ISSUER = "https://auth.example.com/application/o/test-app/"
    JWKS_URI = "https://auth.example.com/application/o/test-app/jwks/"

    @pytest.mark.asyncio
    async def test_valid_jwt(self, rsa_keypair: tuple[bytes, RSAPublicKey], make_signed_jwt: Callable[..., str]) -> None:
        """Test successful JWT validation returns AccessToken."""
        _, public_key = rsa_keypair
        token = make_signed_jwt()

        verifier = OIDCJWTVerifier(issuer=self.ISSUER, jwks_uri=self.JWKS_URI)

        with mock.patch.object(
            verifier._key_manager, "get_signing_key", return_value=public_key
        ):
            result = await verifier.verify_token(token)

        assert result is not None
        assert isinstance(result, AccessToken)
        assert result.client_id == "test-client-id"
        assert result.scopes == ["openid", "email", "profile"]
        assert result.token == token
        assert result.expires_at is not None

    @pytest.mark.asyncio
    async def test_expired_jwt(self, rsa_keypair: tuple[bytes, RSAPublicKey], make_signed_jwt: Callable[..., str]) -> None:
        """Test that expired JWT returns None."""
        _, public_key = rsa_keypair
        token = make_signed_jwt({"exp": int(time.time()) - 100})

        verifier = OIDCJWTVerifier(issuer=self.ISSUER, jwks_uri=self.JWKS_URI)

        with mock.patch.object(
            verifier._key_manager, "get_signing_key", return_value=public_key
        ):
            result = await verifier.verify_token(token)

        assert result is None

    @pytest.mark.asyncio
    async def test_wrong_issuer(self, rsa_keypair: tuple[bytes, RSAPublicKey], make_signed_jwt: Callable[..., str]) -> None:
        """Test that JWT with wrong issuer returns None."""
        _, public_key = rsa_keypair
        token = make_signed_jwt({"iss": "https://evil.example.com/"})

        verifier = OIDCJWTVerifier(issuer=self.ISSUER, jwks_uri=self.JWKS_URI)

        with mock.patch.object(
            verifier._key_manager, "get_signing_key", return_value=public_key
        ):
            result = await verifier.verify_token(token)

        assert result is None

    @pytest.mark.asyncio
    async def test_audience_validation_pass(self, rsa_keypair: tuple[bytes, RSAPublicKey], make_signed_jwt: Callable[..., str]) -> None:
        """Test that JWT with correct audience passes validation."""
        _, public_key = rsa_keypair
        token = make_signed_jwt({"aud": "my-mcp-server"})

        verifier = OIDCJWTVerifier(
            issuer=self.ISSUER, jwks_uri=self.JWKS_URI, audience="my-mcp-server"
        )

        with mock.patch.object(
            verifier._key_manager, "get_signing_key", return_value=public_key
        ):
            result = await verifier.verify_token(token)

        assert result is not None

    @pytest.mark.asyncio
    async def test_audience_validation_fail(self, rsa_keypair: tuple[bytes, RSAPublicKey], make_signed_jwt: Callable[..., str]) -> None:
        """Test that JWT with wrong audience returns None."""
        _, public_key = rsa_keypair
        token = make_signed_jwt({"aud": "wrong-audience"})

        verifier = OIDCJWTVerifier(
            issuer=self.ISSUER, jwks_uri=self.JWKS_URI, audience="my-mcp-server"
        )

        with mock.patch.object(
            verifier._key_manager, "get_signing_key", return_value=public_key
        ):
            result = await verifier.verify_token(token)

        assert result is None

    @pytest.mark.asyncio
    async def test_no_audience_validation_when_not_configured(
        self, rsa_keypair: tuple[bytes, RSAPublicKey], make_signed_jwt: Callable[..., str]
    ) -> None:
        """Test that audience is not checked when not configured."""
        _, public_key = rsa_keypair
        token = make_signed_jwt()

        verifier = OIDCJWTVerifier(
            issuer=self.ISSUER, jwks_uri=self.JWKS_URI, audience=None
        )

        with mock.patch.object(
            verifier._key_manager, "get_signing_key", return_value=public_key
        ):
            result = await verifier.verify_token(token)

        assert result is not None

    @pytest.mark.asyncio
    async def test_malformed_jwt(self) -> None:
        """Test that malformed JWT returns None."""
        verifier = OIDCJWTVerifier(issuer=self.ISSUER, jwks_uri=self.JWKS_URI)

        with mock.patch.object(
            verifier._key_manager,
            "get_signing_key",
            side_effect=jwt.DecodeError("Not a JWT"),
        ):
            result = await verifier.verify_token("not.a.jwt")

        assert result is None

    @pytest.mark.asyncio
    async def test_jwks_fetch_failure(self) -> None:
        """Test that JWKS fetch failure returns None."""
        verifier = OIDCJWTVerifier(issuer=self.ISSUER, jwks_uri=self.JWKS_URI)

        with mock.patch.object(
            verifier._key_manager,
            "get_signing_key",
            side_effect=PyJWKClientError("Connection refused"),
        ):
            result = await verifier.verify_token("some.jwt.token")

        assert result is None

    @pytest.mark.asyncio
    async def test_client_id_from_azp(self, rsa_keypair: tuple[bytes, RSAPublicKey], make_signed_jwt: Callable[..., str]) -> None:
        """Test that client_id is extracted from 'azp' claim."""
        _, public_key = rsa_keypair
        token = make_signed_jwt({"azp": "my-client-id"})

        verifier = OIDCJWTVerifier(issuer=self.ISSUER, jwks_uri=self.JWKS_URI)

        with mock.patch.object(
            verifier._key_manager, "get_signing_key", return_value=public_key
        ):
            result = await verifier.verify_token(token)

        assert result is not None
        assert result.client_id == "my-client-id"

    @pytest.mark.asyncio
    async def test_client_id_fallback(self, rsa_keypair: tuple[bytes, RSAPublicKey], make_signed_jwt: Callable[..., str]) -> None:
        """Test client_id falls back to 'client_id' claim when 'azp' is absent."""
        _, public_key = rsa_keypair
        token = make_signed_jwt({"azp": None, "client_id": "fallback-client"})

        verifier = OIDCJWTVerifier(issuer=self.ISSUER, jwks_uri=self.JWKS_URI)

        with mock.patch.object(
            verifier._key_manager, "get_signing_key", return_value=public_key
        ):
            result = await verifier.verify_token(token)

        assert result is not None
        assert result.client_id == "fallback-client"


# --- Tests for discover_jwks_uri ---


class TestDiscoverJWKSUri:
    """Tests for OIDC discovery of JWKS URI."""

    def test_successful_discovery(self) -> None:
        """Test successful OIDC discovery returns jwks_uri."""
        discovery_response = json.dumps(
            {
                "issuer": "https://auth.example.com/application/o/test/",
                "jwks_uri": "https://auth.example.com/application/o/test/jwks/",
            }
        ).encode()

        with mock.patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = mock.MagicMock()
            mock_response.read.return_value = discovery_response
            mock_response.__enter__ = mock.MagicMock(return_value=mock_response)
            mock_response.__exit__ = mock.MagicMock(return_value=False)
            mock_urlopen.return_value = mock_response

            result = discover_jwks_uri(
                "https://auth.example.com/application/o/test/"
            )

        assert result == "https://auth.example.com/application/o/test/jwks/"

    def test_discovery_failure_raises_error(self) -> None:
        """Test that discovery failure raises ValueError."""
        with mock.patch(
            "urllib.request.urlopen", side_effect=Exception("Connection refused")
        ):
            with pytest.raises(ValueError, match="OIDC discovery failed"):
                discover_jwks_uri(
                    "https://auth.example.com/application/o/test/"
                )

    def test_discovery_missing_jwks_uri_raises_error(self) -> None:
        """Test that missing jwks_uri in discovery document raises ValueError."""
        discovery_response = json.dumps(
            {"issuer": "https://auth.example.com/application/o/test/"}
        ).encode()

        with mock.patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = mock.MagicMock()
            mock_response.read.return_value = discovery_response
            mock_response.__enter__ = mock.MagicMock(return_value=mock_response)
            mock_response.__exit__ = mock.MagicMock(return_value=False)
            mock_urlopen.return_value = mock_response

            with pytest.raises(ValueError, match="does not contain 'jwks_uri'"):
                discover_jwks_uri(
                    "https://auth.example.com/application/o/test/"
                )

    def test_trailing_slash_handling(self) -> None:
        """Test that trailing slash is handled correctly in discovery URL."""
        discovery_response = json.dumps(
            {"jwks_uri": "https://auth.example.com/jwks/"}
        ).encode()

        with mock.patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = mock.MagicMock()
            mock_response.read.return_value = discovery_response
            mock_response.__enter__ = mock.MagicMock(return_value=mock_response)
            mock_response.__exit__ = mock.MagicMock(return_value=False)
            mock_urlopen.return_value = mock_response

            discover_jwks_uri("https://auth.example.com/application/o/test/")

        call_url = mock_urlopen.call_args[0][0]
        assert call_url.endswith("/.well-known/openid-configuration")
        # No double slashes (except https://)
        path_part = call_url.replace("https://", "")
        assert "//" not in path_part


# --- Tests for issuer URL validation ---


class TestIssuerURLValidation:
    """Tests for OIDC issuer URL HTTPS validation."""

    def test_discover_jwks_uri_rejects_http(self) -> None:
        """Test that discover_jwks_uri rejects plain HTTP issuer URLs."""
        with pytest.raises(ValueError, match="HTTPS"):
            discover_jwks_uri("http://auth.example.com/")

    def test_verifier_rejects_http_issuer(self) -> None:
        """Test that OIDCJWTVerifier rejects plain HTTP issuer URLs."""
        with pytest.raises(ValueError, match="HTTPS"):
            OIDCJWTVerifier(
                issuer="http://auth.example.com/",
                jwks_uri="https://auth.example.com/jwks/",
            )

    def test_http_allowed_with_env_var(self) -> None:
        """Test that HTTP is allowed when OIDC_ALLOW_HTTP=true is set."""
        discovery_response = json.dumps(
            {
                "issuer": "http://localhost:8080/",
                "jwks_uri": "http://localhost:8080/jwks/",
            }
        ).encode()

        with mock.patch.dict(os.environ, {"OIDC_ALLOW_HTTP": "true"}):
            with mock.patch("urllib.request.urlopen") as mock_urlopen:
                mock_response = mock.MagicMock()
                mock_response.read.return_value = discovery_response
                mock_response.__enter__ = mock.MagicMock(
                    return_value=mock_response
                )
                mock_response.__exit__ = mock.MagicMock(return_value=False)
                mock_urlopen.return_value = mock_response

                result = discover_jwks_uri("http://localhost:8080/")

        assert result == "http://localhost:8080/jwks/"

    def test_discover_jwks_uri_rejects_non_url(self) -> None:
        """Test that discover_jwks_uri rejects non-URL strings."""
        with pytest.raises(ValueError, match="valid HTTP\\(S\\) URL"):
            discover_jwks_uri("not-a-url")

    def test_verifier_accepts_https(self) -> None:
        """Test that OIDCJWTVerifier accepts HTTPS issuer URLs."""
        verifier = OIDCJWTVerifier(
            issuer="https://auth.example.com/",
            jwks_uri="https://auth.example.com/jwks/",
        )
        assert verifier._issuer == "https://auth.example.com/"
