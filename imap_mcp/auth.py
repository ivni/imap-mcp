"""JWT authentication for OIDC provider integration.

Validates JWT bearer tokens issued by an external OIDC provider
(Authentik, Keycloak, Auth0, etc.) against JWKS keys, implementing
the MCP SDK's TokenVerifier protocol.
"""

import json
import logging
import os
import urllib.request
from typing import Any, Dict, List, Optional

import jwt
from jwt import PyJWKClient, PyJWKClientError
from mcp.server.auth.provider import AccessToken

logger = logging.getLogger("imap_mcp.auth")


def _validate_issuer_url(issuer_url: str) -> None:
    """Validate that the OIDC issuer URL uses HTTPS.

    Rejects plain HTTP unless OIDC_ALLOW_HTTP=true is set (for local
    development). Also rejects non-URL strings.

    Args:
        issuer_url: The OIDC issuer URL to validate.

    Raises:
        ValueError: If the URL is not HTTPS (and HTTP is not explicitly
            allowed) or if the string is not a valid HTTP(S) URL.
    """
    if issuer_url.startswith("https://"):
        return

    if issuer_url.startswith("http://"):
        allow_http = os.environ.get("OIDC_ALLOW_HTTP", "").lower() == "true"
        if allow_http:
            logger.warning(
                "OIDC issuer URL uses HTTP (not HTTPS): %s — "
                "allowed by OIDC_ALLOW_HTTP=true (development only)",
                issuer_url,
            )
            return
        raise ValueError(
            f"OIDC issuer URL must use HTTPS: {issuer_url}. "
            "Set OIDC_ALLOW_HTTP=true for local development."
        )

    raise ValueError(
        f"OIDC issuer URL must be a valid HTTP(S) URL: {issuer_url}"
    )


class JWKSKeyManager:
    """Manages JWKS key fetching and caching for JWT validation.

    Fetches public keys from an OIDC provider's JWKS endpoint,
    caching them with automatic refresh on key rotation (kid mismatch).

    Attributes:
        jwks_uri: URL of the JWKS endpoint.
    """

    def __init__(self, jwks_uri: str, cache_lifetime: int = 3600) -> None:
        """Initialize the JWKS key manager.

        Args:
            jwks_uri: URL of the JWKS endpoint.
            cache_lifetime: Seconds to cache JWKS keys (default: 3600).
        """
        self._jwks_client = PyJWKClient(
            uri=jwks_uri,
            cache_jwk_set=True,
            lifespan=cache_lifetime,
        )

    def get_signing_key(self, token: str) -> Any:
        """Get the signing key for a given JWT token.

        Extracts the 'kid' from the token header and fetches the
        corresponding key from JWKS. PyJWKClient handles caching
        and automatic refresh on kid miss.

        Args:
            token: The raw JWT string.

        Returns:
            The public key for signature verification.

        Raises:
            PyJWKClientError: If the key cannot be found or fetched.
        """
        signing_key = self._jwks_client.get_signing_key_from_jwt(token)
        return signing_key.key


class OIDCJWTVerifier:
    """Verifies JWT tokens issued by an OIDC provider.

    Implements the MCP SDK's TokenVerifier protocol. Provider-agnostic:
    works with any OIDC provider (Authentik, Keycloak, Auth0, etc.).
    Validates JWT signature (RS256) against JWKS keys, checks issuer,
    expiration, and optionally audience.

    Attributes:
        issuer: Expected JWT issuer URL.
        audience: Expected JWT audience (optional).
    """

    def __init__(
        self,
        issuer: str,
        jwks_uri: str,
        audience: Optional[str] = None,
        jwks_cache_lifetime: int = 3600,
    ) -> None:
        """Initialize the OIDC JWT verifier.

        Args:
            issuer: Expected JWT issuer URL (must match 'iss' claim).
            jwks_uri: URL of the OIDC provider's JWKS endpoint.
            audience: Expected JWT audience ('aud' claim). If None,
                audience validation is skipped.
            jwks_cache_lifetime: Seconds to cache JWKS keys (default: 3600).
        """
        _validate_issuer_url(issuer)
        self._issuer = issuer
        self._audience = audience
        self._key_manager = JWKSKeyManager(jwks_uri, jwks_cache_lifetime)

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify a JWT bearer token from the OIDC provider.

        Validates the JWT signature, issuer, expiration, and optionally
        audience. Returns an AccessToken on success, None on failure.

        Args:
            token: The raw JWT bearer token string.

        Returns:
            AccessToken with claims from the JWT if valid, None otherwise.
        """
        try:
            signing_key = self._key_manager.get_signing_key(token)

            decode_options: Dict[str, bool] = {
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": self._audience is not None,
            }

            decode_kwargs: Dict[str, Any] = {
                "jwt": token,
                "key": signing_key,
                "algorithms": ["RS256"],
                "issuer": self._issuer,
                "options": decode_options,
            }
            if self._audience is not None:
                decode_kwargs["audience"] = self._audience

            claims = jwt.decode(**decode_kwargs)

            client_id = claims.get("azp") or claims.get("client_id", "unknown")
            scopes = _extract_scopes(claims)
            expires_at = claims.get("exp")

            return AccessToken(
                token=token,
                client_id=str(client_id),
                scopes=scopes,
                expires_at=int(expires_at) if expires_at else None,
            )

        except jwt.ExpiredSignatureError:
            logger.warning("JWT token has expired")
            return None
        except jwt.InvalidIssuerError:
            logger.warning("JWT issuer mismatch")
            return None
        except jwt.InvalidAudienceError:
            logger.warning("JWT audience mismatch")
            return None
        except (jwt.InvalidTokenError, PyJWKClientError) as e:
            logger.warning("JWT validation failed: %s", type(e).__name__)
            return None


def _extract_scopes(claims: Dict[str, Any]) -> List[str]:
    """Extract scopes from JWT claims.

    Handles both space-delimited 'scope' string (OAuth 2.0 standard)
    and list-formatted 'scope' claims (some OIDC providers).

    Args:
        claims: Decoded JWT claims dictionary.

    Returns:
        List of scope strings.
    """
    scope_claim = claims.get("scope", "")
    if isinstance(scope_claim, str):
        return scope_claim.split() if scope_claim else []
    if isinstance(scope_claim, list):
        return [str(s) for s in scope_claim]
    return []


def discover_jwks_uri(issuer_url: str) -> str:
    """Discover the JWKS URI from an OIDC issuer's well-known configuration.

    Fetches the OpenID Connect discovery document and extracts the
    jwks_uri field. Raises ValueError if discovery fails.

    Args:
        issuer_url: The OIDC issuer URL.

    Returns:
        The JWKS endpoint URL.

    Raises:
        ValueError: If the URL is not HTTPS, or discovery fails, or
            the document lacks jwks_uri.
    """
    _validate_issuer_url(issuer_url)
    discovery_url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"
    try:
        with urllib.request.urlopen(discovery_url, timeout=10) as response:
            config = json.loads(response.read().decode())
            jwks_uri = config.get("jwks_uri")
            if jwks_uri:
                return str(jwks_uri)
    except Exception as e:
        logger.error("OIDC discovery failed for %s: %s", discovery_url, e)
        raise ValueError(
            f"OIDC discovery failed for {issuer_url}: {e}. "
            "Set OIDC_JWKS_URI environment variable explicitly."
        ) from e

    raise ValueError(
        f"OIDC discovery document at {discovery_url} does not contain 'jwks_uri'. "
        "Set OIDC_JWKS_URI environment variable explicitly."
    )
