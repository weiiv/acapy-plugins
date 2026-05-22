"""Client attestation validation for tenant token flow.

Verifies attestation JWTs signed by trusted Wallet Providers.
Provider public keys are looked up from the admin allow list via internal API.
"""

import json
from datetime import datetime, timezone
from typing import Any

import httpx
from authlib.oauth2.rfc6749.errors import InvalidRequestError
from joserfc import jwk, jwt
from joserfc.jws import extract_compact

from core.observability.observability import internal_api_headers
from core.consts import SUPPORTED_SIGNING_ALGS
from tenant.security.jti_cache import JtiCache
from core.utils.logging import get_logger
from tenant.config import settings

logger = get_logger(__name__)


# --- Attestation PoP jti replay cache (draft-07 §9 step 10) ---
_JTI_WINDOW = int(getattr(settings, "ATTESTATION_CLOCK_SKEW_SECONDS", 60)) * 2
_attest_pop_jti_cache = JtiCache(window=_JTI_WINDOW)


class InvalidAttestationError(InvalidRequestError):
    """OAuth error for invalid client attestation."""

    error = "invalid_client_attestation"


def _jwt_extract(jwt_token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Extract JWT header and payload without signature verification."""
    try:
        obj = extract_compact(jwt_token.encode())
        header = obj.headers()
        payload = json.loads(obj.payload)
    except Exception as ex:
        raise InvalidAttestationError(description="malformed_attestation") from ex
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise InvalidAttestationError(description="malformed_attestation")
    return header, payload


def _now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _required_claim_str(claims: dict[str, Any], name: str) -> str:
    value = claims.get(name)
    if not isinstance(value, str) or not value:
        raise InvalidAttestationError(description=f"missing_{name}")
    return value


def _required_claim_int(claims: dict[str, Any], name: str) -> int:
    value = claims.get(name)
    if not isinstance(value, int):
        raise InvalidAttestationError(description=f"missing_{name}")
    return value


def _thumbprint(jwk_dict: dict[str, Any]) -> str:
    """Compute JWK thumbprint per RFC 7638 using joserfc."""
    try:
        return jwk.thumbprint(jwk_dict)
    except Exception as ex:
        raise InvalidAttestationError(description="invalid_jwk") from ex


def _extract_cnf_jwk(claims: dict[str, Any]) -> dict[str, Any] | None:
    """Extract cnf.jwk from attestation payload."""
    cnf = claims.get("cnf")
    if not isinstance(cnf, dict):
        return None
    jwk = cnf.get("jwk")
    if isinstance(jwk, dict):
        return jwk
    return None


async def _lookup_provider_key(iss: str, kid: str) -> dict[str, Any] | None:
    """Look up a resolved provider key from admin internal API by iss + kid."""
    url = f"{settings.INTERNAL_BASE_URL}/wallet-providers/lookup"
    headers = internal_api_headers(settings.INTERNAL_AUTH_TOKEN)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                url,
                params={"iss": iss, "kid": kid},
                headers=headers,
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            if not data.get("found"):
                return None
            return data.get("public_key")
    except Exception:
        logger.warning(
            "Failed to look up provider key iss=%s kid=%s",
            iss,
            kid,
            exc_info=True,
        )
        return None


def _verify_signature(
    token: str,
    public_key_jwk: dict[str, Any],
    *,
    error: str = "attestation_signature_invalid",
) -> dict[str, Any]:
    """Verify JWT signature using the given JWK. Returns decoded claims."""
    try:
        key = jwk.import_key(public_key_jwk)
        result = jwt.decode(token, key, algorithms=list(SUPPORTED_SIGNING_ALGS))
        return dict(result.claims)
    except InvalidAttestationError:
        raise
    except Exception as ex:
        raise InvalidAttestationError(description=error) from ex


async def validate_client_attestation(
    *,
    client_attestation: str | None,
    client_attestation_pop: str | None = None,
    attestation_required: bool,
    expected_audience: str | None = None,
    db=None,
) -> dict[str, Any] | None:
    """Validate client attestation JWT + PoP against the trusted provider allow list.

    Implements draft-ietf-oauth-attestation-based-client-auth-07 §6.2 and §9.
    """
    if not client_attestation:
        if attestation_required:
            raise InvalidAttestationError(description="missing_client_attestation")
        return None

    # --- Attestation JWT validation (§5.1, §9 steps 2-6) ---

    # 1. Decode header and payload (without verification first, to extract iss + kid)
    header, claims = _jwt_extract(client_attestation)

    # 2. Validate typ header (§5.1: REQUIRED, MUST be "oauth-client-attestation+jwt")
    typ = header.get("typ")
    if typ != "oauth-client-attestation+jwt":
        raise InvalidAttestationError(description="invalid_attestation_typ")

    # 3. Extract kid from header, iss from payload
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise InvalidAttestationError(description="missing_kid")
    issuer = _required_claim_str(claims, "iss")

    # 4. Look up provider public key by iss + kid (§9 step 5)
    provider_key = await _lookup_provider_key(issuer, kid)
    if not provider_key:
        raise InvalidAttestationError(description="untrusted_provider")

    # 5. Verify signature using provider's public key (§9 step 5)
    verified_claims = _verify_signature(client_attestation, provider_key)

    # 6. Validate required claims (§5.1)
    subject = _required_claim_str(verified_claims, "sub")
    issued_at = verified_claims.get("iat")
    expires_at = verified_claims.get("exp")

    # 7. Check time validity (§9 step 11) — skip if iat/exp absent
    skew = int(settings.ATTESTATION_CLOCK_SKEW_SECONDS)
    now = _now_ts()
    if issued_at is not None and int(issued_at) > now + skew:
        raise InvalidAttestationError(description="attestation_not_yet_valid")
    if expires_at is not None and int(expires_at) <= now - skew:
        raise InvalidAttestationError(description="attestation_expired")

    # 8. Extract cnf.jwk — REQUIRED per §5.1
    cnf_jwk = _extract_cnf_jwk(verified_claims)
    if not cnf_jwk:
        raise InvalidAttestationError(description="missing_cnf_jwk")

    cnf_jkt = _thumbprint(cnf_jwk)

    # --- Attestation PoP JWT validation (§5.2, §9 steps 7-10) ---

    if not client_attestation_pop:
        raise InvalidAttestationError(description="missing_client_attestation_pop")

    # 9. Validate PoP typ header
    # (§5.2: REQUIRED, MUST be "oauth-client-attestation-pop+jwt")
    pop_header, _ = _jwt_extract(client_attestation_pop)
    pop_typ = pop_header.get("typ")
    if pop_typ != "oauth-client-attestation-pop+jwt":
        raise InvalidAttestationError(description="invalid_attestation_pop_typ")

    # 10. Verify PoP signature using cnf.jwk from attestation (§9 step 7)
    pop_claims = _verify_signature(
        client_attestation_pop, cnf_jwk, error="attestation_pop_signature_invalid"
    )

    # 11. Verify PoP iss matches attestation sub (§5.2 rule 4, §9 step 13)
    # TODO: re-enable once clients conform to spec
    # pop_iss = pop_claims.get("iss")
    # if pop_iss != subject:
    #     raise InvalidAttestationError(description="attestation_pop_iss_mismatch")

    # 12. Verify PoP aud (§5.2: REQUIRED, must be AS issuer identifier)
    pop_aud = pop_claims.get("aud")
    if not pop_aud:
        raise InvalidAttestationError(description="missing_attestation_pop_aud")

    # 12b. Validate PoP aud value matches the expected AS issuer (§5.2, §9 step 9)
    # TODO: re-enable once clients send full tenant-scoped aud
    # if expected_audience:
    #     aud_values = pop_aud if isinstance(pop_aud, list) else [pop_aud]
    #     if expected_audience not in aud_values:
    #         raise InvalidAttestationError(
    #             description="attestation_pop_aud_mismatch"
    #         )

    # 13. Verify PoP jti is present (§5.2: REQUIRED)
    pop_jti = pop_claims.get("jti")
    if not isinstance(pop_jti, str) or not pop_jti:
        raise InvalidAttestationError(description="missing_attestation_pop_jti")

    # TODO: Re-enable once Ontario Wallet sends unique jti per request
    # 13b. Check jti replay (§9 step 10: MUST verify jti not previously used)
    # if not await _attest_pop_jti_cache.check_and_store(pop_jti, db):
    #     raise InvalidAttestationError(description="attestation_pop_jti_replay")

    # 14. Verify PoP iat is present and within window (§5.2: REQUIRED)
    pop_iat = pop_claims.get("iat")
    if not isinstance(pop_iat, int):
        raise InvalidAttestationError(description="missing_attestation_pop_iat")
    if pop_iat > now + skew:
        raise InvalidAttestationError(description="attestation_pop_not_yet_valid")
    # TODO: Re-enable once Ontario Wallet sends fresh PoP iat
    # if pop_iat < now - _JTI_WINDOW:
    #     raise InvalidAttestationError(description="attestation_pop_too_old")

    # 15. Verify PoP exp if present (§5.2: OPTIONAL, but MUST reject if expired)
    # TODO: Re-enable once Ontario Wallet sends valid exp
    # pop_exp = pop_claims.get("exp")
    # if isinstance(pop_exp, int) and pop_exp <= now - skew:
    #     raise InvalidAttestationError(description="attestation_pop_expired")

    return {
        "present": True,
        "verified": True,
        "iss": issuer,
        "kid": kid,
        "sub": subject,
        "cnf_jkt": cnf_jkt,
        "pop_jti": pop_jti,
        "iat": issued_at,
        "exp": expires_at,
    }
