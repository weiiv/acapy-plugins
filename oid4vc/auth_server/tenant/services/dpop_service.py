"""DPoP proof validation service for the tenant token endpoint.

Wraps authlib's DPoPProofValidator to provide a clean async interface
for the FastAPI token flow. Returns the JWK thumbprint (jkt) on success
or raises an OAuth2 error.
"""

from authlib.jose import JoseError, JsonWebKey, jwt
from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from authlib.oauth2.rfc9449 import DPoPProofValidator
from authlib.oauth2.rfc9449.errors import InvalidDPopProofError, UseDPoPNonceError
from authlib.oauth2.rfc9449.validator import normalize_url

from tenant.config import settings
from tenant.security.dpop import HmacDPoPNonceGenerator


class _FixedDPoPProofValidator(DPoPProofValidator):
    """Override validate_proof to fix two authlib bugs.

    1. Header lookup is case-sensitive ("DPoP") but Starlette lowercases headers.
    2. jwt.decode(proof, None) crashes because JWS can't resolve a None key.
    """

    def validate_proof(
        self, request: OAuth2Request, access_token: str = None, for_resource: bool = False
    ) -> str:
        # Use lowercase key since Starlette normalizes headers
        proof = request.headers.get("dpop")
        if not proof:
            raise InvalidDPopProofError(
                "DPoP proof required", algs=self.algs, for_resource=for_resource
            )

        # Validation 1
        if len(proof.split(",")) > 1:
            raise InvalidDPopProofError(
                "DPoP header must contain a single proof",
                algs=self.algs,
                for_resource=for_resource,
            )

        uri = normalize_url(request.uri)

        claims_options = {
            "jti": {"essential": True},
            "iat": {"essential": True},
            "htm": {"essential": True, "value": request.method},
            "htu": {"essential": True, "value": uri},
        }

        if access_token:
            ath = create_s256_code_challenge(access_token)
            claims_options["ath"] = {"essential": True, "value": ath}

        # Extract the embedded JWK from the proof header for signature verification
        import base64
        import json

        try:
            hdr_seg = proof.split(".")[0]
            hdr_seg += "=" * (-len(hdr_seg) % 4)
            unverified_header = json.loads(base64.urlsafe_b64decode(hdr_seg))
        except Exception:
            raise InvalidDPopProofError(
                description="DPoP malformed proof",
                algs=self.algs,
                for_resource=for_resource,
            )

        if "jwk" not in unverified_header:
            raise InvalidDPopProofError(
                description="DPoP missing 'jwk' header",
                algs=self.algs,
                for_resource=for_resource,
            )

        key = JsonWebKey.import_key(unverified_header["jwk"])
        self.validate_header(unverified_header, for_resource=for_resource)

        # Validation 7
        if not key.public_only:
            raise InvalidDPopProofError(
                "DPoP 'jwk' not a public key", algs=self.algs, for_resource=for_resource
            )

        # Now decode and verify signature with the extracted key
        try:
            claims_options.update(self.claims_options)
            claims = jwt.decode(
                proof, key.get_public_key(), claims_options=claims_options
            )
            claims.validate(leeway=30)
        except JoseError as error:
            raise InvalidDPopProofError(
                description=f"DPoP {error.description.lower()}",
                algs=self.algs,
                for_resource=for_resource,
            )

        # Validation 10 — nonce
        if self.nonce_generator:
            if "nonce" not in claims:
                raise UseDPoPNonceError(
                    self.nonce_generator.next(), for_resource=for_resource
                )
            elif not self.nonce_generator.check(claims["nonce"]):
                raise UseDPoPNonceError(
                    self.nonce_generator.next(),
                    description="DPoP invalid claim 'nonce'",
                    for_resource=for_resource,
                )

        return key.thumbprint()


# Module-level singleton — initialized lazily on first use
_validator: _FixedDPoPProofValidator | None = None


def _get_validator() -> _FixedDPoPProofValidator:
    global _validator
    if _validator is None:
        nonce_gen = None
        if settings.DPOP_NONCE_SECRET:
            nonce_gen = HmacDPoPNonceGenerator(
                secret=settings.DPOP_NONCE_SECRET,
                interval=settings.DPOP_NONCE_INTERVAL,
            )
        _validator = _FixedDPoPProofValidator(
            nonce_generator=nonce_gen,
            algs=["ES256", "ES384"],
        )
    return _validator


def validate_dpop_proof(
    oauth2_request: OAuth2Request,
    *,
    access_token: str | None = None,
) -> str:
    """Validate DPoP proof and return the JWK thumbprint (jkt).

    Raises:
        InvalidDPopProofError: proof is malformed or invalid
        UseDPoPNonceError: nonce is missing or stale (includes fresh nonce in error)
    """
    validator = _get_validator()
    return validator.validate_proof(
        oauth2_request,
        access_token=access_token,
    )


def get_dpop_nonce() -> str | None:
    """Return a fresh DPoP nonce for response headers, or None if nonce not configured."""
    if not settings.DPOP_NONCE_SECRET:
        return None
    validator = _get_validator()
    if validator.nonce_generator:
        return validator.nonce_generator.next()
    return None
