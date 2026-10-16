"""Token endpoint for OID4VCI."""

import base64
import datetime
import hashlib
import hmac
import json
import time
from datetime import UTC
from secrets import token_urlsafe
from typing import Any, Dict
from urllib.parse import urlparse

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.wallet.base import WalletError
from acapy_agent.wallet.error import WalletNotFoundError
from acapy_agent.wallet.jwt import b64_to_dict
from acapy_agent.wallet.util import b64_to_bytes
from aiohttp import web
from aiohttp_apispec import docs, form_schema
from aries_askar import Key
from marshmallow import fields, pre_load

from oid4vc.did_utils import retrieve_or_create_did_jwk
from oid4vc.jwt import (
    JWTVerifyResult,
    jwt_sign,
    jwt_verify,
    key_from_x5c,
    key_material_for_kid,
)

from ..app_resources import AppResources
from ..config import Config
from ..models.exchange import OID4VCIExchangeRecord
from ..models.nonce import Nonce
from ..pop_result import PopResult
from ..utils import (
    get_auth_header,
    get_auth_server_url,
    get_first_auth_server,
    get_tenant_subpath,
)
from .constants import (
    EXPIRES_IN,
    LOGGER,
    NONCE_BYTES,
    PRE_AUTHORIZED_CODE_GRANT_TYPE,
)


class GetTokenSchema(OpenAPISchema):
    """Schema for the token endpoint.

    Accept both 'pre-authorized_code' (OID4VCI v1.0) and legacy
    'pre_authorized_code' (underscore) for compatibility by normalizing input.
    """

    grant_type = fields.Str(required=True, metadata={"description": "", "example": ""})

    pre_authorized_code = fields.Str(
        data_key="pre-authorized_code",
        required=True,
        metadata={"description": "", "example": ""},
    )
    user_pin = fields.Str(required=False)

    @pre_load
    def normalize_fields(self, data, **_kwargs):
        """Normalize legacy field names to OID4VCI v1.0 keys.

        Accept 'pre_authorized_code' by mapping it to 'pre-authorized_code'.
        """
        # webargs may pass a MultiDictProxy; make a writable copy first
        try:
            mutable = dict(data)
        except (TypeError, ValueError):
            mutable = data
        # Map legacy underscore field to the hyphenated v1.0 key if needed
        if "pre_authorized_code" in mutable and "pre-authorized_code" not in mutable:
            mutable["pre-authorized_code"] = mutable.get("pre_authorized_code")
        return mutable


@docs(tags=["oid4vci"], summary="Get credential issuance token")
@form_schema(GetTokenSchema())
async def token(request: web.Request):
    """Token endpoint to exchange pre-authorized codes for access tokens.

    OID4VCI v1.0: This step MUST NOT require DID or verification method.
    """
    context: AdminRequestContext = request["context"]
    async with context.profile.session() as session:
        auth_server = await get_first_auth_server(session, context.profile)
    if auth_server:
        # The wallet should never reach this endpoint when an external auth server
        # is configured — it should obtain a token directly from the auth server's
        # token_endpoint advertised in the AS well-known metadata.  Return an
        # explicit error rather than silently proxying.
        raise web.HTTPBadRequest(
            reason="Token endpoint not available: use the authorization server"
        )
    form = await request.post()
    LOGGER.debug("Token request form: %s", dict(form))

    if (form.get("grant_type")) != PRE_AUTHORIZED_CODE_GRANT_TYPE:
        return web.json_response(
            {
                "error": "unsupported_grant_type",
                "error_description": "grant_type not supported",
            },
            status=400,
        )

    # Accept both hyphenated and underscored keys
    pre_authorized_code = form.get("pre-authorized_code") or form.get(
        "pre_authorized_code"
    )
    if not pre_authorized_code or not isinstance(pre_authorized_code, str):
        return web.json_response(
            {
                "error": "invalid_request",
                "error_description": "pre-authorized_code is missing or invalid",
            },
            status=400,
        )

    # Accept both legacy user_pin and OID4VCI 1.0 final tx_code in token requests.
    user_pin = form.get("tx_code") or form.get("user_pin")
    try:
        async with context.profile.session() as session:
            record = await OID4VCIExchangeRecord.retrieve_by_code(
                session, pre_authorized_code
            )
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        return web.json_response(
            {"error": "invalid_grant", "error_description": err.roll_up}, status=400
        )

    if record.pin is not None:
        if user_pin is None:
            return web.json_response(
                {
                    "error": "invalid_request",
                    "error_description": "user_pin is required",
                },
                status=400,
            )
        if not hmac.compare_digest(user_pin, record.pin):
            return web.json_response(
                {"error": "invalid_grant", "error_description": "pin is invalid"},
                status=400,
            )

    # Check if pre-authorized code has already been used
    if record.token is not None:
        return web.json_response(
            {
                "error": "invalid_grant",
                "error_description": "pre-authorized code has already been used",
            },
            status=400,
        )

    payload = {
        "sub": record.refresh_id,
        "exp": int(time.time()) + EXPIRES_IN,
    }

    # v1 compliance: do not require DID/verification method at token step.
    # Sign with a default did:jwk under this wallet to produce a JWT access token.
    async with context.profile.session() as session:
        try:
            jwk_info = await retrieve_or_create_did_jwk(session)
            vm = f"{jwk_info.did}#0"
            token_jwt = await jwt_sign(
                context.profile,
                headers={"kid": vm, "typ": "JWT"},
                payload=payload,
                verification_method=vm,
            )
        except (WalletNotFoundError, WalletError, ValueError) as err:
            return web.json_response(
                {
                    "error": "server_error",
                    "error_description": f"Unable to sign access token: {str(err)}",
                },
                status=500,
            )

        record.token = token_jwt
        await record.save(
            session,
            reason="Created new token",
        )

    # Nonce handling per OID4VCI 1.0:
    #   - enable_nonce_endpoint=True: do NOT generate or return a c_nonce here.
    #     The wallet obtains a fresh nonce per credential request from POST
    #     /nonce (spec §7), which is redeemed during PoP validation.
    #   - enable_nonce_endpoint=False: no Nonce Endpoint is published, so we
    #     fall back to the legacy flow — return c_nonce in the token response
    #     and store it on the exchange record for later comparison.
    config = Config.from_settings(context.settings)
    response: Dict[str, Any] = {
        "access_token": record.token,
        "token_type": "Bearer",
        "expires_in": EXPIRES_IN,
    }
    if not config.enable_nonce_endpoint:
        c_nonce_value = token_urlsafe(NONCE_BYTES)
        async with context.profile.session() as session:
            record.nonce = c_nonce_value
            await record.save(session, reason="Stored c_nonce for PoP validation")
        response["c_nonce"] = c_nonce_value
        response["c_nonce_expires_in"] = EXPIRES_IN

    return web.json_response(response)


async def check_token(
    context: AdminRequestContext,
    bearer: str | None = None,
    *,
    request: web.Request,
) -> JWTVerifyResult:
    """Validate the OID4VCI token.

    Accepts both ``Bearer`` and ``DPoP`` Authorization schemes. A token bound to a
    DPoP key (``cnf.jkt``) must use the ``DPoP`` scheme with a valid DPoP proof
    (RFC 9449 §7).
    """
    if not bearer:
        raise web.HTTPUnauthorized()
    try:
        scheme, cred = bearer.split(" ", 1)
    except ValueError:
        raise web.HTTPUnauthorized() from None
    if scheme.lower() not in ("bearer", "dpop"):
        raise web.HTTPUnauthorized()

    config = Config.from_settings(context.settings)
    profile = context.profile

    async with profile.session() as session:
        auth_server = await get_first_auth_server(session, profile)

    if auth_server:
        private_url = get_auth_server_url(auth_server)
        subpath = get_tenant_subpath(profile, tenant_prefix="/tenant")
        issuer_server_url = f"{config.endpoint}{subpath}"
        introspect_endpoint = f"{private_url}/introspect"
        auth_header = await get_auth_header(
            profile, auth_server, issuer_server_url, introspect_endpoint
        )
        resp = await AppResources.get_http_client().post(
            introspect_endpoint,
            data={"token": cred},
            headers={"Authorization": auth_header},
        )
        introspect = await resp.json()
        if not introspect.get("active"):
            raise web.HTTPUnauthorized(reason="invalid_token")
        result = JWTVerifyResult(headers={}, payload=introspect, verified=True)
    else:
        result = await jwt_verify(context.profile, cred)
        if not result.verified:
            raise web.HTTPUnauthorized(
                text='{"error": "invalid_token", '
                '"error_description": "Token verification failed"}',
                headers={"Content-Type": "application/json"},
            )

        if result.payload["exp"] < datetime.datetime.now(UTC).timestamp():
            raise web.HTTPUnauthorized(
                text='{"error": "invalid_token", "error_description": "Token expired"}',
                headers={"Content-Type": "application/json"},
            )

    cnf = result.payload.get("cnf")
    bound_jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
    if bound_jkt:
        if scheme.lower() != "dpop":
            # RFC 9449 §7.2: a DPoP-bound token MUST NOT be accepted as a bearer token.
            raise _dpop_unauthorized("invalid_token", "DPoP-bound token sent as Bearer")
        _verify_dpop_proof(request, cred, bound_jkt, config.endpoint)

    return result


_DPOP_ALGS = ("ES256", "ES384", "ES512")
_DPOP_PROOF_MAX_AGE = 60
_DPOP_IAT_LEEWAY = 30


def _dpop_unauthorized(error: str, description: str) -> web.HTTPUnauthorized:
    """Build a 401 with a DPoP challenge (RFC 9449 §7.1)."""
    algs = " ".join(_DPOP_ALGS)
    return web.HTTPUnauthorized(
        text=json.dumps({"error": error, "error_description": description}),
        headers={
            "Content-Type": "application/json",
            "WWW-Authenticate": (
                f'DPoP error="{error}", error_description="{description}", algs="{algs}"'
            ),
        },
    )


def _verify_dpop_proof(
    request: web.Request, access_token: str, bound_jkt: str, public_url: str
) -> None:
    """Check the DPoP proof per RFC 9449 §4.3 and its binding to the token."""
    proofs = request.headers.getall("DPoP", [])
    if len(proofs) != 1 or "," in proofs[0]:
        raise _dpop_unauthorized("invalid_dpop_proof", "expected a single DPoP proof")
    try:
        enc_header, enc_payload, enc_sig = proofs[0].split(".")
        header = b64_to_dict(enc_header)
        claims = b64_to_dict(enc_payload)
        signature = b64_to_bytes(enc_sig, urlsafe=True)
    except Exception:
        raise _dpop_unauthorized("invalid_dpop_proof", "malformed DPoP proof") from None

    if header.get("typ") != "dpop+jwt":
        raise _dpop_unauthorized("invalid_dpop_proof", "typ must be dpop+jwt")
    alg = header.get("alg")
    if alg not in _DPOP_ALGS:
        raise _dpop_unauthorized("invalid_dpop_proof", "unsupported alg")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict) or "d" in jwk:
        raise _dpop_unauthorized("invalid_dpop_proof", "jwk must be a public key")
    try:
        key = Key.from_jwk(jwk)
        valid = key.verify_signature(
            f"{enc_header}.{enc_payload}".encode(), signature, sig_type=alg
        )
    except Exception:
        valid = False
    if not valid:
        raise _dpop_unauthorized("invalid_dpop_proof", "invalid signature")

    if not claims.get("jti"):
        raise _dpop_unauthorized("invalid_dpop_proof", "missing jti")
    if claims.get("htm") != request.method:
        raise _dpop_unauthorized("invalid_dpop_proof", "htm mismatch")
    # The proof may name either the advertised public URL or the URL as received.
    expected_htu = {
        f"{public_url}{request.path}",
        str(request.url.with_query(None).with_fragment(None)),
    }
    if claims.get("htu") not in expected_htu:
        raise _dpop_unauthorized("invalid_dpop_proof", "htu mismatch")
    iat = claims.get("iat")
    now = time.time()
    if (
        not isinstance(iat, (int, float))
        or iat > now + _DPOP_IAT_LEEWAY
        or iat < now - _DPOP_PROOF_MAX_AGE
    ):
        raise _dpop_unauthorized("invalid_dpop_proof", "iat outside acceptable window")
    ath = (
        base64.urlsafe_b64encode(hashlib.sha256(access_token.encode("ascii")).digest())
        .rstrip(b"=")
        .decode()
    )
    if claims.get("ath") != ath:
        raise _dpop_unauthorized("invalid_dpop_proof", "ath mismatch")

    if key.get_jwk_thumbprint() != bound_jkt:
        raise _dpop_unauthorized("invalid_token", "Invalid DPoP key binding")


async def handle_proof_of_posession(
    profile: Profile, proof: Dict[str, Any], c_nonce: str | None = None
):
    """Validate the proof of possession JWT in a Credential Request.

    Nonce validation strategy depends on ``config.enable_nonce_endpoint``:
      - True: nonce is redeemed via the local DB (``Nonce.redeem_by_value``).
        The ``c_nonce`` argument is ignored — when the Nonce Endpoint is
        published, the issuer is the sole authority on nonce lifecycle, and
        any c_nonce that may have been carried in an external AS's token
        response is irrelevant.
      - False: nonce is validated by direct comparison against ``c_nonce``,
        which the caller obtains from the token introspect payload (external
        AS) or the exchange record (built-in token endpoint).
    """
    encoded_headers, encoded_payload, encoded_signature = proof["jwt"].split(".", 3)
    headers = b64_to_dict(encoded_headers)

    # OID4VCI 1.0 requires typ="openid4vci-proof+jwt"
    # But accept common draft spec values for backward compatibility
    typ = headers.get("typ")
    valid_typ_values = ["openid4vci-proof+jwt", "JWT", "jwt", "openid4vci-jwt"]
    if typ and typ not in valid_typ_values:
        LOGGER.warning("Proof JWT has unexpected typ header: %s", typ)
        raise web.HTTPBadRequest(
            text=json.dumps(
                {
                    "error": "invalid_proof",
                    "error_description": f"unsupported typ: {typ}",
                }
            ),
            content_type="application/json",
        )

    if "jwk" in headers:
        # Prefer inline JWK over kid-based DID resolution (OID4VCI spec §7.2.1).
        # Wallets such as walt.id send both kid and jwk in the proof header;
        # resolving the kid as a DID URL fails when the key is not registered in
        # a resolvable DID document, causing a spurious "invalid kid in proof".
        key = Key.from_jwk(headers["jwk"])
    elif "kid" in headers:
        try:
            key = await key_material_for_kid(profile, headers["kid"])
        except ValueError as exc:
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_proof",
                        "error_description": "invalid kid in proof",
                    }
                ),
                content_type="application/json",
            ) from exc
    elif "x5c" in headers:
        # OID4VCI 1.0: wallet may use x5c (certificate-based) key binding.
        # Extract the public key from the leaf cert for signature verification.
        try:
            key = key_from_x5c(headers["x5c"])
        except Exception as exc:
            LOGGER.debug("Failed to extract key from x5c cert chain: %s", exc)
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_proof",
                        "error_description": "invalid x5c certificate in proof header",
                    }
                ),
                content_type="application/json",
            ) from exc
    else:
        # No key material in the header. Some draft-era wallets (e.g. walt.id)
        # omit jwk/kid/x5c from the proof header and instead put the DID in the
        # payload `iss` claim. Decode the payload first and attempt resolution.
        payload_for_iss = b64_to_dict(encoded_payload)
        iss = payload_for_iss.get("iss")
        if iss:
            # key_material_for_kid expects a DID URL (with fragment), not a bare
            # DID.  For did:jwk and did:key the first verification method is #0.
            kid_url = iss if "#" in iss else f"{iss}#0"
            try:
                key = await key_material_for_kid(profile, kid_url)
                LOGGER.debug("Resolved proof key from payload iss: %s", iss)
            except (ValueError, Exception) as exc:
                LOGGER.debug("Could not resolve key from iss '%s': %s", iss, exc)
                raise web.HTTPBadRequest(
                    text=json.dumps(
                        {
                            "error": "invalid_proof",
                            "error_description": "no key material in proof header and"
                            " iss could not be resolved",
                        }
                    ),
                    content_type="application/json",
                ) from exc
        else:
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_proof",
                        "error_description": "no key material in proof header",
                    }
                ),
                content_type="application/json",
            )

    payload = b64_to_dict(encoded_payload)

    # OID4VCI 1.0 § 7.2.2: the proof JWT MUST contain an `aud` claim equal to
    # the Credential Issuer Identifier (the issuer's base URL).  Omitting this
    # check allows proof replay across issuers.
    aud = payload.get("aud")
    if aud is not None:
        issuer_endpoint = Config.from_settings(profile.settings).endpoint
        # aud may be a string or a list of strings (per RFC 7519 § 4.1.3)
        aud_values = [aud] if isinstance(aud, str) else list(aud)

        def _strip_default_port(url: str) -> str:
            """Remove explicit default ports (https:443, http:80) for comparison."""
            try:
                p = urlparse(url)
                if (p.scheme == "https" and p.port == 443) or (
                    p.scheme == "http" and p.port == 80
                ):
                    netloc = p.hostname or ""
                    return p._replace(netloc=netloc).geturl()
            except Exception:
                pass
            return url

        norm_endpoint = _strip_default_port(issuer_endpoint) if issuer_endpoint else ""
        if issuer_endpoint and not any(
            _strip_default_port(av) == norm_endpoint
            or _strip_default_port(av).startswith(norm_endpoint + "/tenant/")
            for av in aud_values
        ):
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_proof",
                        "error_description": (
                            f"proof JWT aud '{aud}' does not match "
                            f"issuer endpoint '{issuer_endpoint}'"
                        ),
                    }
                ),
                content_type="application/json",
            )

    # OID4VCI 1.0 final spec uses "nonce"; older draft wallets may use "c_nonce".
    nonce = payload.get("nonce") or payload.get("c_nonce")

    config = Config.from_settings(profile.settings)
    if config.enable_nonce_endpoint:
        # The /nonce endpoint is published — nonces are managed locally in the DB.
        # Use DB-based redemption regardless of any c_nonce from the access token.
        async with profile.session() as session:
            redeemed = await Nonce.redeem_by_value(session, nonce)
        if not redeemed:
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_nonce",
                        "error_description": "invalid or already-used nonce",
                    }
                ),
                content_type="application/json",
            )
    else:
        # No local nonce endpoint — rely on c_nonce from the access token.
        if not c_nonce:
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_nonce",
                        "error_description": "no c_nonce available to verify proof",
                    }
                ),
                content_type="application/json",
            )
        if c_nonce != nonce:
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_nonce",
                        "error_description": "nonce mismatch",
                    }
                ),
                content_type="application/json",
            )

    decoded_signature = b64_to_bytes(encoded_signature, urlsafe=True)
    verified = key.verify_signature(
        f"{encoded_headers}.{encoded_payload}".encode(),
        decoded_signature,
        sig_type=headers.get("alg", ""),
    )

    # If the wallet sent a kid-based proof (no jwk in header), derive the public
    # JWK from the resolved key so credential processors that need the raw JWK
    # (e.g. mso_mdoc for holder key binding in DeviceKey) can access it.
    holder_jwk = headers.get("jwk")
    if holder_jwk is None and (
        "kid" in headers or not any(k in headers for k in ("jwk", "kid", "x5c"))
    ):
        try:
            holder_jwk = json.loads(key.get_jwk_public())
        except Exception:
            LOGGER.debug("Could not derive holder JWK from resolved key")

    return PopResult(
        headers,
        payload,
        verified,
        holder_kid=headers.get("kid"),
        holder_jwk=holder_jwk,
        holder_x5c=headers.get("x5c"),
    )
