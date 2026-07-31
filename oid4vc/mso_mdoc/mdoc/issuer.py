"""Operations supporting mso_mdoc issuance using isomdl-uniffi.

This module implements ISO/IEC 18013-5:2021 compliant mobile document issuance
using the isomdl-uniffi Rust library via UniFFI bindings. It provides
cryptographic operations for creating signed mobile documents (mDocs) including
mobile driver's licenses (mDLs).

Protocol Compliance:
- OpenID4VCI 1.0 § E.1.1: mso_mdoc Credential Format
  https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-E.1.1
- ISO/IEC 18013-5:2021 § 8: Mobile document format and structure
- ISO/IEC 18013-5:2021 § 9: Cryptographic mechanisms
- RFC 8152: CBOR Object Signing and Encryption (COSE)
- RFC 8949: Concise Binary Object Representation (CBOR)
- RFC 7517: JSON Web Key (JWK) format for key material

The mso_mdoc format is defined in OpenID4VCI 1.0 Appendix E.1.1 as a specific
credential format that follows the ISO 18013-5 mobile document structure.
"""

import json
import logging
from typing import Any, Awaitable, Callable, Mapping, Optional

from isomdl_uniffi import Mdoc, PreparedMdoc

from .utils import extract_signing_cert

LOGGER = logging.getLogger(__name__)


# ISO 18013-5 mandatory data elements for the org.iso.18013.5.1 namespace.
# These are non-Option fields in the upstream isomdl OrgIso1801351 struct;
# omitting any of them causes a GeneralConstructionError from the Rust FFI.
MDL_MANDATORY_FIELDS = (
    "family_name",
    "given_name",
    "birth_date",
    "issue_date",
    "expiry_date",
    "issuing_country",
    "issuing_authority",
    "document_number",
    "portrait",
    "driving_privileges",
    "un_distinguishing_sign",
)


def _prepare_mdl_namespaces(
    payload: Mapping[str, Any],
) -> tuple[str, Optional[str]]:
    """Prepare mDL namespace items for create_and_sign_mdl.

    Args:
        payload: The credential payload

    Returns:
        Tuple of (mdl_items_json, aamva_items_json) where aamva_items_json
        may be None. Both are JSON-serialized dicts; isomdl-uniffi handles
        CBOR encoding internally.

    Raises:
        ValueError: If any ISO 18013-5 mandatory data element is missing.
    """
    mdl_payload = payload.get("org.iso.18013.5.1", payload)
    mdl_items = {k: v for k, v in mdl_payload.items() if k != "org.iso.18013.5.1.aamva"}

    # isomdl-uniffi's create_and_sign_mdl requires driving_privileges even
    # when none are granted — default to an empty array so callers that omit
    # the field don't hit a GeneralConstructionError.
    mdl_items.setdefault("driving_privileges", [])

    # Validate mandatory fields before calling into the Rust FFI so that
    # callers get a clear error message instead of an opaque
    # GeneralConstructionError.
    missing = [f for f in MDL_MANDATORY_FIELDS if f not in mdl_items]
    if missing:
        raise ValueError(
            f"mDL credential_subject is missing mandatory ISO 18013-5 "
            f"data element(s): {', '.join(missing)}"
        )

    aamva_payload = payload.get("org.iso.18013.5.1.aamva")
    aamva_items_json = json.dumps(aamva_payload) if aamva_payload else None

    return json.dumps(mdl_items), aamva_items_json


def _prepare_generic_namespaces(doctype: str, payload: Mapping[str, Any]) -> dict:
    """Prepare namespaces for generic doctypes.

    Args:
        doctype: The document type
        payload: The credential payload

    Returns:
        Dictionary of namespaces with JSON-encoded element values
        for use with Mdoc.create_and_sign.
    """
    encoded_payload = {k: json.dumps(v) for k, v in payload.items()}
    return {doctype: encoded_payload}


def make_wallet_signer(wallet: Any, verkey: str) -> Callable[[bytes], Awaitable[bytes]]:
    """Wrap a wallet verkey as an async signer for isomdl_mdoc_sign.

    Delegates to BaseWallet.sign_message, which dispatches to the registered
    SignerRegistry backend (HSM via kmslite, or in-wallet software key).
    """

    async def _sign(tbs: bytes) -> bytes:
        return await wallet.sign_message(tbs, verkey)

    return _sign


async def isomdl_mdoc_sign(
    jwk: dict,
    headers: Mapping[str, Any],
    payload: Mapping[str, Any],
    iaca_cert_pem: str,
    signer: Callable[[bytes], Awaitable[bytes]],
    signature_algorithm: str = "ES256",
) -> str:
    """Create a signed mso_mdoc using isomdl-uniffi's two-step PreparedMdoc API.

    The caller supplies an async *signer* callable — any backend that can
    produce raw r‖s bytes over the TBS payload (PEM key, HSM, wallet) works.
    Private key material never needs to cross the FFI boundary.

    Args:
        jwk: Holder device key in JWK format.
        headers: Must include ``doctype``.
        payload: Credential data to sign.
        iaca_cert_pem: Issuer certificate in PEM format (chain or single cert).
        signer: Async callable ``(tbs: bytes) -> bytes`` returning raw r‖s.
        signature_algorithm: COSE algorithm name — ``"ES256"``, ``"ES384"``,
            or ``"ES512"``.  Defaults to ``"ES256"`` (P-256 / ISO 18013-5).

    Returns:
        CBOR-encoded mDoc as base64url string (no padding).
    """
    if not isinstance(headers, dict):
        raise ValueError("missing headers.")

    if not isinstance(payload, dict):
        raise ValueError("missing payload.")

    try:
        doctype = headers.get("doctype")
        holder_jwk = json.dumps(jwk)

        LOGGER.debug("holder_jwk: %s", holder_jwk)
        LOGGER.debug("iaca_cert_pem length: %d", len(iaca_cert_pem))

        # Rust's x509_cert crate reads only the first PEM block in a chain.
        signing_cert_pem = extract_signing_cert(iaca_cert_pem)
        if signing_cert_pem != iaca_cert_pem:
            LOGGER.info(
                "iaca_cert_pem contained a PEM chain; extracted first certificate "
                "(%d bytes) as the signing cert",
                len(signing_cert_pem),
            )

        if doctype == "org.iso.18013.5.1.mDL":
            mdl_items, aamva_items = _prepare_mdl_namespaces(payload)
            LOGGER.info("Creating mDL prepared mdoc via PreparedMdoc.new_mdl")
            prepared = PreparedMdoc.new_mdl(
                mdl_items, aamva_items, holder_jwk, signature_algorithm
            )
        else:
            namespaces = _prepare_generic_namespaces(doctype, payload)
            LOGGER.info("Creating prepared mdoc with namespaces: %s", list(namespaces.keys()))
            prepared = PreparedMdoc(doctype, namespaces, holder_jwk, signature_algorithm)

        tbs = prepared.signature_payload()
        LOGGER.debug("Signing %d-byte TBS payload", len(tbs))
        sig = await signer(tbs)

        mdoc = prepared.complete(signing_cert_pem, sig)
        LOGGER.info("Generated mdoc with doctype: %s", mdoc.doctype())

        return mdoc.issuer_signed_b64()

    except Exception as ex:
        LOGGER.error("Failed to create mdoc with isomdl: %r", ex)
        raise ValueError(f"Failed to create mdoc: {ex!r}") from ex


def parse_mdoc(cbor_data: str) -> Mdoc:
    """Parse a CBOR-encoded mDoc string into an Mdoc object."""
    try:
        return Mdoc.from_string(cbor_data)
    except Exception as ex:
        LOGGER.error("Failed to parse mdoc: %s", ex)
        raise ValueError(f"Failed to parse mdoc: {ex}") from ex
