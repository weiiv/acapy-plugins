"""mso_mdoc credential processor.

Glues together the signing-key resolution, payload preparation, and isomdl
binding layers to implement ISO/IEC 18013-5:2021 compliant mDoc issuance and
verification inside the OID4VCI plugin framework.
"""

import base64
import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.key_type import P256
from acapy_agent.wallet.keys.manager import multikey_to_verkey

from oid4vc.cred_processor import CredProcessorError, CredVerifier, Issuer, PresVerifier
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.presentation import OID4VPPresentation
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult
from x509_certs import (
    X509Error,
    X509TrustAnchorRecord,
    embedded_x5c,
    pem_chain,
    select_certificate,
)

from .mdoc.issuer import MDL_MANDATORY_FIELDS, isomdl_mdoc_sign, make_wallet_signer
from .mdoc.cred_verifier import MsoMdocCredVerifier
from .mdoc.pres_verifier import MsoMdocPresVerifier
from .payload import normalize_mdoc_result, prepare_mdoc_payload

__all__ = ["MsoMdocCredProcessor"]

LOGGER = logging.getLogger(__name__)


async def _get_trust_anchors(profile: Profile) -> List[str]:
    """PEMs of the x509 trust anchors with purpose ``iaca``."""
    async with profile.session() as session:
        records = await X509TrustAnchorRecord.query(session, {"purpose": "iaca"})
    return [record.certificate_pem for record in records]


class MsoMdocCredProcessor(Issuer, CredVerifier, PresVerifier):
    """Credential processor class for mso_mdoc credential format."""

    # COSE algorithm name → integer identifier mapping (RFC 8152 / IANA COSE registry)
    _COSE_ALG: dict = {"ES256": -7, "ES384": -35, "ES512": -36, "ES256K": -47}

    def credential_metadata(self, supported_cred: dict) -> dict:
        """Shape issuer metadata for mso_mdoc format.

        Lifts ``doctype`` from ``format_data`` to the top level, converts the
        namespace-keyed claims dict to the spec-compliant flat array, moves
        ``display`` into ``credential_metadata``, and converts COSE algorithm
        string names to integer identifiers per OID4VCI 1.0 / ISO 18013-5.
        """
        format_data = supported_cred.pop("format_data", None) or {}
        supported_cred.pop("vc_additional_data", None)  # trust anchors etc. are internal

        doctype = format_data.get("doctype")
        claims = format_data.get("claims")

        # Convert COSE algorithm string names to integer identifiers
        # (e.g. "ES256" → -7).  Numeric strings ("-7") are already converted
        # by to_issuer_metadata(); this handles name-form values like "ES256".
        algs = supported_cred.get("credential_signing_alg_values_supported")
        if algs:
            supported_cred["credential_signing_alg_values_supported"] = [
                self._COSE_ALG.get(a, a) if isinstance(a, str) else a for a in algs
            ]

        # Convert namespace-keyed claims dict to flat path-array per OID4VCI spec
        if isinstance(claims, dict):
            claims_list = []
            for namespace, claim_map in claims.items():
                if isinstance(claim_map, dict):
                    for claim_name, descriptor in claim_map.items():
                        entry: dict = {"path": [namespace, claim_name]}
                        if isinstance(descriptor, dict):
                            if "mandatory" in descriptor:
                                entry["mandatory"] = descriptor["mandatory"]
                            if "display" in descriptor:
                                entry["display"] = descriptor["display"]
                        claims_list.append(entry)
            claims = claims_list

        if claims:
            cred_meta = supported_cred.setdefault("credential_metadata", {})
            cred_meta["claims"] = claims

        # Move top-level display into credential_metadata per OID4VCI 1.0 §12.2.4
        display = supported_cred.pop("display", None)
        if display is not None:
            cred_meta = supported_cred.setdefault("credential_metadata", {})
            cred_meta["display"] = display

        if doctype:
            return {"doctype": doctype, **supported_cred}
        return supported_cred

    def __init__(self):
        """Initialize the processor."""

    def _validate_and_get_doctype(
        self, body: Dict[str, Any], supported: SupportedCredential
    ) -> str:
        """Validate and extract doctype from request and configuration.

        Validates the document type identifier according to ISO 18013-5 § 8.3.2.1.2.1
        requirements and OpenID4VCI 1.0 § E.1.1 specification.

        Args:
            body: Request body containing credential issuance parameters
            supported: Supported credential configuration with format data

        Returns:
            Validated doctype string (e.g., "org.iso.18013.5.1.mDL")

        Raises:
            CredProcessorError: If doctype validation fails with detailed context
        """
        doctype_from_request = body.get("doctype")
        doctype_from_config = (
            supported.format_data.get("doctype") if supported.format_data else None
        )

        if not doctype_from_request and not doctype_from_config:
            raise CredProcessorError(
                "Document type (doctype) is required for mso_mdoc format. "
                "Provide doctype in request body or credential configuration. "
                "See OpenID4VCI 1.0 § E.1.1 and ISO 18013-5 § 8.3.2.1.2.1"
            )

        # Use doctype from request if provided, otherwise from configuration
        doctype = doctype_from_request or doctype_from_config

        if doctype_from_request and doctype_from_config:
            if doctype_from_request != doctype_from_config:
                raise CredProcessorError(
                    f"Document type mismatch: request contains '{doctype_from_request}' "
                    f"but credential configuration specifies '{doctype_from_config}'. "
                    "Ensure consistency between request and credential configuration."
                )

        # Validate doctype format (basic ISO format check)
        if not doctype or not isinstance(doctype, str):
            raise CredProcessorError(
                "Invalid doctype format: expected non-empty string, "
                f"got {type(doctype).__name__}"
            )

        if not doctype.startswith("org.iso."):
            LOGGER.warning(
                "Document type '%s' does not follow ISO format convention (org.iso.*)",
                doctype,
            )

        return doctype

    def _extract_device_key(self, pop: PopResult) -> Optional[str]:
        """Extract the holder's device key from the proof of possession.

        Extracts and validates the device key for holder binding according to
        ISO 18013-5 § 9.1.3.4 device authentication requirements and
        OpenID4VCI proof of possession mechanisms.

        Args:
            pop: Proof of possession result containing holder key information

        Returns:
            Serialized device key string (JWK JSON or key identifier),
            or None if unavailable

        Raises:
            CredProcessorError: If device key format is invalid or unsupported
        """
        device_candidate = pop.holder_jwk or pop.holder_kid

        if isinstance(device_candidate, dict):
            # The device key embedded in the mDoc MSO must contain ONLY public
            # parameters; passing 'd' to the Rust isomdl library would leak
            # the holder's private key into the issued credential.
            _PUBLIC_JWK_FIELDS = frozenset(("kty", "crv", "x", "y", "n", "e"))
            public_only = {
                k: v for k, v in device_candidate.items() if k in _PUBLIC_JWK_FIELDS
            }
            return json.dumps(public_only)
        elif isinstance(device_candidate, str):
            # If a DID with fragment, prefer fragment (key id); otherwise raw string
            m = re.match(r"did:(.+?):(.+?)(?:#(.*))?$", device_candidate)
            if m:
                method = m.group(1)
                identifier = m.group(2)
                fragment = m.group(3)

                if method == "jwk":
                    # did:jwk encodes the holder's public JWK as a base64url
                    # value in the DID identifier itself (i.e. between
                    # "did:jwk:" and "#0").  ACA-Py uses this method natively
                    # when a wallet generates ephemeral keys.
                    #
                    # Without special handling the generic DID regex returns
                    # only the fragment "0", and json.loads("0") silently
                    # produces the integer 0 — which the Rust isomdl library
                    # then receives as the holder key, causing an opaque
                    # failure with no hint that the root cause is a
                    # mis-parsed DID method.
                    try:
                        # Base64url may be missing padding — add it back.
                        padding = "=" * (-len(identifier) % 4)
                        jwk_bytes = base64.urlsafe_b64decode(identifier + padding)
                        return jwk_bytes.decode("utf-8")
                    except Exception as exc:
                        raise CredProcessorError(
                            f"Invalid did:jwk identifier — could not decode "
                            f"embedded JWK from '{device_candidate}': {exc}"
                        ) from exc

                return fragment if fragment else device_candidate
            else:
                return device_candidate

        return None

    def _build_headers(
        self, doctype: str, device_key_str: Optional[str]
    ) -> Dict[str, Any]:
        """Build mso_mdoc headers according to OID4VCI specification."""
        headers = {"doctype": doctype}
        if device_key_str:
            headers["deviceKey"] = device_key_str
        return headers

    async def _signing_verkey(self, wallet: BaseWallet, multikey: Optional[str]) -> str:
        """Verkey of the exchange's P-256 signing key."""
        if not multikey:
            raise CredProcessorError("mso_mdoc requires signing_multikey on the exchange")
        verkey = multikey_to_verkey(multikey)
        if (await wallet.get_signing_key(verkey)).key_type != P256:
            raise CredProcessorError("mso_mdoc requires a P-256 signing key")
        return verkey

    async def _assign_status_entry(
        self,
        context: AdminRequestContext,
        supported: SupportedCredential,
        doctype: str,
    ) -> Optional[Dict[str, Any]]:
        """Optionally assign a Token Status List entry for the credential.

        If ``status_list_def_id`` and ``status_list_base_uri`` are set in the
        ``SupportedCredential.vc_additional_data``, this method attempts to
        assign an entry from the status_list plugin and returns the status
        claim dict to embed in the payload.

        Returns ``None`` if the status list plugin is not installed or not
        configured for this credential type.
        """
        additional = supported.vc_additional_data or {}
        definition_id = additional.get("status_list_def_id")
        base_uri = (additional.get("status_list_base_uri") or "").rstrip("/")

        if not definition_id or not base_uri:
            return None

        try:
            from status_list.status_list.v1_0 import (  # noqa: PLC0415
                status_handler as _status_handler,
            )
        except ImportError:
            LOGGER.debug(
                "status_list plugin not installed; skipping revocation entry assignment"
            )
            return None

        try:
            entry = await _status_handler.assign_status_list_entry(context, definition_id)
        except Exception as exc:
            LOGGER.warning(
                "Failed to assign status list entry for definition %s: %s",
                definition_id,
                exc,
            )
            return None

        if entry is None:
            LOGGER.warning(
                "Status list entry assignment returned None for definition %s",
                definition_id,
            )
            return None

        list_number = entry.get("list_number", "")
        list_index = entry.get("list_index", 0)
        status_uri = f"{base_uri}/{list_number}"

        LOGGER.info(
            "Assigned status list entry: doctype=%s list_number=%s index=%d uri=%s",
            doctype,
            list_number,
            list_index,
            status_uri,
        )

        return {"status_list": {"idx": list_index, "uri": status_uri}}

    async def issue(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
    ):
        """Return signed credential in CBOR format.

        Issues an ISO 18013-5 compliant mDoc credential using the mobile
        security object (MSO) format. The credential is CBOR-encoded and
        follows the issuerSigned structure defined in ISO 18013-5.

        Protocol Compliance:
        - OpenID4VCI 1.0 § 7.3.1: Credential Response for mso_mdoc format
        - OpenID4VCI 1.0 Appendix E.1.1: mso_mdoc Credential format identifier
        - ISO 18013-5 § 8.3: Mobile document structure
        - ISO 18013-5 § 9.1.2: IssuerSigned data structure
        - ISO 18013-5 § 9.1.3: Mobile security object (MSO)
        - RFC 8949: CBOR encoding for binary efficiency
        - RFC 8152: COSE signing for cryptographic protection

        OpenID4VCI 1.0 § E.1.1: mso_mdoc Format
        https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-E.1.1
        """
        if not supported.format_data:
            raise CredProcessorError("Supported credential must have format_data")

        try:
            # Validate and extract doctype
            doctype = self._validate_and_get_doctype(body, supported)

            # Extract device key for holder binding
            device_key_str = self._extract_device_key(pop)

            # Build mso_mdoc headers
            headers = self._build_headers(doctype, device_key_str)

            # Get payload
            payload = prepare_mdoc_payload(ex_record.credential_subject, doctype)

            # Optionally assign a status list entry and embed the status claim
            status_claim = await self._assign_status_entry(context, supported, doctype)
            if status_claim:
                payload["status"] = status_claim

            if not device_key_str and not pop.holder_jwk:
                raise CredProcessorError(
                    "No device key available: provide holder_jwk or holder_kid"
                )

            # Clean up JWK for isomdl (remove extra fields like kid, alg, use)
            # isomdl rejects alg and use fields in the holder JWK
            if pop.holder_jwk and isinstance(pop.holder_jwk, dict):
                if pop.holder_jwk.get("kty") != "EC":
                    raise CredProcessorError(
                        "mso_mdoc requires an EC holder key, "
                        f"got kty={pop.holder_jwk.get('kty')}"
                    )
                holder_jwk_clean = {
                    k: v
                    for k, v in pop.holder_jwk.items()
                    if k in ["kty", "crv", "x", "y"]
                }
            else:
                # Fallback: build a minimal JWK placeholder from device_key_str
                # The Rust library needs a JWK dict for the holder key binding
                holder_jwk_clean = None

            # Issue mDoc using isomdl-uniffi library with ISO 18013-5 compliance
            LOGGER.debug(
                "Issuing mso_mdoc with holder_jwk=%s headers=%s payload_keys=%s",
                holder_jwk_clean,
                headers,
                (list(payload.keys()) if isinstance(payload, dict) else type(payload)),
            )
            # Use cleaned JWK if available, otherwise fall back to
            # the device key extracted from holder_kid.
            # isomdl_mdoc_sign expects a dict-like JWK.
            signing_holder_key = holder_jwk_clean
            if signing_holder_key is None and device_key_str:
                try:
                    signing_holder_key = json.loads(device_key_str)
                except (json.JSONDecodeError, TypeError):
                    # device_key_str is a key-id, not a JWK —
                    # cannot bind holder key without a JWK.
                    raise CredProcessorError(
                        "Holder key identifier provided but a full "
                        "EC JWK is required for mso_mdoc device "
                        "key binding. Provide holder_jwk in the "
                        "proof of possession."
                    )

            if signing_holder_key is None:
                raise CredProcessorError(
                    "Unable to resolve a holder JWK for device key binding."
                )

            multikey = ex_record.signing_multikey
            async with context.profile.session() as session:
                wallet = session.inject(BaseWallet)
                verkey = await self._signing_verkey(wallet, multikey)

                async def certificate_chain_for(valid_until: datetime) -> str:
                    try:
                        record = await select_certificate(
                            session, multikey, "mdoc_ds", valid_until
                        )
                    except X509Error as err:
                        raise CredProcessorError(str(err)) from err
                    return pem_chain(embedded_x5c(record))

                mso_mdoc = await isomdl_mdoc_sign(
                    signing_holder_key,
                    headers,
                    payload,
                    make_wallet_signer(wallet, verkey),
                    certificate_chain_for,
                )

            # Normalize mDoc result handling for robust string/bytes processing
            mso_mdoc = normalize_mdoc_result(mso_mdoc)

            LOGGER.info(
                "Issued mso_mdoc credential with doctype: %s, format: %s",
                doctype,
                supported.format,
            )

        except Exception as ex:
            # Log full exception for debugging before raising a generic error
            LOGGER.exception("mso_mdoc issuance error: %s", ex)
            # Surface the underlying exception text in the CredProcessorError
            raise CredProcessorError(f"Failed to issue mso_mdoc credential: {ex}") from ex

        # issuer_signed_b64() already returns base64url without padding
        # (ISO 18013-5 §8.3 compliant) — exactly what OID4VCI 1.0 §7.3.1 requires.
        LOGGER.debug("mso_mdoc credential: %s", mso_mdoc)

        return mso_mdoc

    def _prepare_payload(
        self, payload: Dict[str, Any], doctype: str = None
    ) -> Dict[str, Any]:
        return prepare_mdoc_payload(payload, doctype)

    def _normalize_mdoc_result(self, result: Any) -> str:
        return normalize_mdoc_result(result)

    def validate_credential_subject(self, supported: SupportedCredential, subject: dict):
        """Validate the credential subject."""
        if not subject:
            raise CredProcessorError("Credential subject cannot be empty")

        if not isinstance(subject, dict):
            raise CredProcessorError("Credential subject must be a dictionary")

        # For mDL doctypes, validate mandatory ISO 18013-5 fields early so
        # that the API caller gets an actionable error at exchange-creation
        # time rather than an opaque FFI error at issuance time.
        doctype = (supported.format_data or {}).get("doctype", "")
        if doctype == "org.iso.18013.5.1.mDL":
            # The subject may be namespace-wrapped or flat.
            claims = subject.get("org.iso.18013.5.1", subject)
            # driving_privileges defaults to [] at issuance time, so
            # exclude it from the early check.
            missing = [
                f
                for f in MDL_MANDATORY_FIELDS
                if f != "driving_privileges" and f not in claims
            ]
            if missing:
                raise CredProcessorError(
                    f"mDL credential_subject is missing mandatory ISO 18013-5 "
                    f"data element(s): {', '.join(missing)}"
                )

        return True

    def validate_supported_credential(self, supported: SupportedCredential):
        """Validate a supported MSO MDOC Credential."""
        if not supported.format_data:
            raise CredProcessorError("format_data is required for mso_mdoc format")

        # Validate doctype presence and format
        self._validate_and_get_doctype({}, supported)

        return True

    async def verify_credential(
        self,
        profile: Profile,
        credential: Any,
    ):
        """Verify an mso_mdoc credential."""
        trust_anchors = await _get_trust_anchors(profile)
        verifier = MsoMdocCredVerifier(trust_anchors=trust_anchors)
        return await verifier.verify_credential(profile, credential)

    async def verify_presentation(
        self,
        profile: Profile,
        presentation: Any,
        presentation_record: "OID4VPPresentation",
    ):
        """Verify an mso_mdoc presentation."""
        trust_anchors = await _get_trust_anchors(profile)
        verifier = MsoMdocPresVerifier(trust_anchors=trust_anchors)
        return await verifier.verify_presentation(
            profile, presentation, presentation_record
        )
