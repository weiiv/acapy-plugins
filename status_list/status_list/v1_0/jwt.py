"""JWT Methods."""

from typing import Any, Dict, List, Mapping, Optional

from acapy_agent.core.profile import Profile
from acapy_agent.resolver.did_resolver import DIDUrl
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.key_type import ED25519, P256
from acapy_agent.wallet.jwt import (
    BaseVerificationKeyStrategy,
    dict_to_b64,
    did_lookup_name,
    nym_to_did,
)
from acapy_agent.wallet.util import bytes_to_b64


async def jwt_sign(
    profile: Profile,
    headers: Dict[str, Any],
    payload: Mapping[str, Any],
    did: Optional[str] = None,
    verification_method: Optional[str] = None,
    *,
    verkey: Optional[str] = None,
    x5c: Optional[List[str]] = None,
) -> str:
    """Create a signed JWT given headers, payload, and a signing key.

    The key is *verkey* when given; otherwise it is resolved from *did* /
    *verification_method*. Only the DID path adds a ``kid`` header; *x5c*
    adds an ``x5c`` header.
    """
    if verkey is None and verification_method is None:
        if did is None:
            raise ValueError("did or verificationMethod required.")

        did = nym_to_did(did)

        verkey_strat = profile.inject(BaseVerificationKeyStrategy)
        verification_method = await verkey_strat.get_verification_method_id_for_did(
            did, profile
        )
        if not verification_method:
            raise ValueError("Could not determine verification method from DID")
    elif verkey is None:
        # We look up keys by did for now
        did = DIDUrl.parse(verification_method).did
        if not did:
            raise ValueError("DID URL must be absolute")

    encoded_payload = dict_to_b64(payload)

    if not headers.get("typ", None):
        headers["typ"] = "JWT"

    if x5c:
        headers = {**headers, "x5c": x5c}
    elif verkey is None:
        headers = {**headers, "kid": verification_method}

    async with profile.session() as session:
        wallet = session.inject(BaseWallet)
        if verkey is None:
            did_info = await wallet.get_local_did(did_lookup_name(did))
            verkey, key_type = did_info.verkey, did_info.key_type
        else:
            key_type = (await wallet.get_signing_key(verkey)).key_type

        if key_type == ED25519:
            headers["alg"] = "EdDSA"
        elif key_type == P256:
            headers["alg"] = "ES256"
        else:
            raise ValueError("Unable to determine JWT signing alg")

        encoded_headers = dict_to_b64(headers)
        sig_bytes = await wallet.sign_message(
            f"{encoded_headers}.{encoded_payload}".encode(), verkey
        )

    sig = bytes_to_b64(sig_bytes, urlsafe=True, pad=False)
    return f"{encoded_headers}.{encoded_payload}.{sig}"
