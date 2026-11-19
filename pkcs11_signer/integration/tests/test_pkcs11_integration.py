"""Black-box integration tests for pkcs11_signer against a real PKCS#11 token.

Only cases the unit suite cannot reach are here: it mocks `pkcs11`, so it
cannot observe a real token, real Askar storage, or ACA-Py's sign dispatch.

`alice` runs the plugin configured against the BouncyHsm container; `bob` runs
the same image with the plugin unconfigured. Nothing here imports the plugin.

    docker compose up --build --exit-code-from tests
"""

import base64
import json
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from . import ALICE, BOB, post

PROVIDER = "bouncyhsm"
P256_MULTIKEY_PREFIX = bytes.fromhex("8024")
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58decode(value: str) -> bytes:
    num = 0
    for char in value:
        num = num * 58 + B58_ALPHABET.index(char)
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(value) - len(value.lstrip("1"))) + raw


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _public_key(multikey: str) -> ec.EllipticCurvePublicKey:
    assert multikey.startswith("z"), multikey
    raw = _b58decode(multikey[1:])
    assert raw.startswith(P256_MULTIKEY_PREFIX), multikey
    return ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), raw[len(P256_MULTIKEY_PREFIX) :]
    )


def _create_key(agent: str = ALICE, provider: str = PROVIDER):
    body = {"alg": "p256", "kid": f"did:example:pkcs11-int#{uuid.uuid4()}"}
    if provider:
        body["provider"] = provider
    return post(agent, "/wallet/keys", json=body)


def _assert_jwt_signed_by(kid: str, multikey: str):
    """Sign through ACA-Py and verify the ES256 signature against `multikey`."""
    resp = post(
        ALICE,
        "/wallet/jwt/sign",
        json={"verificationMethod": kid, "headers": {}, "payload": {"n": kid}},
    )
    assert resp.ok, resp.content
    header, payload, signature = resp.json().split(".")
    assert json.loads(_b64url_decode(header))["alg"] == "ES256"

    sig = _b64url_decode(signature)
    assert len(sig) == 64
    der = encode_dss_signature(
        int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    )
    _public_key(multikey).verify(
        der, f"{header}.{payload}".encode(), ec.ECDSA(hashes.SHA256())
    )


def test_hsm_key_signs_through_wallet_dispatch():
    """Key generated on the token; the JWT signature verifies against it.

    Only the token holds that private key, so a valid signature means dispatch
    reached the HSM and the SEC1/DER codecs match a real PKCS#11 module.
    """
    created = _create_key()
    assert created.status_code == 201, created.content
    key = created.json()
    _assert_jwt_signed_by(key["kid"], key["multikey"])


def test_software_key_still_signs_in_wallet():
    """No provider on the key, so Askar signs."""
    created = _create_key(provider=None)
    assert created.status_code == 201, created.content
    key = created.json()
    _assert_jwt_signed_by(key["kid"], key["multikey"])


def test_unconfigured_agent_rejects_provider():
    """bob loads the plugin without config, so no provider is registered."""
    resp = _create_key(agent=BOB)
    assert resp.status_code == 400, resp.content
    assert PROVIDER in resp.json()["message"]
