"""Integration tests for kmslite against a real BouncyHSM.

Run inside the `integration-test-runner` container (docker compose):

    docker compose -f docker-compose.yml up --build --exit-code-from test-runner

The tests exercise PKCS11Signer end-to-end against BouncyHsm on
`Server=bouncyhsm; Port=8765;` (see docker-compose.yml env).

Prerequisite: a token labelled `kmslite-test` must exist with User PIN `1234`.
The `_ensure_test_token` fixture provisions it via BouncyHsm's REST API if
missing (idempotent).
"""

import asyncio
import os
import uuid

import httpx
import pytest

from acapy_agent.wallet.key_type import P256

from kmslite.v1_0.signers.pkcs11 import PKCS11Signer


PKCS11_LIB = os.environ.get(
    "KMSLITE_PKCS11_LIB",
    "/opt/bouncyhsm-client/native/Linux-x64/BouncyHsm.Pkcs11Lib.so",
)
TOKEN_LABEL = os.environ.get("KMSLITE_TOKEN_LABEL", "kmslite-test")
USER_PIN = os.environ.get("KMSLITE_USER_PIN", "1234")
SO_PIN = os.environ.get("KMSLITE_SO_PIN", "12345678")
BOUNCY_HTTP = os.environ.get("BOUNCY_HSM_HTTP", "http://bouncyhsm:8080")


@pytest.fixture(scope="session", autouse=True)
def ensure_test_token():
    """Create the test token via BouncyHsm REST API if it doesn't exist."""
    with httpx.Client(base_url=BOUNCY_HTTP, timeout=10) as client:
        slots = client.get("/Slot").json()
        found = any(
            (s.get("Token") or {}).get("Label") == TOKEN_LABEL for s in slots
        )
        if not found:
            resp = client.post(
                "/Slot",
                json={
                    "Description": "kmslite integration test token",
                    "Token": {
                        "Label": TOKEN_LABEL,
                        "UserPin": USER_PIN,
                        "SoPin": SO_PIN,
                        "SerialNumber": "kmslite01",
                        "SimulateHwRng": False,
                        "SimulateQualifiedArea": False,
                    },
                },
            )
            resp.raise_for_status()
    yield


@pytest.fixture
def signer() -> PKCS11Signer:
    """Build a real PKCS11Signer talking to BouncyHsm."""
    return PKCS11Signer(
        lib_path=PKCS11_LIB,
        token_label=TOKEN_LABEL,
        pin=USER_PIN,
        pool_size=2,
    )


@pytest.mark.asyncio
async def test_generate_keypair_returns_p256_verkey(signer):
    key_ref = f"kmslite-int-{uuid.uuid4()}"
    verkey = await signer.generate_keypair(key_ref, P256)

    from acapy_agent.wallet.util import b58_to_bytes

    raw = b58_to_bytes(verkey)
    assert len(raw) == 33, "verkey should be base58 of 33-byte SEC1-compressed point"
    assert raw[0] in (0x02, 0x03), "compressed point prefix should be 0x02 or 0x03"


@pytest.mark.asyncio
async def test_sign_and_verify_end_to_end(signer):
    """Full round-trip: HSM signs, cryptography lib verifies with the same pubkey."""
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes

    from kmslite.v1_0.x509 import verkey_to_public_key

    key_ref = f"kmslite-int-sign-{uuid.uuid4()}"
    verkey = await signer.generate_keypair(key_ref, P256)
    pubkey = verkey_to_public_key(verkey, P256)

    payload = b"hello from kmslite integration test"
    raw_sig = await signer.sign(key_ref, payload, P256)

    # Raw r||s from HSM → DER for cryptography.verify().
    assert len(raw_sig) == 64
    r = int.from_bytes(raw_sig[:32], "big")
    s = int.from_bytes(raw_sig[32:], "big")
    der = utils.encode_dss_signature(r, s)

    pubkey.verify(der, payload, ec.ECDSA(hashes.SHA256()))


@pytest.mark.asyncio
async def test_get_public_key_matches_generate(signer):
    key_ref = f"kmslite-int-getpub-{uuid.uuid4()}"
    verkey_created = await signer.generate_keypair(key_ref, P256)
    verkey_reread = await signer.get_public_key(key_ref, P256)
    assert verkey_created == verkey_reread


@pytest.mark.asyncio
async def test_session_pool_handles_concurrent_signs(signer):
    """pool_size=2 must handle overlapping signs without corruption."""
    key_ref = f"kmslite-int-concurrent-{uuid.uuid4()}"
    await signer.generate_keypair(key_ref, P256)

    payloads = [f"msg-{i}".encode() for i in range(8)]
    sigs = await asyncio.gather(
        *(signer.sign(key_ref, p, P256) for p in payloads)
    )
    assert all(len(s) == 64 for s in sigs)
    # Verify each: signatures must round-trip against the same pubkey.
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes

    from kmslite.v1_0.x509 import verkey_to_public_key

    verkey = await signer.get_public_key(key_ref, P256)
    pubkey = verkey_to_public_key(verkey, P256)
    for payload, raw in zip(payloads, sigs):
        r = int.from_bytes(raw[:32], "big")
        s = int.from_bytes(raw[32:], "big")
        pubkey.verify(utils.encode_dss_signature(r, s), payload, ec.ECDSA(hashes.SHA256()))
