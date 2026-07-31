"""Tests for x509 helpers (WalletBackedPrivateKey, build_csr, cert-matches-verkey)."""

import asyncio

import pytest
from aries_askar import Key, KeyAlg
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from acapy_agent.wallet.error import WalletError
from acapy_agent.wallet.key_type import ED25519, P256
from acapy_agent.wallet.util import bytes_to_b58

from kmslite.v1_0.x509 import (
    WalletBackedPrivateKey,
    assert_cert_matches_verkey,
    build_csr,
    verkey_to_public_key,
)


# ------------------------------------------------------------------ helpers


def _p256_verkey_and_askar_key():
    """Generate a real P-256 key; return (verkey_base58, askar.Key)."""
    k = Key.generate(KeyAlg.P256)
    return bytes_to_b58(k.get_public_bytes()), k


def _sign_via_askar(askar_key, data: bytes) -> bytes:
    """Sign data with the askar Key; returns raw r||s (matches sign_message)."""
    return askar_key.sign_message(data)


class _WalletDouble:
    """Async wallet double that signs via a captured askar Key."""

    def __init__(self, askar_key):
        self._key = askar_key

    async def sign_message(self, message, from_verkey):
        return _sign_via_askar(self._key, message)


# ------------------------------------------------------------------ verkey_to_public_key


def test_verkey_to_public_key_round_trip():
    verkey, askar_key = _p256_verkey_and_askar_key()
    pub = verkey_to_public_key(verkey, P256)
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    assert pub.curve.name == "secp256r1"


def test_verkey_to_public_key_rejects_unsupported():
    with pytest.raises(WalletError, match="unsupported key_type"):
        verkey_to_public_key("aaaa", ED25519)


# ------------------------------------------------------------------ WalletBackedPrivateKey


def test_adapter_public_key_matches_verkey():
    verkey, askar_key = _p256_verkey_and_askar_key()
    loop = asyncio.new_event_loop()
    try:
        adapter = WalletBackedPrivateKey(
            _WalletDouble(askar_key), verkey, P256, loop=loop
        )
        pub = adapter.public_key()
        expected = verkey_to_public_key(verkey, P256)
        assert pub.public_numbers() == expected.public_numbers()
    finally:
        loop.close()


def test_adapter_curve_is_secp256r1():
    verkey, askar_key = _p256_verkey_and_askar_key()
    loop = asyncio.new_event_loop()
    try:
        adapter = WalletBackedPrivateKey(
            _WalletDouble(askar_key), verkey, P256, loop=loop
        )
        assert isinstance(adapter.curve, ec.SECP256R1)
        assert adapter.key_size == 256
    finally:
        loop.close()


def test_adapter_sign_produces_valid_der_signature():
    """End-to-end: adapter.sign() output verifies against the public key."""
    verkey, askar_key = _p256_verkey_and_askar_key()

    async def _run():
        loop = asyncio.get_running_loop()
        adapter = WalletBackedPrivateKey(
            _WalletDouble(askar_key), verkey, P256, loop=loop
        )
        payload = b"hello"
        # `cryptography` builder .sign() is synchronous; must run off-loop.
        der_sig = await asyncio.to_thread(
            adapter.sign, payload, ec.ECDSA(hashes.SHA256())
        )
        # Decode DER back to (r, s) and verify with the public key.
        r, s = utils.decode_dss_signature(der_sig)
        assert r > 0 and s > 0
        # Verify signature with cryptography.
        pub = verkey_to_public_key(verkey, P256)
        pub.verify(der_sig, payload, ec.ECDSA(hashes.SHA256()))

    asyncio.run(_run())


def test_adapter_private_bytes_raises():
    verkey, askar_key = _p256_verkey_and_askar_key()
    loop = asyncio.new_event_loop()
    try:
        adapter = WalletBackedPrivateKey(
            _WalletDouble(askar_key), verkey, P256, loop=loop
        )
        from cryptography.exceptions import UnsupportedAlgorithm

        with pytest.raises(UnsupportedAlgorithm):
            adapter.private_bytes(None, None, None)
        with pytest.raises(UnsupportedAlgorithm):
            adapter.private_numbers()
        with pytest.raises(UnsupportedAlgorithm):
            adapter.exchange(None, None)
    finally:
        loop.close()


# ------------------------------------------------------------------ build_csr


def test_build_csr_end_to_end():
    verkey, askar_key = _p256_verkey_and_askar_key()

    async def _run():
        wallet = _WalletDouble(askar_key)
        csr_pem = await build_csr(
            wallet,
            verkey,
            P256,
            {"cn": "issuer.example.com", "country": "CA"},
        )
        # Parse the CSR and verify its signature + subject.
        csr = x509.load_pem_x509_csr(csr_pem)
        assert csr.is_signature_valid  # cryptography self-verifies
        assert csr.subject.rfc4514_string() == "CN=issuer.example.com,C=CA"
        # Public key in the CSR must equal the verkey's public key.
        expected = verkey_to_public_key(verkey, P256)
        assert (
            csr.public_key().public_numbers() == expected.public_numbers()
        )

    asyncio.run(_run())


def test_build_csr_rejects_empty_subject():
    verkey, askar_key = _p256_verkey_and_askar_key()

    async def _run():
        with pytest.raises(WalletError, match="at least one field"):
            await build_csr(_WalletDouble(askar_key), verkey, P256, {})

    asyncio.run(_run())


# ------------------------------------------------------------------ assert_cert_matches_verkey


def _self_sign_cert(askar_key, cn: str) -> bytes:
    """Build a self-signed cert whose subject public key is `askar_key`."""
    from cryptography.hazmat.primitives import serialization

    verkey = bytes_to_b58(askar_key.get_public_bytes())

    async def _run():
        loop = asyncio.get_running_loop()
        adapter = WalletBackedPrivateKey(
            _WalletDouble(askar_key), verkey, P256, loop=loop
        )
        pub = adapter.public_key()
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(pub)
            .serial_number(1)
            .not_valid_before(__import__("datetime").datetime(2026, 1, 1))
            .not_valid_after(__import__("datetime").datetime(2030, 1, 1))
        )
        # sign the cert via adapter (off-loop because .sign() is sync)
        signed = await asyncio.to_thread(
            cert.sign, adapter, hashes.SHA256()
        )
        return signed.public_bytes(serialization.Encoding.PEM)

    return asyncio.run(_run())


def test_assert_cert_matches_verkey_accepts_matching_cert():
    _verkey, askar_key = _p256_verkey_and_askar_key()
    pem = _self_sign_cert(askar_key, "issuer.example.com")
    assert_cert_matches_verkey(
        pem, bytes_to_b58(askar_key.get_public_bytes()), P256
    )


def test_assert_cert_matches_verkey_rejects_wrong_verkey():
    _v1, k1 = _p256_verkey_and_askar_key()
    _v2, k2 = _p256_verkey_and_askar_key()
    pem = _self_sign_cert(k1, "issuer.example.com")
    with pytest.raises(WalletError, match="does not match"):
        assert_cert_matches_verkey(pem, bytes_to_b58(k2.get_public_bytes()), P256)


def test_assert_cert_matches_verkey_rejects_bad_pem():
    with pytest.raises(WalletError, match="invalid certificate PEM"):
        assert_cert_matches_verkey(b"not a cert", "aaa", P256)
