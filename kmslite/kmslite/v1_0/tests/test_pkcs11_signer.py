"""Tests for PKCS11Signer.

These tests exercise `PKCS11Signer` against mocked python-pkcs11
sessions — no real HSM required. Round-trips against a real Luna / BouncyHSM
belong in the `integration/` suite (not run here).
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest
from aries_askar import Key, KeyAlg

from acapy_agent.wallet.error import WalletError
from acapy_agent.wallet.key_type import ED25519, P256
from acapy_agent.wallet.util import b58_to_bytes

from kmslite.v1_0.signers.pkcs11 import (
    PKCS11Signer,
    _sec1_compress,
    _unwrap_ec_point,
)


# ------------------------------------------------------------------ helpers


def _make_signer(pool_size: int = 2) -> PKCS11Signer:
    """Build a PKCS11Signer with mocked pkcs11 library + sessions."""
    with patch("kmslite.v1_0.signers.pkcs11.pkcs11") as pkcs11_mod:
        mock_lib = MagicMock()
        mock_token = MagicMock()
        pkcs11_mod.lib.return_value = mock_lib
        mock_lib.get_token.return_value = mock_token
        # Each `open` returns a fresh session mock; the signer will hold
        # pool_size of them in its queue.
        mock_token.open.side_effect = [MagicMock() for _ in range(pool_size)]
        signer = PKCS11Signer(
            lib_path="/fake/lib.so",
            token_label="test-token",
            pin="1234",
            pool_size=pool_size,
        )
    return signer


def _fake_ec_point_der(uncompressed_point: bytes) -> bytes:
    """Wrap a raw EC point in the DER OCTET STRING form PKCS#11 returns."""
    return bytes([0x04, len(uncompressed_point)]) + uncompressed_point


def _real_p256_uncompressed_point() -> bytes:
    """Return a real 65-byte SEC1 uncompressed P-256 point (04 || X || Y).

    Using aries-askar to get a genuine key means the round-trip through
    Key.from_public_bytes works too.
    """
    k = Key.generate(KeyAlg.P256)
    compressed = k.get_public_bytes()  # 33 bytes, SEC1 compressed
    # Uncompress by round-tripping via cryptography.
    from cryptography.hazmat.primitives.asymmetric import ec

    pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), compressed
    )
    numbers = pub.public_numbers()
    coord_len = 32
    return (
        b"\x04"
        + numbers.x.to_bytes(coord_len, "big")
        + numbers.y.to_bytes(coord_len, "big")
    )


# ------------------------------------------------------------------ helpers under test


def test_sec1_compress_from_uncompressed():
    # y-coord ending in even → 0x02
    x = b"\x01" * 32
    y_even = b"\x02" * 32
    uncompressed = b"\x04" + x + y_even
    compressed = _sec1_compress(uncompressed)
    assert compressed == b"\x02" + x

    # y-coord ending in odd → 0x03
    y_odd = b"\x02" * 31 + b"\x03"
    uncompressed = b"\x04" + x + y_odd
    assert _sec1_compress(uncompressed) == b"\x03" + x


def test_sec1_compress_already_compressed_is_noop():
    already = b"\x02" + b"\x11" * 32
    assert _sec1_compress(already) is already


def test_sec1_compress_rejects_unknown_prefix():
    with pytest.raises(WalletError, match="bad prefix/length"):
        _sec1_compress(b"\x05" + b"\x00" * 32)


def test_unwrap_ec_point_strips_der_header():
    inner = b"\x04" + b"\x11" * 64
    der = _fake_ec_point_der(inner)
    assert _unwrap_ec_point(der) == inner


def test_unwrap_ec_point_rejects_non_octet_string():
    with pytest.raises(WalletError, match="not a DER OCTET STRING"):
        _unwrap_ec_point(b"\x30\x03abc")


def test_unwrap_ec_point_rejects_length_mismatch():
    with pytest.raises(WalletError, match="unexpected DER length"):
        _unwrap_ec_point(b"\x04\x05abc")  # says 5 bytes, has 3


# ------------------------------------------------------------------ PKCS11Signer construction


def test_init_opens_pool_of_sessions():
    signer = _make_signer(pool_size=3)
    # Pool should contain 3 sessions.
    assert signer._pool.qsize() == 3


def test_init_rejects_zero_pool_size():
    with pytest.raises(ValueError, match="pool_size"):
        with patch("kmslite.v1_0.signers.pkcs11.pkcs11"):
            PKCS11Signer(
                lib_path="x",
                token_label="t",
                pin="p",
                pool_size=0,
            )


def test_from_config_uses_resolved_pin(monkeypatch):
    # `from_config` no longer reads env — it expects a fully-resolved dict
    # with `pin` set. This matches what `KmsLiteConfig._resolve_pkcs11`
    # produces.
    with patch("kmslite.v1_0.signers.pkcs11.pkcs11") as pkcs11_mod:
        pkcs11_mod.lib.return_value.get_token.return_value.open.side_effect = [
            MagicMock() for _ in range(4)
        ]
        signer = PKCS11Signer.from_config(
            {
                "library_path": "/x",
                "token_name": "t",
                "pin": "the-actual-pin",
            }
        )
    assert signer._pool.qsize() == 4


def test_from_config_rejects_missing_required_key():
    with pytest.raises(ValueError, match="missing required key"):
        PKCS11Signer.from_config({"library_path": "/x"})


# ------------------------------------------------------------------ Signer API


@pytest.mark.asyncio
async def test_generate_keypair_returns_base58_compressed():
    signer = _make_signer(pool_size=1)
    uncompressed = _real_p256_uncompressed_point()
    der = _fake_ec_point_der(uncompressed)

    # Patch the helpers to short-circuit the HSM calls (pre-check + create).
    with (
        patch.object(signer, "_assert_key_ref_free_sync", return_value=None),
        patch.object(signer, "_create_keypair_sync", return_value=der),
    ):
        verkey = await signer.generate_keypair("issuer-key-01", P256)

    # verkey should be base58 of 33-byte SEC1-compressed P-256 point.
    raw = b58_to_bytes(verkey)
    assert len(raw) == 33
    assert raw[0] in (0x02, 0x03)


@pytest.mark.asyncio
async def test_generate_keypair_rejects_unsupported_key_type():
    signer = _make_signer(pool_size=1)
    with pytest.raises(WalletError, match="unsupported key_type"):
        await signer.generate_keypair("k", ED25519)


@pytest.mark.asyncio
async def test_generate_keypair_returns_session_to_pool_on_error():
    signer = _make_signer(pool_size=1)
    original_size = signer._pool.qsize()
    with (
        patch.object(signer, "_assert_key_ref_free_sync", return_value=None),
        patch.object(
            signer, "_create_keypair_sync", side_effect=RuntimeError("boom")
        ),
    ):
        with pytest.raises(RuntimeError):
            await signer.generate_keypair("k", P256)
    # Session should have been returned to the pool despite the exception.
    assert signer._pool.qsize() == original_size


@pytest.mark.asyncio
async def test_generate_keypair_rejects_duplicate_label():
    signer = _make_signer(pool_size=1)
    with patch.object(
        signer,
        "_assert_key_ref_free_sync",
        side_effect=WalletError("already exists"),
    ):
        with pytest.raises(WalletError, match="already exists"):
            await signer.generate_keypair("dupe", P256)


@pytest.mark.asyncio
async def test_sign_returns_signature_bytes_and_hashes_message():
    signer = _make_signer(pool_size=1)
    fake_sig = b"\x11" * 64
    with patch.object(
        signer, "_sign_digest_sync", return_value=fake_sig
    ) as sign_mock:
        result = await signer.sign("k", b"hello", P256)

    assert result == fake_sig
    # Called with SHA-256(b"hello") as digest.
    import hashlib

    expected_digest = hashlib.sha256(b"hello").digest()
    (_session_arg, key_ref_arg, digest_arg) = sign_mock.call_args.args
    assert key_ref_arg == "k"
    assert digest_arg == expected_digest


@pytest.mark.asyncio
async def test_sign_rejects_unsupported_key_type():
    signer = _make_signer(pool_size=1)
    with pytest.raises(WalletError, match="unsupported key_type"):
        await signer.sign("k", b"m", ED25519)


@pytest.mark.asyncio
async def test_get_public_key_returns_base58_compressed():
    signer = _make_signer(pool_size=1)
    uncompressed = _real_p256_uncompressed_point()
    der = _fake_ec_point_der(uncompressed)
    with patch.object(signer, "_read_public_point_sync", return_value=der):
        verkey = await signer.get_public_key("issuer-key-01", P256)
    assert len(b58_to_bytes(verkey)) == 33


@pytest.mark.asyncio
async def test_session_pool_serializes_concurrent_calls():
    signer = _make_signer(pool_size=1)
    fake_sig = b"\x22" * 64

    call_order = []

    def slow_sign_sync(session, key_ref, digest):
        call_order.append(("start", key_ref))
        # Sleep to overlap only if concurrency isn't bounded.
        import time

        time.sleep(0.05)
        call_order.append(("end", key_ref))
        return fake_sig

    with patch.object(signer, "_sign_digest_sync", side_effect=slow_sign_sync):
        await asyncio.gather(
            signer.sign("a", b"1", P256),
            signer.sign("b", b"2", P256),
        )

    # With pool_size=1 the two calls must serialize: end-of-first before
    # start-of-second (in some order).
    starts = [i for i, evt in enumerate(call_order) if evt[0] == "start"]
    ends = [i for i, evt in enumerate(call_order) if evt[0] == "end"]
    # 2 starts, 2 ends, and the first end must precede the second start.
    assert len(starts) == 2 and len(ends) == 2
    assert ends[0] < starts[1]
