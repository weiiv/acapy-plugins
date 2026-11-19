"""Tests for PKCS11Signer.

These tests exercise `PKCS11Signer` against mocked python-pkcs11
sessions — no real HSM required. Round-trips against a real Luna / BouncyHSM
belong in the `integration/` suite (not run here).
"""

import asyncio
from threading import Event
from unittest.mock import MagicMock, patch

import pytest
from aries_askar import Key, KeyAlg

from acapy_agent.wallet.error import WalletError
from acapy_agent.wallet.key_type import ED25519, P256
from acapy_agent.wallet.util import b58_to_bytes

from pkcs11_signer.config import Pkcs11Config
from pkcs11_signer.signer import (
    PKCS11Signer,
    _sec1_compress,
    _unwrap_ec_point,
)


# ------------------------------------------------------------------ helpers


def _mock_token(label: str = "test-token", slot_id: int = 0) -> MagicMock:
    """A token mock shaped like pkcs11.types.Token (label + slot.slot_id)."""
    token = MagicMock()
    token.label = label
    token.slot.slot_id = slot_id
    return token


def _make_signer(pool_size: int = 2) -> PKCS11Signer:
    """Build a PKCS11Signer with mocked pkcs11 library + sessions."""
    with patch("pkcs11_signer.signer.pkcs11") as pkcs11_mod:
        mock_lib = MagicMock()
        mock_token = _mock_token()
        pkcs11_mod.lib.return_value = mock_lib
        mock_lib.get_tokens.return_value = iter([mock_token])
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

    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), compressed)
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
        with patch("pkcs11_signer.signer.pkcs11"):
            PKCS11Signer(
                lib_path="x",
                token_label="t",
                pin="p",
                pool_size=0,
            )


def test_from_config_passes_resolved_config():
    cfg = Pkcs11Config(
        provider="hsm-a",
        library_path="/x",
        token_name="t",
        pin="the-actual-pin",
        slot=1,
        pool_size=3,
    )
    with patch("pkcs11_signer.signer.pkcs11") as pkcs11_mod:
        token = _mock_token(label="t", slot_id=1)
        token.open.side_effect = [MagicMock() for _ in range(3)]
        pkcs11_mod.lib.return_value.get_tokens.return_value = iter([token])
        signer = PKCS11Signer.from_config(cfg)
    pkcs11_mod.lib.assert_called_once_with("/x")
    assert all(
        call.kwargs == {"user_pin": "the-actual-pin", "rw": True}
        for call in token.open.call_args_list
    )
    assert signer._pool.qsize() == 3
    assert signer._provider_name == "hsm-a"


def test_init_slot_filters_tokens_sharing_a_label():
    tokens = [_mock_token("shared", slot_id=1), _mock_token("shared", slot_id=3)]
    with patch("pkcs11_signer.signer.pkcs11") as pkcs11_mod:
        mock_lib = pkcs11_mod.lib.return_value
        mock_lib.get_tokens.return_value = iter(tokens)
        signer = PKCS11Signer(
            lib_path="/fake/lib.so",
            token_label="shared",
            pin="1234",
            slot=3,
            pool_size=1,
        )
    assert signer._token is tokens[1]
    mock_lib.get_tokens.assert_called_once_with(token_label="shared")


@pytest.mark.parametrize(
    ("matched", "expected"),
    [
        ([], "matched 0 tokens"),
        ([_mock_token("shared", 1), _mock_token("shared", 3)], "matched 2 tokens"),
    ],
)
def test_init_without_exactly_one_match_lists_visible_tokens(matched, expected):
    visible = MagicMock()
    visible.slot_id = 2
    visible.get_token.return_value.label = "dev-token"
    with patch("pkcs11_signer.signer.pkcs11") as pkcs11_mod:
        mock_lib = pkcs11_mod.lib.return_value
        mock_lib.get_tokens.return_value = iter(matched)
        mock_lib.get_slots.return_value = [visible]
        with pytest.raises(WalletError) as err:
            PKCS11Signer(
                lib_path="/fake/lib.so",
                token_label="ABC_Issuer_002",
                pin="1234",
                pool_size=1,
            )
    message = str(err.value)
    assert expected in message
    assert "ABC_Issuer_002" in message
    assert "slot 2: 'dev-token'" in message


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
        patch.object(signer, "_create_keypair_sync", side_effect=RuntimeError("boom")),
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
    with patch.object(signer, "_sign_digest_sync", return_value=fake_sig) as sign_mock:
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
async def test_sign_rejects_multi_message():
    signer = _make_signer(pool_size=1)
    with pytest.raises(WalletError, match="multi-message"):
        await signer.sign("k", [b"a", b"b"], P256)


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


@pytest.mark.asyncio
async def test_cancelled_sign_keeps_session_until_worker_finishes():
    signer = _make_signer(pool_size=1)
    first_started = Event()
    release_first = Event()
    second_started = Event()

    def blocked_sign_sync(session, key_ref, digest):
        if key_ref == "first":
            first_started.set()
            release_first.wait()
        else:
            second_started.set()
        return b"\x33" * 64

    with patch.object(signer, "_sign_digest_sync", side_effect=blocked_sign_sync):
        first = asyncio.create_task(signer.sign("first", b"x", P256))
        assert await asyncio.to_thread(first_started.wait, 1)
        first.cancel()
        second = asyncio.create_task(signer.sign("second", b"y", P256))

        try:
            await asyncio.sleep(0.05)
            assert not second_started.is_set()
            assert not first.done()
        finally:
            release_first.set()
            first_result, second_result = await asyncio.gather(
                first, second, return_exceptions=True
            )

    assert isinstance(first_result, asyncio.CancelledError)
    assert second_result == b"\x33" * 64

    assert second_started.is_set()
