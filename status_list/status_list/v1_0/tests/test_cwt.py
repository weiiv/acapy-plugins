"""Tests for cwt module."""

import cbor2
import pytest

from acapy_agent.admin.request_context import AdminRequestContext

from .. import status_handler
from ..cwt import (
    STATUSLIST_CWT_TYP,
    cwt_sign,
    to_cwt_claims,
)


# Header labels / claim keys under test (mirror cwt.py private constants).
_HEADER_ALG = 1
_HEADER_KID = 4
_HEADER_TYP = 16
_ALG_EDDSA = -8

_CLAIM_ISS = 1
_CLAIM_SUB = 2
_CLAIM_EXP = 4
_CLAIM_NBF = 5
_CLAIM_IAT = 6
_CLAIM_CTI = 7
_CLAIM_STATUS_LIST = 65533
_CLAIM_TTL = 65534
_SL_BITS = 0
_SL_LST = 1

_COSE_SIGN1_TAG = 18


def test_to_cwt_claims_maps_registered_and_status_list_keys():
    payload = {
        "iss": "did:web:example.com",
        "sub": "https://status.example.com/1",
        "nbf": 100,
        "iat": 100,
        "exp": 200,
        "ttl": 43200,
        "jti": "urn:uuid:1",
        # `lst` is emitted by get_status_list() as unpadded base64url.
        "status_list": {"bits": 1, "lst": "eNo"},
    }

    claims = to_cwt_claims(payload)

    assert claims[_CLAIM_ISS] == "did:web:example.com"
    assert claims[_CLAIM_SUB] == "https://status.example.com/1"
    assert claims[_CLAIM_NBF] == 100
    assert claims[_CLAIM_IAT] == 100
    assert claims[_CLAIM_EXP] == 200
    assert claims[_CLAIM_TTL] == 43200
    assert claims[_CLAIM_CTI] == b"urn:uuid:1"

    inner = claims[_CLAIM_STATUS_LIST]
    assert inner[_SL_BITS] == 1
    # b64url("eNo") decodes to three bytes (zlib compressed empty stream stub)
    assert isinstance(inner[_SL_LST], bytes)
    assert inner[_SL_LST] == b"\x78\xda"


def test_to_cwt_claims_drops_unknown_keys():
    claims = to_cwt_claims({"foo": "bar", "iss": "x"})
    assert claims == {_CLAIM_ISS: "x"}


@pytest.mark.asyncio
async def test_cwt_sign_structure(context: AdminRequestContext):
    payload = {
        "iss": "did:web:example.com",
        "sub": "https://status.example.com/tenants/base/status/1",
        "nbf": 1_700_000_000,
        "iat": 1_700_000_000,
        "exp": 1_700_086_400,
        "ttl": 43200,
        "jti": "urn:uuid:1",
        "status_list": {"bits": 1, "lst": "eNo"},
    }
    verification_method = (
        "did:web:example.com#3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRx"
    )

    cwt = await cwt_sign(
        context.profile,
        payload=payload,
        verification_method=verification_method,
    )

    assert isinstance(cwt, (bytes, bytearray))

    tagged = cbor2.loads(cwt)
    assert isinstance(tagged, cbor2.CBORTag)
    assert tagged.tag == _COSE_SIGN1_TAG

    protected_bstr, unprotected, payload_bstr, signature = tagged.value
    assert isinstance(protected_bstr, (bytes, bytearray))
    assert dict(unprotected) == {}
    assert isinstance(payload_bstr, (bytes, bytearray))
    # Ed25519 raw signature length is 64 bytes.
    assert isinstance(signature, (bytes, bytearray)) and len(signature) == 64

    protected = cbor2.loads(protected_bstr)
    assert protected[_HEADER_ALG] == _ALG_EDDSA
    assert protected[_HEADER_TYP] == STATUSLIST_CWT_TYP
    assert protected[_HEADER_KID] == verification_method

    claims = cbor2.loads(payload_bstr)
    assert claims[_CLAIM_ISS] == "did:web:example.com"
    assert claims[_CLAIM_TTL] == 43200
    assert claims[_CLAIM_CTI] == b"urn:uuid:1"
    assert claims[_CLAIM_STATUS_LIST][_SL_BITS] == 1
    assert isinstance(claims[_CLAIM_STATUS_LIST][_SL_LST], bytes)


@pytest.mark.asyncio
async def test_cwt_sign_requires_did_or_verification_method(
    context: AdminRequestContext,
):
    with pytest.raises(ValueError):
        await cwt_sign(context.profile, payload={"iss": "x"})


@pytest.mark.asyncio
async def test_get_status_list_token_returns_cwt_when_accept_cwt(
    context: AdminRequestContext, seed_db
):
    cwt = await status_handler.get_status_list_token(
        context, "1", accept="application/statuslist+cwt"
    )
    assert isinstance(cwt, (bytes, bytearray))
    tagged = cbor2.loads(cwt)
    assert isinstance(tagged, cbor2.CBORTag)
    assert tagged.tag == _COSE_SIGN1_TAG


@pytest.mark.asyncio
async def test_get_status_list_token_returns_jwt_by_default(
    context: AdminRequestContext, seed_db
):
    token = await status_handler.get_status_list_token(context, "1")
    assert isinstance(token, str)
    assert token.count(".") == 2
