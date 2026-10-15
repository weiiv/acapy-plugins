"""Tests for status list signing with signing_multikey."""

import json
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock

import cbor2
import pytest
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.wallet.jwt import b64_to_dict
from acapy_agent.wallet.keys.manager import (
    MultikeyManager,
    multikey_to_verkey,
    verkey_to_multikey,
)
from acapy_agent.wallet.util import b58_to_bytes, b64_to_bytes, bytes_to_b58
from aiohttp.web import HTTPBadRequest
from aries_askar import Key, KeyAlg
from cryptography.hazmat.primitives.serialization import Encoding
from x509_certs import X509CertificateRecord
from x509_certs.certs import describe, to_x5c
from x509_certs.tests.conftest import NOW, Pki, wallet_public_key

from .. import status_handler
from ..controllers import status_list_def as def_controller
from ..controllers import status_list_pub as pub_controller
from ..error import StatusListError
from ..models import StatusListDef

ISSUER_ID = "https://issuer.example.com"
CWT = "application/statuslist+cwt"
_HEADER_KID = 4
_HEADER_X5CHAIN = 33


@pytest.fixture
async def multikey(context: AdminRequestContext) -> str:
    async with context.profile.session() as session:
        return (await MultikeyManager(session).create(alg="p256"))["multikey"]


@pytest.fixture
def pki() -> Pki:
    return Pki()


async def _store_certificate(context: AdminRequestContext, multikey: str, certs):
    async with context.profile.session() as session:
        await X509CertificateRecord(
            multikey=multikey,
            purpose="sd_jwt_vc_issuer",
            x5c=to_x5c(certs),
            **describe(certs[0]),
        ).save(session)


async def _store_issuer_chain(context, multikey, pki, days=400):
    leaf = pki.leaf(wallet_public_key(multikey), not_after=NOW + timedelta(days=days))
    await _store_certificate(context, multikey, [leaf, pki.intermediate, pki.root])
    return leaf


def _definition(multikey: str, **kwargs) -> StatusListDef:
    return StatusListDef(
        id="definition_id", list_type="ietf", signing_multikey=multikey, **kwargs
    )


def _key(multikey: str) -> Key:
    return Key.from_public_bytes(KeyAlg.P256, b58_to_bytes(multikey_to_verkey(multikey)))


def _verify_jws(token: str, multikey: str) -> tuple[dict, dict]:
    headers, payload, sig = token.split(".")
    assert _key(multikey).verify_signature(
        f"{headers}.{payload}".encode(), b64_to_bytes(sig, urlsafe=True)
    )
    return b64_to_dict(headers), b64_to_dict(payload)


def _request(context: AdminRequestContext, body: dict = None, **match_info):
    return MagicMock(
        app={},
        match_info=match_info,
        query={},
        headers={},
        __getitem__=lambda _, k: {"context": context}[k],
        json=AsyncMock(return_value=body or {}),
    )


def test_record_value_stores_signing_key_only_when_set():
    value = StatusListDef(issuer_did="did:web:example.com").record_value
    assert "signing_multikey" not in value
    assert "issuer_id" not in value

    value = _definition("zDnaeTest", issuer_id=ISSUER_ID).record_value
    assert value["signing_multikey"] == "zDnaeTest"
    assert value["issuer_id"] == ISSUER_ID
    loaded = StatusListDef.from_storage("definition_id", value)
    assert loaded.signing_multikey == "zDnaeTest"
    assert loaded.issuer_id == ISSUER_ID


@pytest.mark.asyncio
async def test_jwt_signed_with_signing_multikey(context, multikey, pki):
    leaf = await _store_issuer_chain(context, multikey, pki)

    token = await status_handler.get_status_list_token(
        context, "0", _definition(multikey, issuer_id=ISSUER_ID)
    )

    headers, payload = _verify_jws(token, multikey)
    assert headers == {
        "typ": "statuslist+jwt",
        "x5c": to_x5c([leaf, pki.intermediate]),
        "alg": "ES256",
    }
    assert payload["iss"] == ISSUER_ID


@pytest.mark.asyncio
async def test_iss_left_out_without_issuer_id(context, multikey, pki):
    await _store_issuer_chain(context, multikey, pki)

    token = await status_handler.get_status_list_token(
        context, "0", _definition(multikey)
    )

    _, payload = _verify_jws(token, multikey)
    assert "iss" not in payload


@pytest.mark.asyncio
async def test_cwt_signed_with_signing_multikey(context, multikey, pki):
    leaf = await _store_issuer_chain(context, multikey, pki)

    token = await status_handler.get_status_list_token(
        context, "0", _definition(multikey), accept=CWT
    )

    protected_bstr, _, payload_bstr, signature = cbor2.loads(token).value
    protected = cbor2.loads(protected_bstr)
    assert protected[_HEADER_X5CHAIN] == [
        leaf.public_bytes(Encoding.DER),
        pki.intermediate.public_bytes(Encoding.DER),
    ]
    assert _HEADER_KID not in protected
    assert _key(multikey).verify_signature(
        cbor2.dumps(["Signature1", protected_bstr, b"", payload_bstr]), signature
    )


@pytest.mark.asyncio
async def test_signing_fails_without_certificate_covering_expiry(context, multikey, pki):
    await _store_issuer_chain(context, multikey, pki, days=10)

    with pytest.raises(StatusListError, match="No sd_jwt_vc_issuer certificate"):
        await status_handler.get_status_list_token(context, "0", _definition(multikey))


@pytest.mark.asyncio
async def test_publish_without_certificate_is_bad_request(context, multikey):
    async with context.profile.session() as session:
        await StatusListDef(
            id="definition_mk_id",
            new_with_id=True,
            supported_cred_id="mk_cred",
            list_type="ietf",
            list_numbers=["99"],
            signing_multikey=multikey,
        ).save(session)

    with pytest.raises(HTTPBadRequest, match="No sd_jwt_vc_issuer certificate"):
        await pub_controller.publish_status_list(
            _request(context, def_id="definition_mk_id")
        )


@pytest.mark.asyncio
async def test_create_definition_with_signing_multikey(context, multikey):
    body = {
        "supported_cred_id": "mk_cred",
        "list_type": "ietf",
        "list_size": 1024,
        "shard_size": 1024,
        "signing_multikey": multikey,
        "issuer_id": ISSUER_ID,
    }

    response = await def_controller.create_status_list_def(_request(context, body))

    async with context.profile.session() as session:
        definition = await StatusListDef.retrieve_by_id(
            session, json.loads(response.body)["id"]
        )
    assert definition.signing_multikey == multikey
    assert definition.issuer_id == ISSUER_ID


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("signing_multikey", "reason"),
    [
        ("zXXXX", "Invalid signing_multikey"),
        (
            verkey_to_multikey(
                bytes_to_b58(Key.generate(KeyAlg.P256).get_public_bytes()), "p256"
            ),
            "not in the wallet",
        ),
    ],
)
async def test_create_definition_rejects_signing_multikey(
    context, signing_multikey, reason
):
    body = {"signing_multikey": signing_multikey}

    with pytest.raises(HTTPBadRequest, match=reason):
        await def_controller.create_status_list_def(_request(context, body))


@pytest.mark.asyncio
async def test_w3c_with_signing_multikey_needs_issuer_id(context, multikey):
    body = {"list_type": "w3c", "signing_multikey": multikey}

    with pytest.raises(HTTPBadRequest, match="issuer_id is required"):
        await def_controller.create_status_list_def(_request(context, body))
    with pytest.raises(HTTPBadRequest, match="issuer_id is required"):
        await def_controller.update_status_list_def(
            _request(context, body, def_id="definition_id")
        )
