from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.jwt import b64_to_bytes, b64_to_dict
from acapy_agent.wallet.key_type import X25519, KeyTypes
from acapy_agent.wallet.keys.manager import (
    MultikeyManager,
    multikey_to_verkey,
    verkey_to_multikey,
)
from acapy_agent.wallet.util import b58_to_bytes, bytes_to_b58
from aiohttp import web
from aries_askar import Key, KeyAlg

from jwt_vc_json.cred_processor import JwtVcJsonCredProcessor
from oid4vc.cred_processor import CredProcessors
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.public_routes import PopResult
from oid4vc.routes.exchange import create_exchange
from sd_jwt_vc.cred_processor import SdJwtCredIssueProcessor

ISSUER_ID = "https://issuer.example.com"
HOLDER_KID = "did:key:z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i#0"


@pytest.fixture(autouse=True)
def key_types(profile: Profile):
    profile.context.injector.bind_instance(KeyTypes, KeyTypes())


@pytest.fixture
async def multikey(profile: Profile) -> str:
    async with profile.session() as session:
        return (await MultikeyManager(session).create(alg="p256"))["multikey"]


@pytest.fixture
def create_request(context: AdminRequestContext, monkeypatch):
    """Build a create_exchange request for a supported credential of `fmt`."""

    def _build(body: dict, fmt: str = "jwt_vc_json"):
        supported = MagicMock(spec=SupportedCredential)
        supported.format = fmt
        monkeypatch.setattr(
            "oid4vc.routes.exchange.SupportedCredential.retrieve_by_id",
            AsyncMock(return_value=supported),
        )
        processors = MagicMock(spec=CredProcessors)
        processors.issuers = {fmt: MagicMock()}
        context.injector.bind_instance(CredProcessors, processors)
        monkeypatch.setattr(
            "oid4vc.routes.exchange.OID4VCIExchangeRecord.save", AsyncMock()
        )

        class Request:
            async def json(self):
                return {
                    "supported_cred_id": "cred_id",
                    "credential_subject": {"name": "alice"},
                    **body,
                }

            def __getitem__(self, key):
                return {"context": context}[key]

        return cast(web.Request, Request())

    return _build


@pytest.mark.asyncio
async def test_create_exchange_signing_multikey(create_request, multikey):
    request = create_request(
        {
            "signing_multikey": multikey,
            "issuer_id": ISSUER_ID,
            "did": "did:key:z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i",
        }
    )

    record = await create_exchange(request)

    assert record.signing_multikey == multikey
    assert record.issuer_id == ISSUER_ID
    assert record.verification_method is None


@pytest.mark.asyncio
async def test_create_exchange_signing_multikey_issuer_id_optional(
    create_request, multikey
):
    request = create_request({"signing_multikey": multikey}, fmt="vc+sd-jwt")

    record = await create_exchange(request)

    assert record.signing_multikey == multikey
    assert record.issuer_id is None


@pytest.mark.asyncio
async def test_create_exchange_signing_multikey_jwt_vc_json_needs_issuer_id(
    create_request, multikey
):
    with pytest.raises(web.HTTPBadRequest, match="issuer_id is required"):
        await create_exchange(create_request({"signing_multikey": multikey}))


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
async def test_create_exchange_signing_multikey_rejected(
    create_request, signing_multikey, reason
):
    request = create_request({"signing_multikey": signing_multikey})

    with pytest.raises(web.HTTPBadRequest, match=reason):
        await create_exchange(request)


@pytest.mark.asyncio
async def test_create_exchange_signing_multikey_unsupported_type(
    create_request, profile: Profile
):
    async with profile.session() as session:
        key_info = await session.inject(BaseWallet).create_key(X25519)
    request = create_request(
        {"signing_multikey": verkey_to_multikey(key_info.verkey, "x25519")}
    )

    with pytest.raises(web.HTTPBadRequest, match="must be ed25519 or p256"):
        await create_exchange(request)


def _exchange(multikey: str, issuer_id=ISSUER_ID) -> OID4VCIExchangeRecord:
    return OID4VCIExchangeRecord(
        state=OID4VCIExchangeRecord.STATE_OFFER_CREATED,
        supported_cred_id="456",
        credential_subject={"name": "alice"},
        signing_multikey=multikey,
        issuer_id=issuer_id,
    )


def _pop() -> PopResult:
    return PopResult(
        headers=None, payload=None, verified=True, holder_kid=HOLDER_KID, holder_jwk=None
    )


def _verify(jws: str, multikey: str) -> tuple[dict, dict]:
    headers, payload, sig = jws.split("~")[0].split(".")
    key = Key.from_public_bytes(KeyAlg.P256, b58_to_bytes(multikey_to_verkey(multikey)))
    assert key.verify_signature(
        f"{headers}.{payload}".encode(), b64_to_bytes(sig, urlsafe=True)
    )
    return b64_to_dict(headers), b64_to_dict(payload)


@pytest.mark.asyncio
async def test_jwt_vc_json_issues_with_signing_multikey(
    context: AdminRequestContext, multikey
):
    supported = SupportedCredential(
        format="jwt_vc_json",
        format_data={"types": ["VerifiableCredential"]},
        vc_additional_data={"type": ["VerifiableCredential"]},
    )

    jws = await JwtVcJsonCredProcessor().issue(
        {}, supported, _exchange(multikey), _pop(), context
    )

    headers, payload = _verify(jws, multikey)
    assert headers == {"typ": "JWT", "alg": "ES256"}
    assert payload["iss"] == ISSUER_ID
    assert payload["vc"]["issuer"] == ISSUER_ID


@pytest.mark.asyncio
async def test_sd_jwt_vc_issues_with_signing_multikey(
    context: AdminRequestContext, multikey
):
    supported = SupportedCredential(
        format="vc+sd-jwt",
        format_data={"vct": "ExampleCredential"},
        vc_additional_data={"sd_list": ["/name"]},
    )

    cred = await SdJwtCredIssueProcessor().issue(
        {}, supported, _exchange(multikey, issuer_id=None), _pop(), context
    )

    headers, payload = _verify(cred, multikey)
    assert headers == {"typ": "vc+sd-jwt", "alg": "ES256"}
    assert "iss" not in payload
