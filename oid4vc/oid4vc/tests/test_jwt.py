import json

import pytest
from acapy_agent.core.profile import Profile
from acapy_agent.wallet.did_method import DIDMethods
from acapy_agent.wallet.error import WalletNotFoundError
from acapy_agent.wallet.jwt import b64_to_bytes, b64_to_dict
from acapy_agent.wallet.keys.manager import MultikeyManager, multikey_to_verkey
from acapy_agent.wallet.key_type import KeyTypes
from acapy_agent.wallet.util import b58_to_bytes, bytes_to_b58, bytes_to_b64
from aries_askar import Key, KeyAlg

from oid4vc.did_utils import retrieve_or_create_did_jwk
from oid4vc.jwk import DID_JWK
from oid4vc.jwt import did_jwk_to_verkey, jwt_sign


@pytest.fixture(autouse=True)
def wallet_registries(profile: Profile):
    did_methods = DIDMethods()
    did_methods.register(DID_JWK)
    profile.context.injector.bind_instance(DIDMethods, did_methods)
    profile.context.injector.bind_instance(KeyTypes, KeyTypes())


async def _create_verkey(profile: Profile, alg: str) -> str:
    async with profile.session() as session:
        key_info = await MultikeyManager(session).create(alg=alg)
    return multikey_to_verkey(key_info["multikey"])


def _did_jwk(verkey: str, alg: KeyAlg) -> str:
    jwk = Key.from_public_bytes(alg, b58_to_bytes(verkey)).get_jwk_public()
    return "did:jwk:" + bytes_to_b64(jwk.encode(), urlsafe=True, pad=False)


def _decode(jws: str):
    headers, payload, sig = jws.split(".")
    return (
        b64_to_dict(headers),
        f"{headers}.{payload}".encode(),
        b64_to_bytes(sig, urlsafe=True),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("alg", "key_alg", "jws_alg"),
    [("p256", KeyAlg.P256, "ES256"), ("ed25519", KeyAlg.ED25519, "EdDSA")],
)
async def test_jwt_sign_verkey(profile: Profile, alg, key_alg, jws_alg):
    verkey = await _create_verkey(profile, alg)

    jws = await jwt_sign(profile, {}, {"iss": "https://issuer.example"}, verkey=verkey)

    headers, signed, sig = _decode(jws)
    assert headers == {"typ": "JWT", "alg": jws_alg}
    key = Key.from_public_bytes(key_alg, b58_to_bytes(verkey))
    assert key.verify_signature(signed, sig)


@pytest.mark.asyncio
async def test_jwt_sign_verkey_keeps_caller_kid(profile: Profile):
    verkey = await _create_verkey(profile, "p256")

    jws = await jwt_sign(profile, {"kid": "issuer-key-1"}, {}, verkey=verkey)

    headers, _, _ = _decode(jws)
    assert headers["kid"] == "issuer-key-1"


@pytest.mark.asyncio
async def test_jwt_sign_verkey_with_x5c(profile: Profile):
    verkey = await _create_verkey(profile, "p256")

    jws = await jwt_sign(profile, {}, {}, x5c_chain=["MIIB"], verkey=verkey)

    headers, _, _ = _decode(jws)
    assert headers["x5c"] == ["MIIB"]
    assert "kid" not in headers


@pytest.mark.asyncio
async def test_jwt_sign_unknown_verkey(profile: Profile):
    verkey = bytes_to_b58(Key.generate(KeyAlg.P256).get_public_bytes())

    with pytest.raises(WalletNotFoundError):
        await jwt_sign(profile, {}, {}, verkey=verkey)


@pytest.mark.asyncio
async def test_jwt_sign_did_jwk_without_did_record(profile: Profile):
    verkey = await _create_verkey(profile, "p256")
    did = _did_jwk(verkey, KeyAlg.P256)

    jws = await jwt_sign(profile, {}, {}, verification_method=f"{did}#0")

    headers, signed, sig = _decode(jws)
    assert headers["kid"] == f"{did}#0"
    assert headers["alg"] == "ES256"
    key = Key.from_public_bytes(KeyAlg.P256, b58_to_bytes(verkey))
    assert key.verify_signature(signed, sig)


@pytest.mark.asyncio
async def test_jwt_sign_did_jwk_prefers_did_record(profile: Profile):
    # The record's key is stored under its JWK thumbprint, so decoding the
    # did:jwk instead of using the record would not find the key.
    async with profile.session() as session:
        did_info = await retrieve_or_create_did_jwk(session)

    jws = await jwt_sign(profile, {}, {}, verification_method=f"{did_info.did}#0")

    headers, signed, sig = _decode(jws)
    assert headers["alg"] == "EdDSA"
    jwk = json.loads(b64_to_bytes(did_info.did[len("did:jwk:") :], urlsafe=True))
    assert Key.from_jwk(jwk).verify_signature(signed, sig)


@pytest.mark.asyncio
async def test_jwt_sign_non_jwk_did_without_record(profile: Profile):
    multikey = "z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i"

    with pytest.raises(WalletNotFoundError):
        await jwt_sign(
            profile, {}, {}, verification_method=f"did:key:{multikey}#{multikey}"
        )


def test_did_jwk_to_verkey():
    key = Key.generate(KeyAlg.P256)
    verkey = bytes_to_b58(key.get_public_bytes())

    assert did_jwk_to_verkey(_did_jwk(verkey, KeyAlg.P256)) == verkey
