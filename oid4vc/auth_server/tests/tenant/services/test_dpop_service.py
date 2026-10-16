import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from authlib.jose import JsonWebKey, jwt
from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc9449.errors import InvalidDPopProofError

from tenant.security.dpop import HmacDPoPNonceGenerator
from tenant.services import dpop_service

_TOKEN_URL = "https://as.example.com/tenants/t1/token"


def _proof_request(*, iat: int, nonce: str | None = None) -> OAuth2Request:
    key = JsonWebKey.generate_key("EC", "P-256", is_private=True)
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": key.as_dict(is_private=False)}
    payload = {"jti": f"jti-{iat}", "htm": "POST", "htu": _TOKEN_URL, "iat": iat}
    if nonce:
        payload["nonce"] = nonce
    proof = jwt.encode(header, payload, key).decode()
    return OAuth2Request("POST", _TOKEN_URL, headers={"dpop": proof})


@pytest.fixture(autouse=True)
def jti_cache(monkeypatch):
    cache = Mock(check_and_store=AsyncMock(return_value=True))
    monkeypatch.setattr(dpop_service, "_dpop_jti_cache", cache)
    return cache


@pytest.fixture
def no_nonce(monkeypatch):
    monkeypatch.setattr(dpop_service.settings, "DPOP_NONCE_SECRET", "")
    monkeypatch.setattr(dpop_service.settings, "DPOP_PROOF_MAX_AGE", 60)
    monkeypatch.setattr(dpop_service, "_validator", None)


@pytest.mark.asyncio
async def test_fresh_proof_without_nonce_is_accepted(no_nonce):
    request = _proof_request(iat=int(time.time()) - 5)

    assert await dpop_service.validate_dpop_proof(request, db=None)


@pytest.mark.asyncio
async def test_old_proof_without_nonce_is_rejected(no_nonce):
    """RFC 9449 §11.1: proofs are only accepted for a limited time after creation."""
    request = _proof_request(iat=int(time.time()) - 3600)

    with pytest.raises(InvalidDPopProofError):
        await dpop_service.validate_dpop_proof(request, db=None)


@pytest.mark.asyncio
async def test_valid_nonce_bounds_lifetime_instead_of_iat(monkeypatch):
    nonce_generator = HmacDPoPNonceGenerator(secret="secret", interval=60)
    monkeypatch.setattr(dpop_service.settings, "DPOP_PROOF_MAX_AGE", 60)
    monkeypatch.setattr(
        dpop_service,
        "_validator",
        dpop_service._FixedDPoPProofValidator(
            nonce_generator=nonce_generator, algs=["ES256", "ES384"]
        ),
    )
    request = _proof_request(iat=int(time.time()) - 3600, nonce=nonce_generator.next())

    assert await dpop_service.validate_dpop_proof(request, db=None)


@pytest.mark.asyncio
async def test_proof_jti_is_recorded_until_proof_expires(no_nonce, jti_cache):
    iat = int(time.time()) - 5
    db = object()

    jkt = await dpop_service.validate_dpop_proof(_proof_request(iat=iat), db=db)

    jti_cache.check_and_store.assert_awaited_once_with(
        f"jti-{iat}",
        db,
        expires_at=iat + 60,
        metadata={"htm": "POST", "htu": _TOKEN_URL, "cnf_jkt": jkt},
    )


@pytest.mark.asyncio
async def test_replayed_proof_is_rejected(no_nonce, jti_cache):
    jti_cache.check_and_store.return_value = False

    with pytest.raises(InvalidDPopProofError, match="replayed"):
        await dpop_service.validate_dpop_proof(
            _proof_request(iat=int(time.time())), db=None
        )


def test_disabled_dpop_does_not_emit_nonce_with_configured_secret(monkeypatch):
    get_validator = Mock()
    monkeypatch.setattr(dpop_service.settings, "DPOP_ENABLED", False)
    monkeypatch.setattr(dpop_service.settings, "DPOP_NONCE_SECRET", "secret")
    monkeypatch.setattr(dpop_service, "_get_validator", get_validator)

    assert dpop_service.get_dpop_nonce() is None
    get_validator.assert_not_called()


def test_enabled_dpop_emits_configured_nonce(monkeypatch):
    nonce_generator = Mock()
    nonce_generator.next.return_value = "nonce"
    monkeypatch.setattr(dpop_service.settings, "DPOP_ENABLED", True)
    monkeypatch.setattr(dpop_service.settings, "DPOP_NONCE_SECRET", "secret")
    monkeypatch.setattr(
        dpop_service,
        "_get_validator",
        Mock(return_value=SimpleNamespace(nonce_generator=nonce_generator)),
    )

    assert dpop_service.get_dpop_nonce() == "nonce"
