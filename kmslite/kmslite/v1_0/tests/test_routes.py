"""End-to-end tests for kmslite admin routes.

Uses a real in-memory Askar profile (via `create_test_profile`) and a fake
in-process `Signer`. Every request path exercises the plugin routes, the
wallet's base-class dispatch (through `SignerRegistry`), and the resulting
Askar reads/writes.
"""

import json
from unittest.mock import MagicMock

import pytest
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from acapy_agent.wallet.base import BaseWallet

from kmslite.v1_0 import routes as kmslite_routes


# --------------------------------------------------------------------- request builder


def _make_request(context, body=None, match_info=None):
    """Return a MagicMock that mimics aiohttp.web.BaseRequest for our handlers."""
    request = MagicMock(spec=web.BaseRequest)
    request.__getitem__ = lambda self, key: context if key == "context" else None
    request.match_info = match_info or {}

    async def _json():
        return body or {}

    request.json = _json
    return request


# --------------------------------------------------------------------- POST /kmslite/did/create


@pytest.mark.asyncio
async def test_create_kms_did_web_happy_path(context, fake_signer):
    body = {
        "method": "web",
        "key_type": "p256",
        "options": {
            "did": "did:web:issuer.example.com",
            "key_ref": "issuer-key-01",
        },
    }
    resp = await kmslite_routes.create_kms_did(_make_request(context, body))
    payload = json.loads(resp.body)

    assert payload["did"] == "did:web:issuer.example.com"
    assert payload["method"] == "web"
    assert payload["key_type"] == "p256"
    assert payload["metadata"]["signer"] == "hsm"
    assert payload["metadata"]["key_ref"] == "issuer-key-01"
    # verkey should be base58 of 33-byte compressed P-256 point.
    from acapy_agent.wallet.util import b58_to_bytes

    raw = b58_to_bytes(payload["verkey"])
    assert len(raw) == 33 and raw[0] in (0x02, 0x03)

    # DID should be retrievable via the wallet's normal API.
    async with context.profile.session() as session:
        wallet = session.inject(BaseWallet)
        did_info = await wallet.get_local_did("did:web:issuer.example.com")
        assert did_info.verkey == payload["verkey"]
        assert did_info.metadata.get("signer") == "hsm"


@pytest.mark.asyncio
async def test_create_kms_did_did_key_derives_did(context, fake_signer):
    body = {
        "method": "key",
        "key_type": "p256",
        "options": {"key_ref": "kdid-01"},
    }
    resp = await kmslite_routes.create_kms_did(_make_request(context, body))
    payload = json.loads(resp.body)
    assert payload["did"].startswith("did:key:")
    assert payload["method"] == "key"


@pytest.mark.asyncio
async def test_create_kms_did_rejects_did_key_with_did_option(context, fake_signer):
    body = {
        "method": "key",
        "key_type": "p256",
        "options": {"key_ref": "kdid-02", "did": "did:key:zAlreadySet"},
    }
    with pytest.raises(web.HTTPBadRequest):
        await kmslite_routes.create_kms_did(_make_request(context, body))


@pytest.mark.asyncio
async def test_create_kms_did_rejects_missing_key_ref(context, fake_signer):
    body = {
        "method": "web",
        "key_type": "p256",
        "options": {"did": "did:web:x.example.com"},
    }
    with pytest.raises(web.HTTPBadRequest):
        await kmslite_routes.create_kms_did(_make_request(context, body))


@pytest.mark.asyncio
async def test_create_kms_did_rejects_when_no_kmslite_config(monkeypatch):
    """No kmslite env vars → 503."""
    from acapy_agent.admin.request_context import AdminRequestContext
    from acapy_agent.utils.testing import create_test_profile
    from acapy_agent.wallet.did_method import DIDMethods
    from acapy_agent.wallet.key_type import KeyTypes

    # Override the autouse env-config fixture: strip everything so the plugin
    # is effectively unconfigured for this one test.
    for var in [
        "KMSLITE_PROVIDER",
        "KMSLITE_PROTOCOL",
        "KMSLITE_PKCS11_LIBRARY_PATH",
        "KMSLITE_PKCS11_TOKEN_NAME",
        "KMSLITE_PKCS11_PIN",
        "KMSLITE_PKCS11_SLOT",
        "KMSLITE_PKCS11_POOL_SIZE",
    ]:
        monkeypatch.delenv(var, raising=False)

    prof = await create_test_profile(
        {"wallet.type": "askar", "admin.admin_insecure_mode": True}
    )
    prof.context.injector.bind_instance(DIDMethods, DIDMethods())
    prof.context.injector.bind_instance(KeyTypes, KeyTypes())
    ctx = AdminRequestContext(prof)

    body = {"method": "web", "key_type": "p256", "options": {"key_ref": "x"}}
    with pytest.raises(web.HTTPServiceUnavailable):
        await kmslite_routes.create_kms_did(_make_request(ctx, body))


# --------------------------------------------------------------------- GET /public-key


@pytest.mark.asyncio
async def test_get_public_key_returns_pem(context, fake_signer):
    # Create the DID first.
    body = {
        "method": "web",
        "key_type": "p256",
        "options": {"did": "did:web:pk.example.com", "key_ref": "pk-01"},
    }
    await kmslite_routes.create_kms_did(_make_request(context, body))

    resp = await kmslite_routes.get_kms_did_public_key(
        _make_request(context, match_info={"did": "did:web:pk.example.com"})
    )
    payload = json.loads(resp.body)
    pem = payload["public_key_pem"].encode()
    pub = serialization.load_pem_public_key(pem)
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    assert pub.curve.name == "secp256r1"


@pytest.mark.asyncio
async def test_get_public_key_404_for_unknown_did(context):
    with pytest.raises(web.HTTPNotFound):
        await kmslite_routes.get_kms_did_public_key(
            _make_request(context, match_info={"did": "did:web:missing.example.com"})
        )


# --------------------------------------------------------------------- POST /csr


@pytest.mark.asyncio
async def test_create_csr_end_to_end(context, fake_signer):
    body = {
        "method": "web",
        "key_type": "p256",
        "options": {"did": "did:web:csr.example.com", "key_ref": "csr-01"},
    }
    await kmslite_routes.create_kms_did(_make_request(context, body))

    csr_req = {"subject": {"cn": "csr.example.com", "country": "CA"}}
    resp = await kmslite_routes.create_kms_did_csr(
        _make_request(
            context, body=csr_req, match_info={"did": "did:web:csr.example.com"}
        )
    )
    payload = json.loads(resp.body)
    pem = payload["csr_pem"].encode()
    csr = x509.load_pem_x509_csr(pem)
    assert csr.is_signature_valid
    assert csr.subject.rfc4514_string() == "CN=csr.example.com,C=CA"


# --------------------------------------------------------------------- POST /certificate (bind)


def _self_sign_cert_for_verkey(verkey: str) -> bytes:
    """Build a self-signed cert whose SPKI matches the given verkey."""
    import datetime

    from acapy_agent.wallet.key_type import P256
    from kmslite.v1_0.x509 import (
        verkey_to_public_key,
    )

    # We need a signer for the cert — reuse the fake signer's askar key.
    pub = verkey_to_public_key(verkey, P256)
    # Use a fresh throwaway key to actually sign the cert (self-signed for
    # testing; SPKI is what the route checks).
    from cryptography.hazmat.primitives.asymmetric import ec

    signer_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(pub)
        .serial_number(1)
        .not_valid_before(datetime.datetime(2026, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .sign(signer_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.mark.asyncio
async def test_bind_certificate_happy_path(context, fake_signer):
    body = {
        "method": "web",
        "key_type": "p256",
        "options": {"did": "did:web:cert.example.com", "key_ref": "cert-01"},
    }
    resp = await kmslite_routes.create_kms_did(_make_request(context, body))
    verkey = json.loads(resp.body)["verkey"]

    cert_pem = _self_sign_cert_for_verkey(verkey).decode()
    bind = await kmslite_routes.bind_kms_did_certificate(
        _make_request(
            context,
            body={"cert_pem": cert_pem},
            match_info={"did": "did:web:cert.example.com"},
        )
    )
    assert json.loads(bind.body)["cert_pem"] == cert_pem

    # Now the get-certificate route returns it.
    got = await kmslite_routes.get_kms_did_certificate(
        _make_request(context, match_info={"did": "did:web:cert.example.com"})
    )
    assert json.loads(got.body)["cert_pem"] == cert_pem


@pytest.mark.asyncio
async def test_bind_certificate_rejects_spki_mismatch(context, fake_signer):
    # Create two DIDs; bind DID-B's cert to DID-A → should 400.
    a_body = {
        "method": "web",
        "key_type": "p256",
        "options": {"did": "did:web:a.example.com", "key_ref": "a"},
    }
    b_body = {
        "method": "web",
        "key_type": "p256",
        "options": {"did": "did:web:b.example.com", "key_ref": "b"},
    }
    await kmslite_routes.create_kms_did(_make_request(context, a_body))
    b_resp = await kmslite_routes.create_kms_did(_make_request(context, b_body))
    b_verkey = json.loads(b_resp.body)["verkey"]

    cert_pem = _self_sign_cert_for_verkey(b_verkey).decode()
    with pytest.raises(web.HTTPBadRequest):
        await kmslite_routes.bind_kms_did_certificate(
            _make_request(
                context,
                body={"cert_pem": cert_pem},
                match_info={"did": "did:web:a.example.com"},
            )
        )


@pytest.mark.asyncio
async def test_get_certificate_404_when_not_bound(context, fake_signer):
    body = {
        "method": "web",
        "key_type": "p256",
        "options": {"did": "did:web:nocert.example.com", "key_ref": "nc-01"},
    }
    await kmslite_routes.create_kms_did(_make_request(context, body))
    with pytest.raises(web.HTTPNotFound):
        await kmslite_routes.get_kms_did_certificate(
            _make_request(context, match_info={"did": "did:web:nocert.example.com"})
        )


# --------------------------------------------------------------------- registration


@pytest.mark.asyncio
async def test_register_installs_five_routes():
    app = web.Application()
    await kmslite_routes.register(app)
    # Filter kmslite routes (path prefix).
    kms_routes = [
        r for r in app.router.routes()
        if str(r.resource) and "/kmslite/did" in str(r.resource)
    ]
    assert len(kms_routes) == 5
