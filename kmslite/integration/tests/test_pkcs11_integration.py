"""Black-box integration tests for kmslite's signing delegation.

Scoped deliberately: only cases a unit test cannot reach are here, because the
unit suite mocks `pkcs11` and patches route registration, so it cannot observe
a real token, real Askar storage, or whether the routes are mounted at all.
Payload validation, PEM parsing and the X.509 matching rules are unit-tested.

`alice` runs the plugin configured against the BouncyHsm container; `bob` runs
the same image with kmslite unconfigured. Nothing here imports the plugin.

    docker compose up --build --exit-code-from tests
"""

import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from . import ALICE, BOB, get, post

SUBJECT = {"country": "CA", "organization": "kmslite", "cn": "kmslite.example.com"}


def _create_did(agent: str = ALICE, key_ref: str = None):
    return post(
        agent,
        "/kmslite/did/create",
        json={
            "method": "key",
            "key_type": "p256",
            "options": {"key_ref": key_ref or f"kmslite-int-{uuid.uuid4()}"},
        },
    )


def _public_key(did: str) -> ec.EllipticCurvePublicKey:
    resp = get(ALICE, f"/kmslite/did/{did}/public-key")
    assert resp.ok, resp.content
    return serialization.load_pem_public_key(resp.json()["public_key_pem"].encode())


def _csr(did: str) -> x509.CertificateSigningRequest:
    resp = post(ALICE, f"/kmslite/did/{did}/csr", json={"subject": SUBJECT})
    assert resp.ok, resp.content
    return x509.load_pem_x509_csr(resp.json()["csr_pem"].encode())


@pytest.fixture(scope="session")
def hsm_did() -> dict:
    """One HSM-backed did:key, shared by the read-only tests."""
    resp = _create_did()
    assert resp.ok, resp.content
    return resp.json()


def test_hsm_did_is_stored_as_an_ordinary_wallet_did(hsm_did):
    """Public-only Askar entry plus store_did, not a kmslite-private record."""
    resp = get(ALICE, "/wallet/did", params={"did": hsm_did["did"]})
    assert resp.ok, resp.content
    assert [d["did"] for d in resp.json()["results"]] == [hsm_did["did"]]
    assert hsm_did["metadata"]["signer"] == "bouncyhsm"


def test_duplicate_key_ref_is_rejected_by_the_token(hsm_did):
    """Uniqueness is the token's answer, not our pre-check against a mock."""
    resp = _create_did(key_ref=hsm_did["metadata"]["key_ref"])
    assert resp.status_code == 400, resp.content


def test_csr_is_signed_by_the_hsm_held_key(hsm_did):
    """Signing reached the HSM and our SEC1/DER codecs match a real module.

    The proof-of-possession verifies against the CSR's own public key, which
    is the key the HSM generated; no other party can produce that signature.
    """
    csr = _csr(hsm_did["did"])
    assert csr.is_signature_valid
    assert (
        csr.public_key().public_numbers() == _public_key(hsm_did["did"]).public_numbers()
    )
    assert (
        csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        == (SUBJECT["cn"])
    )


def test_software_did_still_signs_in_wallet():
    """The other half of delegation: no signer marker, so Askar must sign."""
    created = post(
        ALICE,
        "/wallet/did/create",
        json={"method": "key", "options": {"key_type": "p256"}},
    )
    assert created.ok, created.content
    result = created.json()["result"]
    assert "signer" not in (result.get("metadata") or {})

    csr = _csr(result["did"])
    assert csr.is_signature_valid
    assert (
        csr.public_key().public_numbers() == _public_key(result["did"]).public_numbers()
    )


def test_routes_are_mounted_but_unavailable_when_unconfigured():
    """bob loads the plugin without signer config: mounted, but 503."""
    assert _create_did(agent=BOB).status_code == 503
