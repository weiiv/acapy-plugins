import json
from datetime import timedelta

import pytest
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.key_type import KeyTypes
from acapy_agent.wallet.keys.manager import MultikeyManager
from aries_askar import Key, KeyAlg
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mso_mdoc.cred_processor import MsoMdocCredProcessor
from oid4vc.cred_processor import CredProcessorError
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult
from x509_certs import X509CertificateRecord, X509TrustAnchorRecord
from x509_certs.certs import describe, to_pem, to_x5c
from x509_certs.tests.conftest import NOW, wallet_public_key

DOCTYPE = "org.example.doc"
MDL_DS_EKU = "1.0.18013.5.1.2"


@pytest.fixture
async def profile():
    profile = await create_test_profile()
    profile.context.injector.bind_instance(KeyTypes, KeyTypes())
    yield profile


@pytest.fixture
def context(profile):
    yield AdminRequestContext(profile)


@pytest.fixture
async def multikey(profile) -> str:
    async with profile.session() as session:
        return (await MultikeyManager(session).create(alg="p256"))["multikey"]


@pytest.fixture
def iaca():
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        _iso_builder("Test IACA", key.public_key(), NOW + timedelta(days=3650))
        .issuer_name(_name("Test IACA"))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_key_usage(key_cert_sign=True, crl_sign=True), critical=True)
    )
    return key, builder.sign(key, hashes.SHA256())


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _key_usage(**flags) -> x509.KeyUsage:
    names = (
        "digital_signature content_commitment key_encipherment data_encipherment "
        "key_agreement key_cert_sign crl_sign encipher_only decipher_only"
    ).split()
    return x509.KeyUsage(**{n: flags.get(n, False) for n in names})


def _iso_builder(cn: str, public_key, not_after) -> x509.CertificateBuilder:
    """Builder with extensions isomdl requires on a DS certificate (also used for IACA)."""
    return (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )
        .add_extension(
            x509.IssuerAlternativeName(
                [x509.UniformResourceIdentifier("https://iaca.example.com")]
            ),
            critical=False,
        )
        .add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        [x509.UniformResourceIdentifier("https://iaca.example.com/crl")],
                        None,
                        None,
                        None,
                    )
                ]
            ),
            critical=False,
        )
    )


async def _store_ds_certificate(profile, multikey, iaca, days: int):
    iaca_key, iaca_cert = iaca
    ds = (
        _iso_builder("Test DS", wallet_public_key(multikey), NOW + timedelta(days=days))
        .issuer_name(iaca_cert.subject)
        .add_extension(_key_usage(digital_signature=True), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier(MDL_DS_EKU)]), critical=True
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(iaca_key.public_key()),
            critical=False,
        )
        .sign(iaca_key, hashes.SHA256())
    )
    async with profile.session() as session:
        await X509CertificateRecord(
            multikey=multikey,
            purpose="mdoc_ds",
            x5c=to_x5c([ds, iaca_cert]),
            **describe(ds),
        ).save(session)


async def _store_anchor(profile, iaca, purpose: str):
    _, iaca_cert = iaca
    async with profile.session() as session:
        await X509TrustAnchorRecord(
            purpose=purpose,
            certificate_pem=to_pem(iaca_cert),
            **{
                k: v
                for k, v in describe(iaca_cert).items()
                if k in ("subject", "not_after")
            },
        ).save(session)


def _supported() -> SupportedCredential:
    return SupportedCredential(format="mso_mdoc", format_data={"doctype": DOCTYPE})


def _exchange(multikey) -> OID4VCIExchangeRecord:
    return OID4VCIExchangeRecord(
        state=OID4VCIExchangeRecord.STATE_OFFER_CREATED,
        supported_cred_id="456",
        credential_subject={"name": "alice"},
        signing_multikey=multikey,
    )


def _pop(holder_jwk=True) -> PopResult:
    jwk = json.loads(Key.generate(KeyAlg.P256).get_jwk_public()) if holder_jwk else None
    return PopResult(
        headers=None, payload=None, verified=True, holder_kid=None, holder_jwk=jwk
    )


@pytest.mark.asyncio
async def test_issue_and_verify(context, profile, multikey, iaca):
    await _store_ds_certificate(profile, multikey, iaca, days=60)
    await _store_anchor(profile, iaca, "iaca")
    processor = MsoMdocCredProcessor()

    mdoc = await processor.issue({}, _supported(), _exchange(multikey), _pop(), context)

    result = await processor.verify_credential(profile, mdoc)
    assert result.verified, result.payload


@pytest.mark.asyncio
async def test_verify_ignores_non_iaca_anchors(context, profile, multikey, iaca):
    await _store_ds_certificate(profile, multikey, iaca, days=60)
    await _store_anchor(profile, iaca, "sd_jwt_vc_ca")
    processor = MsoMdocCredProcessor()

    mdoc = await processor.issue({}, _supported(), _exchange(multikey), _pop(), context)

    result = await processor.verify_credential(profile, mdoc)
    assert not result.verified


@pytest.mark.asyncio
async def test_issue_needs_certificate_covering_mso_validity(
    context, profile, multikey, iaca
):
    # isomdl makes the MSO valid for 30 days.
    await _store_ds_certificate(profile, multikey, iaca, days=10)

    with pytest.raises(CredProcessorError, match="No mdoc_ds certificate"):
        await MsoMdocCredProcessor().issue(
            {}, _supported(), _exchange(multikey), _pop(), context
        )


@pytest.mark.asyncio
async def test_issue_requires_signing_multikey(context):
    with pytest.raises(CredProcessorError, match="requires signing_multikey"):
        await MsoMdocCredProcessor().issue(
            {}, _supported(), _exchange(None), _pop(), context
        )


@pytest.mark.asyncio
async def test_issue_requires_device_key(context, multikey):
    with pytest.raises(CredProcessorError, match="No device key available"):
        await MsoMdocCredProcessor().issue(
            {}, _supported(), _exchange(multikey), _pop(holder_jwk=False), context
        )
