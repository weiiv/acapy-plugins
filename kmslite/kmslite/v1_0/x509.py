"""X.509 helpers: CSR building + verkey-to-cert matching for kmslite."""

import asyncio
from typing import Optional

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding
from cryptography.x509.oid import NameOID

from acapy_agent.wallet.error import WalletError
from acapy_agent.wallet.key_type import KeyType, P256
from acapy_agent.wallet.util import b58_to_bytes

_CURVE_BY_KEY_TYPE = {P256: ec.SECP256R1}

# Field-name → x509 NameOID for CSR subject building.
_SUBJECT_FIELDS = {
    "country": NameOID.COUNTRY_NAME,
    "state": NameOID.STATE_OR_PROVINCE_NAME,
    "locality": NameOID.LOCALITY_NAME,
    "organization": NameOID.ORGANIZATION_NAME,
    "organizational_unit": NameOID.ORGANIZATIONAL_UNIT_NAME,
}


def _curve_for(key_type: KeyType) -> ec.EllipticCurve:
    cls = _CURVE_BY_KEY_TYPE.get(key_type)
    if cls is None:
        raise WalletError(
            f"unsupported key_type {key_type} "
            f"(supported: {list(_CURVE_BY_KEY_TYPE)})"
        )
    return cls()


def _hash_alg_for(key_type: KeyType) -> hashes.HashAlgorithm:
    if key_type is P256:
        return hashes.SHA256()
    raise WalletError(f"no hash paired with key_type {key_type}")


def verkey_to_public_key(
    verkey: str, key_type: KeyType
) -> ec.EllipticCurvePublicKey:
    """Rebuild an EllipticCurvePublicKey from a base58 verkey."""
    return ec.EllipticCurvePublicKey.from_encoded_point(
        _curve_for(key_type), b58_to_bytes(verkey)
    )


class WalletBackedPrivateKey(EllipticCurvePrivateKey):
    """EllipticCurvePrivateKey adapter that signs via `wallet.sign_message`.

    Lets `cryptography.x509` builders drive an HSM- or software-backed key
    uniformly. Builders call `.sign()` synchronously; we bridge back to the
    async wallet via `run_coroutine_threadsafe` on the captured loop, so
    callers must run the builder off the event loop (e.g. `asyncio.to_thread`).
    """

    def __init__(
        self,
        wallet,
        verkey: str,
        key_type: KeyType,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self._wallet = wallet
        self._verkey = verkey
        self._curve = _curve_for(key_type)
        self._loop = loop or asyncio.get_event_loop()
        self._public_key = verkey_to_public_key(verkey, key_type)

    @property
    def curve(self) -> ec.EllipticCurve:
        return self._curve

    @property
    def key_size(self) -> int:
        return self._public_key.key_size

    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self._public_key

    def sign(self, data: bytes, signature_algorithm) -> bytes:
        # sign_message returns raw r||s; cryptography.x509 wants DER SEQUENCE.
        fut = asyncio.run_coroutine_threadsafe(
            self._wallet.sign_message(data, self._verkey), self._loop
        )
        raw = fut.result()
        if raw is None or len(raw) % 2:
            raise WalletError(
                f"WalletBackedPrivateKey: bad signature length "
                f"({0 if raw is None else len(raw)})"
            )
        n = len(raw) // 2
        r = int.from_bytes(raw[:n], "big")
        s = int.from_bytes(raw[n:], "big")
        return utils.encode_dss_signature(r, s)

    # ABC-satisfying stubs; unused by cryptography.x509 builders.
    def exchange(self, algorithm, peer_public_key):
        raise UnsupportedAlgorithm("ECDH not supported")

    def private_numbers(self):
        raise UnsupportedAlgorithm("private material not accessible")

    def private_bytes(self, encoding, format, encryption_algorithm):
        raise UnsupportedAlgorithm("private material not accessible")

    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        raise UnsupportedAlgorithm("decrypt not supported for signer keys")

    def __copy__(self) -> "WalletBackedPrivateKey":  # noqa: D105
        return self

    def __deepcopy__(self, memo) -> "WalletBackedPrivateKey":  # noqa: D105
        return self


def _build_subject(subject: dict) -> x509.Name:
    attrs = [
        x509.NameAttribute(oid, subject[field])
        for field, oid in _SUBJECT_FIELDS.items()
        if field in subject
    ]
    cn = subject.get("cn") or subject.get("common_name")
    if cn:
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    if not attrs:
        raise WalletError("subject must contain at least one field")
    return x509.Name(attrs)


def _build_csr_sync(
    private_key: WalletBackedPrivateKey, subject: dict, key_type: KeyType
) -> bytes:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(_build_subject(subject))
        .sign(private_key, _hash_alg_for(key_type))
    )
    return csr.public_bytes(serialization.Encoding.PEM)


async def build_csr(
    wallet, verkey: str, key_type: KeyType, subject: dict
) -> bytes:
    """PEM-encoded CSR whose subject public key is `verkey`; signed via wallet."""
    loop = asyncio.get_running_loop()
    adapter = WalletBackedPrivateKey(wallet, verkey, key_type, loop=loop)
    return await asyncio.to_thread(_build_csr_sync, adapter, subject, key_type)


def assert_cert_matches_verkey(
    cert_pem: bytes, verkey: str, key_type: KeyType
) -> None:
    """Raise WalletError if the cert's SPKI doesn't match `verkey`."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except ValueError as err:
        raise WalletError(f"invalid certificate PEM: {err}") from err

    cert_pub = cert.public_key()
    if not isinstance(cert_pub, ec.EllipticCurvePublicKey):
        raise WalletError("certificate public key is not an EC key")

    verkey_pub = verkey_to_public_key(verkey, key_type)
    if cert_pub.public_numbers() != verkey_pub.public_numbers():
        raise WalletError(
            "certificate SubjectPublicKeyInfo does not match the DID's verkey"
        )
