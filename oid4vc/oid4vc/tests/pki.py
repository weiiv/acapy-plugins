from datetime import datetime, timedelta, timezone
from typing import Optional

from acapy_agent.wallet.keys.manager import multikey_to_verkey
from acapy_agent.wallet.util import b58_to_bytes
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NOW = datetime.now(timezone.utc).replace(microsecond=0)


def make_cert(
    cn: str,
    public_key,
    signer_key,
    issuer: Optional[x509.Certificate] = None,
    ca: bool = False,
    not_before: datetime = NOW - timedelta(days=1),
    not_after: datetime = NOW + timedelta(days=30),
) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer.subject if issuer else name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(signer_key, hashes.SHA256())
    )


class Pki:
    """Root -> intermediate CA pair that issues leaf certificates."""

    def __init__(self, name: str = "Test"):
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root = make_cert(
            f"{name} Root", self.root_key.public_key(), self.root_key, ca=True
        )
        self.int_key = ec.generate_private_key(ec.SECP256R1())
        self.intermediate = make_cert(
            f"{name} Intermediate",
            self.int_key.public_key(),
            self.root_key,
            issuer=self.root,
            ca=True,
        )

    def leaf(self, public_key, **kwargs) -> x509.Certificate:
        return make_cert(
            "Leaf", public_key, self.int_key, issuer=self.intermediate, **kwargs
        )


def wallet_public_key(multikey: str) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), b58_to_bytes(multikey_to_verkey(multikey))
    )
