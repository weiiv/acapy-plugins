"""PKCS#11 signer for the kmslite plugin (P-256 only today)."""

import asyncio
import hashlib
import logging
from contextlib import asynccontextmanager, contextmanager
from typing import Any, Mapping, Optional

import pkcs11
from pkcs11 import Attribute, KeyType as P11KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import PKCS11Error
from pkcs11.util.ec import encode_named_curve_parameters

from acapy_agent.wallet.error import WalletError
from acapy_agent.wallet.key_type import P256, KeyType
from acapy_agent.wallet.util import bytes_to_b58

LOGGER = logging.getLogger(__name__)
AUDIT = logging.getLogger("kmslite.audit")

_OCTET_STRING_TAG = 0x04
_CURVE_OID_BY_KEY_TYPE = {P256: "secp256r1"}


def _unwrap_ec_point(der: bytes) -> bytes:
    """DER OCTET STRING → raw SEC1 point (short-form length only)."""
    if len(der) < 2 or der[0] != _OCTET_STRING_TAG:
        raise WalletError("PKCS11 EC_POINT: not a DER OCTET STRING")
    length = der[1]
    if length & 0x80 or length != len(der) - 2:
        raise WalletError("PKCS11 EC_POINT: unexpected DER length encoding")
    return der[2:]


def _sec1_compress(point: bytes) -> bytes:
    """Compress an uncompressed SEC1 point; pass through if already compressed."""
    if not point:
        raise WalletError("PKCS11 EC_POINT: empty")
    prefix = point[0]
    if prefix in (0x02, 0x03):
        return point
    if prefix != 0x04 or (len(point) - 1) % 2:
        raise WalletError(f"PKCS11 EC_POINT: bad prefix/length 0x{prefix:02x}")
    n = (len(point) - 1) // 2
    x, y = point[1 : 1 + n], point[1 + n :]
    return bytes([0x03 if (y[-1] & 1) else 0x02]) + x


def _der_point_to_verkey(der: bytes) -> str:
    """PKCS#11 DER-wrapped EC point → base58(SEC1-compressed) verkey string."""
    return bytes_to_b58(_sec1_compress(_unwrap_ec_point(der)))


@contextmanager
def _wrap_pkcs11_errors(op: str, key_ref: str):
    """Rethrow pkcs11 errors as WalletError with op-labeled messages."""
    try:
        yield
    except pkcs11.NoSuchKey as err:
        raise WalletError(f"PKCS11 {op}: no key on token with label {key_ref!r}") from err
    except pkcs11.MultipleObjectsReturned as err:
        raise WalletError(
            f"PKCS11 {op}: key_ref {key_ref!r} is ambiguous on the token"
        ) from err
    except PKCS11Error as err:
        raise WalletError(f"PKCS11 {op}: {err}") from err


class PKCS11Signer:
    """Signer backed by a PKCS#11 token; one authenticated session per op."""

    def __init__(
        self,
        lib_path: str,
        token_label: str,
        pin: str,
        slot: Optional[int] = None,
        pool_size: int = 4,
        provider_name: str = "hsm",
    ) -> None:
        if pool_size < 1:
            raise ValueError("pool_size must be >= 1")
        self._provider_name = provider_name
        self._lib = pkcs11.lib(lib_path)
        self._token = self._lib.get_token(token_label=token_label)
        self._pool: "asyncio.Queue[Any]" = asyncio.Queue(maxsize=pool_size)
        for _ in range(pool_size):
            self._pool.put_nowait(self._token.open(user_pin=pin, rw=True))
        LOGGER.info("PKCS11Signer: token=%r pool_size=%d", token_label, pool_size)

    @classmethod
    def from_config(
        cls, cfg: Mapping[str, Any], provider_name: str = "hsm"
    ) -> "PKCS11Signer":
        """Instantiate from a resolved config dict (see KmsLiteConfig)."""
        try:
            return cls(
                lib_path=cfg["library_path"],
                token_label=cfg["token_name"],
                pin=cfg["pin"],
                slot=cfg.get("slot"),
                pool_size=int(cfg.get("pool_size", 4)),
                provider_name=provider_name,
            )
        except KeyError as err:
            raise ValueError(
                f"kmslite.pkcs11: missing required key {err.args[0]!r}"
            ) from None

    @asynccontextmanager
    async def _session(self):
        session = await self._pool.get()
        try:
            yield session
        finally:
            self._pool.put_nowait(session)

    def _audit(self, event: str, key_ref: str, key_type: KeyType, **extra) -> None:
        AUDIT.info(
            "kmslite %s",
            event,
            extra={
                "event": event,
                "provider": self._provider_name,
                "key_ref": key_ref,
                "key_type": key_type.key_type,
                **extra,
            },
        )

    def _check_key_type(self, key_type: KeyType) -> str:
        curve = _CURVE_OID_BY_KEY_TYPE.get(key_type)
        if curve is None:
            raise WalletError(f"PKCS11Signer: unsupported key_type {key_type}")
        return curve

    # ---- Signer protocol ----

    async def generate_keypair(self, key_ref: str, key_type: KeyType) -> str:
        curve_name = self._check_key_type(key_type)
        async with self._session() as session:
            # Real HSMs enforce CKA_LABEL uniqueness; simulators (BouncyHsm)
            # don't, so we pre-check.
            with _wrap_pkcs11_errors("generate_keypair", key_ref):
                await asyncio.to_thread(
                    self._assert_key_ref_free_sync, session, key_ref
                )
                der = await asyncio.to_thread(
                    self._create_keypair_sync, session, key_ref, curve_name
                )
        verkey = _der_point_to_verkey(der)
        self._audit("generate_keypair", key_ref, key_type)
        return verkey

    async def get_public_key(self, key_ref: str, key_type: KeyType) -> str:
        self._check_key_type(key_type)
        async with self._session() as session:
            with _wrap_pkcs11_errors("get_public_key", key_ref):
                der = await asyncio.to_thread(
                    self._read_public_point_sync, session, key_ref
                )
        return _der_point_to_verkey(der)

    async def sign(
        self, key_ref: str, message: bytes, key_type: KeyType
    ) -> bytes:
        self._check_key_type(key_type)
        digest = hashlib.sha256(message).digest()
        async with self._session() as session:
            with _wrap_pkcs11_errors("sign", key_ref):
                signature = await asyncio.to_thread(
                    self._sign_digest_sync, session, key_ref, digest
                )
        self._audit("sign", key_ref, key_type, message_digest=digest.hex())
        return bytes(signature)

    # ---- Blocking helpers (run inside asyncio.to_thread) ----

    def _assert_key_ref_free_sync(self, session, key_ref: str) -> None:
        try:
            session.get_key(object_class=ObjectClass.PRIVATE_KEY, label=key_ref)
        except pkcs11.NoSuchKey:
            return
        raise WalletError(
            f"PKCS11Signer: key_ref {key_ref!r} already exists on the token"
        )

    def _create_keypair_sync(
        self, session, key_ref: str, curve_name: str
    ) -> bytes:
        ec_params = encode_named_curve_parameters(curve_name)
        public_key, _ = session.generate_keypair(
            P11KeyType.EC,
            label=key_ref,
            store=True,
            mechanism=Mechanism.EC_KEY_PAIR_GEN,
            public_template={Attribute.EC_PARAMS: ec_params},
            private_template={
                Attribute.SENSITIVE: True,
                Attribute.EXTRACTABLE: False,
                Attribute.SIGN: True,
            },
        )
        return bytes(public_key[Attribute.EC_POINT])

    def _read_public_point_sync(self, session, key_ref: str) -> bytes:
        pub = session.get_key(object_class=ObjectClass.PUBLIC_KEY, label=key_ref)
        return bytes(pub[Attribute.EC_POINT])

    def _sign_digest_sync(self, session, key_ref: str, digest: bytes) -> bytes:
        priv = session.get_key(object_class=ObjectClass.PRIVATE_KEY, label=key_ref)
        return priv.sign(digest, mechanism=Mechanism.ECDSA)
