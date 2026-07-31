"""Test fixtures for kmslite route tests.

Uses `create_test_profile` for a real in-memory Askar profile, wires a
`SignerRegistry` with a fake in-process `Signer` that delegates signing to a
real aries-askar Key. This lets us exercise the full dispatch path
(HTTP → wallet.sign_message → BaseWallet.sign_message → SignerRegistry →
fake signer) end-to-end without an HSM.
"""

from typing import Dict

import pytest
from aries_askar import Key, KeyAlg

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.did_method import DIDMethods
from acapy_agent.wallet.key_type import KeyTypes, P256, KeyType
from acapy_agent.wallet.signer_registry import Signer, SignerRegistry
from acapy_agent.wallet.util import bytes_to_b58


class FakeInProcessSigner(Signer):
    """Signer that "holds" keys in-process for testing dispatch.

    A real signer forwards to an HSM; this one just stores askar `Key`
    objects keyed by `key_ref` and delegates signing to them. From ACA-Py's
    perspective the dispatch is indistinguishable from a real HSM signer.
    """

    def __init__(self) -> None:
        self._keys: Dict[str, Key] = {}

    def generate_and_store(self, key_ref: str, key_type: KeyType) -> str:
        """Create a fresh key and register it under `key_ref`; return verkey."""
        if key_type is not P256:
            raise ValueError(f"FakeInProcessSigner: unsupported key_type {key_type}")
        askar_key = Key.generate(KeyAlg.P256)
        self._keys[key_ref] = askar_key
        return bytes_to_b58(askar_key.get_public_bytes())

    # ---- Signer protocol methods (called by the wallet's dispatch) ----

    async def generate_keypair(self, key_ref: str, key_type: KeyType) -> str:
        """Called by the create-DID route via `signer.generate_keypair(...)`."""
        return self.generate_and_store(key_ref, key_type)

    async def sign(self, key_ref: str, message: bytes, key_type: KeyType) -> bytes:
        """Called by the wallet's base-class dispatch."""
        askar_key = self._keys[key_ref]
        return askar_key.sign_message(message)


@pytest.fixture
async def fake_signer():
    yield FakeInProcessSigner()


@pytest.fixture(autouse=True)
def _kmslite_env(monkeypatch):
    """Provide minimal kmslite env config for route tests.

    The signer itself is wired manually via `fake_signer` in the `profile`
    fixture; the env vars just make `KmsLiteConfig.from_settings` return a
    valid config so `_get_config()` in routes doesn't raise 503.
    """
    # First clear anything that might leak in from the host env.
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
    monkeypatch.setenv("KMSLITE_PROVIDER", "hsm")
    monkeypatch.setenv("KMSLITE_PROTOCOL", "pkcs11")
    monkeypatch.setenv("KMSLITE_PKCS11_LIBRARY_PATH", "/does/not/matter")
    monkeypatch.setenv("KMSLITE_PKCS11_TOKEN_NAME", "test")
    monkeypatch.setenv("KMSLITE_PKCS11_PIN", "test-pin")


@pytest.fixture
async def profile(fake_signer):
    """In-memory profile with SignerRegistry pre-wired (config comes from env)."""
    prof = await create_test_profile(
        {
            "wallet.type": "askar",
            "admin.admin_insecure_mode": True,
        }
    )
    prof.context.injector.bind_instance(DIDMethods, DIDMethods())
    prof.context.injector.bind_instance(KeyTypes, KeyTypes())
    registry = SignerRegistry()
    registry.register("hsm", fake_signer)
    prof.context.injector.bind_instance(SignerRegistry, registry)
    yield prof


@pytest.fixture
def context(profile) -> AdminRequestContext:
    return AdminRequestContext(profile)
