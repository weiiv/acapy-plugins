"""Tests for kmslite plugin setup() wiring (env-based config)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.wallet.signer_registry import SignerRegistry

from kmslite.v1_0 import PROTOCOL_IMPLEMENTATIONS, setup


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Every setup test starts with kmslite env vars unset."""
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


def _make_context() -> InjectionContext:
    from acapy_agent.admin.base_server import BaseAdminServer

    ctx = InjectionContext(settings={})
    admin = MagicMock(spec=BaseAdminServer)
    admin.app = MagicMock()
    ctx.injector.bind_instance(BaseAdminServer, admin)
    return ctx


def _configure_pkcs11_env(monkeypatch):
    """Set env vars for a valid PKCS#11 configuration."""
    monkeypatch.setenv("KMSLITE_PROVIDER", "hsm")
    monkeypatch.setenv("KMSLITE_PROTOCOL", "pkcs11")
    monkeypatch.setenv("KMSLITE_PKCS11_LIBRARY_PATH", "/fake/lib.so")
    monkeypatch.setenv("KMSLITE_PKCS11_TOKEN_NAME", "test")
    monkeypatch.setenv("KMSLITE_PKCS11_PIN", "1234")
    monkeypatch.setenv("KMSLITE_PKCS11_POOL_SIZE", "2")


@pytest.mark.asyncio
async def test_setup_without_env_config_binds_registry_but_no_signer():
    """No kmslite env vars → SignerRegistry created, empty; routes still registered."""
    ctx = _make_context()
    with patch("kmslite.v1_0.routes.register", new=AsyncMock()) as reg:
        await setup(ctx)

    registry = ctx.inject(SignerRegistry)
    assert registry.names() == []
    reg.assert_awaited_once()


@pytest.mark.asyncio
async def test_setup_registers_pkcs11_signer_when_configured_via_env(monkeypatch):
    """Full happy path: env vars set → PKCS11Signer registered."""
    _configure_pkcs11_env(monkeypatch)
    ctx = _make_context()

    with (
        patch("kmslite.v1_0.signers.pkcs11.pkcs11") as pkcs11_mod,
        patch("kmslite.v1_0.routes.register", new=AsyncMock()),
    ):
        pkcs11_mod.lib.return_value.get_token.return_value.open.side_effect = [
            MagicMock() for _ in range(2)
        ]
        await setup(ctx)

    registry = ctx.inject(SignerRegistry)
    assert registry.names() == ["hsm"]
    assert type(registry.get("hsm")).__name__ == "PKCS11Signer"


@pytest.mark.asyncio
async def test_setup_unknown_protocol_logs_but_does_not_raise(monkeypatch, caplog):
    """Unknown protocol → error logged, plugin still loads."""
    monkeypatch.setenv("KMSLITE_PROVIDER", "hsm")
    monkeypatch.setenv("KMSLITE_PROTOCOL", "ridicu-lous")
    ctx = _make_context()

    with patch("kmslite.v1_0.routes.register", new=AsyncMock()):
        await setup(ctx)

    registry = ctx.inject(SignerRegistry)
    assert registry.names() == []
    # Config raises "unknown protocol" during from_settings, caught and logged.
    assert any(
        "unknown protocol" in rec.message.lower()
        or "invalid config" in rec.message.lower()
        for rec in caplog.records
    )


@pytest.mark.asyncio
async def test_setup_missing_pin_logged(monkeypatch, caplog):
    """Provider/protocol set but PIN missing → logged, plugin loads without signer."""
    monkeypatch.setenv("KMSLITE_PROVIDER", "hsm")
    monkeypatch.setenv("KMSLITE_PROTOCOL", "pkcs11")
    monkeypatch.setenv("KMSLITE_PKCS11_LIBRARY_PATH", "/x")
    monkeypatch.setenv("KMSLITE_PKCS11_TOKEN_NAME", "t")
    # PIN not set.
    ctx = _make_context()

    with patch("kmslite.v1_0.routes.register", new=AsyncMock()):
        await setup(ctx)

    registry = ctx.inject(SignerRegistry)
    assert registry.names() == []
    assert any(
        "pin is required" in rec.message.lower()
        or "invalid config" in rec.message.lower()
        for rec in caplog.records
    )


def test_protocol_implementations_covers_pkcs11():
    assert "pkcs11" in PROTOCOL_IMPLEMENTATIONS
    from kmslite.v1_0.signers.pkcs11 import PKCS11Signer

    assert PROTOCOL_IMPLEMENTATIONS["pkcs11"] is PKCS11Signer
