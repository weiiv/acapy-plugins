"""Tests for pkcs11_signer setup()."""

from unittest.mock import MagicMock, patch

import pytest

from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.event_bus import EventBus
from acapy_agent.core.plugin_registry import PluginRegistry
from acapy_agent.wallet.signer_registry import SignerRegistry

from pkcs11_signer import setup
from pkcs11_signer.signer import PKCS11Signer

from .test_config import ENV_VARS


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def _configure_env(monkeypatch, provider=None):
    if provider:
        monkeypatch.setenv("PKCS11_PROVIDER", provider)
    monkeypatch.setenv("PKCS11_LIBRARY_PATH", "/fake/lib.so")
    monkeypatch.setenv("PKCS11_TOKEN_NAME", "test")
    monkeypatch.setenv("PKCS11_PIN", "1234")
    monkeypatch.setenv("PKCS11_POOL_SIZE", "2")


def _mock_pkcs11(pkcs11_mod):
    token = MagicMock()
    token.label = "test"
    token.slot.slot_id = 0
    token.open.side_effect = [MagicMock() for _ in range(2)]
    pkcs11_mod.lib.return_value.get_tokens.return_value = iter([token])


async def test_plugin_registry_loads_signer(monkeypatch):
    _configure_env(monkeypatch, provider="hsm")
    ctx = InjectionContext(settings={})
    ctx.injector.bind_instance(EventBus, EventBus())
    plugins = PluginRegistry()
    assert plugins.register_plugin("pkcs11_signer") is not None

    with patch("pkcs11_signer.signer.pkcs11") as pkcs11_mod:
        _mock_pkcs11(pkcs11_mod)
        await plugins.init_context(ctx)

    assert isinstance(ctx.inject(SignerRegistry).get("hsm"), PKCS11Signer)


async def test_not_configured_binds_empty_registry(caplog):
    ctx = InjectionContext(settings={})
    await setup(ctx)

    assert ctx.inject(SignerRegistry).names() == []
    assert "not configured" in caplog.text


@pytest.mark.parametrize(("provider", "expected"), [(None, "pkcs11"), ("hsm", "hsm")])
async def test_registers_signer_under_provider(monkeypatch, provider, expected):
    _configure_env(monkeypatch, provider)
    ctx = InjectionContext(settings={})

    with patch("pkcs11_signer.signer.pkcs11") as pkcs11_mod:
        _mock_pkcs11(pkcs11_mod)
        await setup(ctx)

    registry = ctx.inject(SignerRegistry)
    assert registry.names() == [expected]
    assert isinstance(registry.get(expected), PKCS11Signer)


async def test_reuses_existing_registry(monkeypatch):
    _configure_env(monkeypatch)
    ctx = InjectionContext(settings={})
    existing = SignerRegistry()
    existing.register("other", MagicMock())
    ctx.injector.bind_instance(SignerRegistry, existing)

    with patch("pkcs11_signer.signer.pkcs11") as pkcs11_mod:
        _mock_pkcs11(pkcs11_mod)
        await setup(ctx)

    assert ctx.inject(SignerRegistry) is existing
    assert sorted(existing.names()) == ["other", "pkcs11"]


async def test_invalid_config_logged_and_no_signer(monkeypatch, caplog):
    monkeypatch.setenv("PKCS11_LIBRARY_PATH", "/x")
    monkeypatch.setenv("PKCS11_TOKEN_NAME", "t")
    ctx = InjectionContext(settings={})

    await setup(ctx)

    assert ctx.inject(SignerRegistry).names() == []
    assert "invalid config" in caplog.text
    assert "PKCS11_PIN" in caplog.text


async def test_token_open_failure_logged_and_no_signer(monkeypatch, caplog):
    _configure_env(monkeypatch)
    ctx = InjectionContext(settings={})

    with patch("pkcs11_signer.signer.pkcs11") as pkcs11_mod:
        pkcs11_mod.lib.side_effect = RuntimeError("cannot load library")
        await setup(ctx)

    assert ctx.inject(SignerRegistry).names() == []
    assert "could not open token" in caplog.text
