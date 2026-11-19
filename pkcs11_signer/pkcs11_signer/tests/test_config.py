"""Tests for Pkcs11Config (plugin_config wins; env is fallback)."""

import pytest

from pkcs11_signer.config import (
    DEFAULT_POOL_SIZE,
    DEFAULT_PROVIDER,
    ConfigError,
    Pkcs11Config,
)

ENV_VARS = [
    "PKCS11_PROVIDER",
    "PKCS11_LIBRARY_PATH",
    "PKCS11_TOKEN_NAME",
    "PKCS11_PIN",
    "PKCS11_SLOT",
    "PKCS11_POOL_SIZE",
]


class _FakeSettings:
    """Stand-in for acapy_agent.config.settings.Settings.for_plugin()."""

    def __init__(self, plugin_config: dict):
        self._plugin_config = plugin_config

    def for_plugin(self, name: str):
        return self._plugin_config.get(name, {})


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def _settings(**pkcs11):
    return _FakeSettings({"pkcs11": pkcs11})


def test_returns_none_when_not_configured():
    assert Pkcs11Config.from_settings(_FakeSettings({})) is None


def test_settings_without_for_plugin_treated_as_empty():
    assert Pkcs11Config.from_settings(object()) is None


def test_env_only(monkeypatch):
    monkeypatch.setenv("PKCS11_LIBRARY_PATH", "/opt/lib.so")
    monkeypatch.setenv("PKCS11_TOKEN_NAME", "dev")
    monkeypatch.setenv("PKCS11_PIN", "1234")

    cfg = Pkcs11Config.from_settings(_FakeSettings({}))
    assert cfg == Pkcs11Config(
        provider=DEFAULT_PROVIDER,
        library_path="/opt/lib.so",
        token_name="dev",
        pin="1234",
        slot=None,
        pool_size=DEFAULT_POOL_SIZE,
    )


def test_env_provider_slot_and_pool_size(monkeypatch):
    monkeypatch.setenv("PKCS11_PROVIDER", "hsm")
    monkeypatch.setenv("PKCS11_LIBRARY_PATH", "/opt/lib.so")
    monkeypatch.setenv("PKCS11_TOKEN_NAME", "dev")
    monkeypatch.setenv("PKCS11_PIN", "1234")
    monkeypatch.setenv("PKCS11_POOL_SIZE", "8")
    monkeypatch.setenv("PKCS11_SLOT", "2")

    cfg = Pkcs11Config.from_settings(_FakeSettings({}))
    assert cfg.provider == "hsm"
    assert cfg.pool_size == 8
    assert cfg.slot == 2


def test_plugin_config_with_pin_env_indirection(monkeypatch):
    monkeypatch.setenv("MY_HSM_PIN", "shh-secret")
    cfg = Pkcs11Config.from_settings(
        _settings(
            provider="hsm",
            library_path="/opt/lib.so",
            token_name="dev",
            pin_env="MY_HSM_PIN",
            pool_size=2,
            slot=0,
        )
    )
    assert cfg.provider == "hsm"
    assert cfg.pin == "shh-secret"
    assert cfg.pool_size == 2
    assert cfg.slot == 0


def test_plugin_config_wins_over_env(monkeypatch):
    monkeypatch.setenv("PKCS11_PROVIDER", "env-provider")
    monkeypatch.setenv("PKCS11_TOKEN_NAME", "env-token")
    monkeypatch.setenv("PKCS11_PIN", "env-pin")
    monkeypatch.setenv("PKCS11_POOL_SIZE", "999")
    cfg = Pkcs11Config.from_settings(
        _settings(
            provider="plugin-provider",
            library_path="/opt/lib.so",
            token_name="plugin-token",
            pool_size=3,
        )
    )
    assert cfg.provider == "plugin-provider"
    assert cfg.token_name == "plugin-token"
    assert cfg.pool_size == 3
    assert cfg.pin == "env-pin"


def test_pin_env_names_missing_var_raises(monkeypatch):
    monkeypatch.setenv("PKCS11_PIN", "ignored-when-pin_env-set")
    with pytest.raises(ConfigError, match="NOT_SET_PKCS11_TEST_VAR"):
        Pkcs11Config.from_settings(
            _settings(
                library_path="/x", token_name="t", pin_env="NOT_SET_PKCS11_TEST_VAR"
            )
        )


def test_missing_library_path_raises(monkeypatch):
    monkeypatch.setenv("PKCS11_PIN", "p")
    with pytest.raises(ConfigError, match="library_path"):
        Pkcs11Config.from_settings(_settings(token_name="t"))


def test_missing_token_name_raises(monkeypatch):
    monkeypatch.setenv("PKCS11_PIN", "p")
    with pytest.raises(ConfigError, match="token_name"):
        Pkcs11Config.from_settings(_settings(library_path="/x"))


def test_missing_pin_raises():
    with pytest.raises(ConfigError, match="PKCS11_PIN"):
        Pkcs11Config.from_settings(_settings(library_path="/x", token_name="t"))


@pytest.mark.parametrize(
    ("field", "value"),
    [("pool_size", "many"), ("pool_size", 0), ("slot", "first")],
)
def test_invalid_int_fields_raise(monkeypatch, field, value):
    monkeypatch.setenv("PKCS11_PIN", "p")
    with pytest.raises(ConfigError, match=field):
        Pkcs11Config.from_settings(
            _settings(library_path="/x", token_name="t", **{field: value})
        )


def test_config_error_message_format():
    msg = str(ConfigError("token_name", "PKCS11_TOKEN_NAME"))
    assert "pkcs11_signer plugin" in msg
    assert "pkcs11.token_name" in msg
    assert "PKCS11_TOKEN_NAME" in msg
