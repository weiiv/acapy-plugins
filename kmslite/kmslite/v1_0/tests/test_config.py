"""Tests for KmsLiteConfig (plugin_config file wins; env is fallback).

Mirrors the pattern used by the `status_list` plugin.
"""

import pytest

from kmslite.v1_0.config import ConfigError, KmsLiteConfig


class _FakeSettings:
    """Stand-in for acapy_agent.config.settings.Settings.for_plugin()."""

    def __init__(self, plugin_config: dict):
        self._plugin_config = plugin_config

    def for_plugin(self, name: str):
        return self._plugin_config.get(name, {})


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Every test starts with kmslite env vars unset."""
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


# ------------------------------------------------------------------ not configured


def test_returns_none_when_neither_source_configures():
    assert KmsLiteConfig.from_settings(_FakeSettings({})) is None


# ------------------------------------------------------------------ env-only


def test_env_only_configures_pkcs11_signer(monkeypatch):
    monkeypatch.setenv("KMSLITE_PROVIDER", "hsm")
    monkeypatch.setenv("KMSLITE_PROTOCOL", "pkcs11")
    monkeypatch.setenv("KMSLITE_PKCS11_LIBRARY_PATH", "/opt/lib.dylib")
    monkeypatch.setenv("KMSLITE_PKCS11_TOKEN_NAME", "dev")
    monkeypatch.setenv("KMSLITE_PKCS11_PIN", "1234")

    cfg = KmsLiteConfig.from_settings(_FakeSettings({}))
    assert cfg is not None
    assert cfg.provider == "hsm"
    assert cfg.protocol == "pkcs11"
    assert cfg.protocol_cfg["library_path"] == "/opt/lib.dylib"
    assert cfg.protocol_cfg["pin"] == "1234"
    assert cfg.protocol_cfg["pool_size"] == 4  # default
    assert "slot" not in cfg.protocol_cfg


def test_env_pool_size_and_slot_coerce_to_int(monkeypatch):
    monkeypatch.setenv("KMSLITE_PROVIDER", "hsm")
    monkeypatch.setenv("KMSLITE_PROTOCOL", "pkcs11")
    monkeypatch.setenv("KMSLITE_PKCS11_LIBRARY_PATH", "/opt/lib.dylib")
    monkeypatch.setenv("KMSLITE_PKCS11_TOKEN_NAME", "dev")
    monkeypatch.setenv("KMSLITE_PKCS11_PIN", "1234")
    monkeypatch.setenv("KMSLITE_PKCS11_POOL_SIZE", "8")
    monkeypatch.setenv("KMSLITE_PKCS11_SLOT", "2")

    cfg = KmsLiteConfig.from_settings(_FakeSettings({}))
    assert cfg.protocol_cfg["pool_size"] == 8
    assert cfg.protocol_cfg["slot"] == 2


# ------------------------------------------------------------------ plugin-config only


def test_plugin_config_with_pin_env_indirection(monkeypatch):
    monkeypatch.setenv("MY_HSM_PIN", "shh-secret")
    settings = _FakeSettings(
        {
            "kmslite": {
                "provider": "hsm",
                "protocol": "pkcs11",
                "pkcs11": {
                    "library_path": "/opt/lib.dylib",
                    "token_name": "dev",
                    "pin_env": "MY_HSM_PIN",
                    "pool_size": 2,
                },
            }
        }
    )
    cfg = KmsLiteConfig.from_settings(settings)
    assert cfg.protocol_cfg["pin"] == "shh-secret"
    assert cfg.protocol_cfg["pool_size"] == 2


def test_plugin_config_pin_env_names_missing_var_raises():
    settings = _FakeSettings(
        {
            "kmslite": {
                "provider": "hsm",
                "protocol": "pkcs11",
                "pkcs11": {
                    "library_path": "/opt/lib.dylib",
                    "token_name": "dev",
                    "pin_env": "DEFINITELY_NOT_SET_KMSLITE_TEST_VAR",
                },
            }
        }
    )
    with pytest.raises(ConfigError, match="pkcs11.pin_env"):
        KmsLiteConfig.from_settings(settings)


# ------------------------------------------------------------------ plugin-config wins over env


def test_plugin_config_wins_over_env(monkeypatch):
    """Plugin-config value takes precedence over env var (matches status_list)."""
    monkeypatch.setenv("KMSLITE_PKCS11_TOKEN_NAME", "env-value")
    monkeypatch.setenv("KMSLITE_PKCS11_PIN", "env-pin")
    monkeypatch.setenv("KMSLITE_PKCS11_POOL_SIZE", "999")
    settings = _FakeSettings(
        {
            "kmslite": {
                "provider": "hsm",
                "protocol": "pkcs11",
                "pkcs11": {
                    "library_path": "/opt/lib.dylib",
                    "token_name": "plugin-value",
                    "pin_env": "KMSLITE_PKCS11_PIN",  # still uses env via indirection
                    "pool_size": 3,
                },
            }
        }
    )
    cfg = KmsLiteConfig.from_settings(settings)
    # plugin-config token_name wins
    assert cfg.protocol_cfg["token_name"] == "plugin-value"
    # plugin-config pool_size wins
    assert cfg.protocol_cfg["pool_size"] == 3
    # PIN comes via pin_env indirection (which happens to name the env var)
    assert cfg.protocol_cfg["pin"] == "env-pin"


def test_env_fills_gap_when_plugin_config_omits_field(monkeypatch):
    """A field missing from plugin-config falls back to its env var."""
    monkeypatch.setenv("KMSLITE_PKCS11_PIN", "env-pin")
    settings = _FakeSettings(
        {
            "kmslite": {
                "provider": "hsm",
                "protocol": "pkcs11",
                "pkcs11": {
                    "library_path": "/opt/lib.dylib",
                    "token_name": "dev",
                    # no pin_env, no pin — falls through to KMSLITE_PKCS11_PIN
                },
            }
        }
    )
    cfg = KmsLiteConfig.from_settings(settings)
    assert cfg.protocol_cfg["pin"] == "env-pin"


# ------------------------------------------------------------------ error cases


def test_provider_only_raises():
    settings = _FakeSettings({"kmslite": {"provider": "hsm"}})
    with pytest.raises(ConfigError, match="protocol"):
        KmsLiteConfig.from_settings(settings)


def test_unknown_protocol_raises():
    settings = _FakeSettings(
        {"kmslite": {"provider": "hsm", "protocol": "voodoo"}}
    )
    with pytest.raises(ValueError, match="unknown protocol"):
        KmsLiteConfig.from_settings(settings)


def test_missing_library_path_raises():
    settings = _FakeSettings(
        {
            "kmslite": {
                "provider": "hsm",
                "protocol": "pkcs11",
                "pkcs11": {"token_name": "t", "pin_env": "IRRELEVANT"},
            }
        }
    )
    with pytest.raises(ConfigError, match="pkcs11.library_path"):
        KmsLiteConfig.from_settings(settings)


def test_missing_token_name_raises(monkeypatch):
    monkeypatch.setenv("KMSLITE_PKCS11_PIN", "p")
    settings = _FakeSettings(
        {
            "kmslite": {
                "provider": "hsm",
                "protocol": "pkcs11",
                "pkcs11": {"library_path": "/x"},
            }
        }
    )
    with pytest.raises(ConfigError, match="pkcs11.token_name"):
        KmsLiteConfig.from_settings(settings)


def test_missing_pin_everywhere_raises():
    settings = _FakeSettings(
        {
            "kmslite": {
                "provider": "hsm",
                "protocol": "pkcs11",
                "pkcs11": {"library_path": "/x", "token_name": "t"},
            }
        }
    )
    with pytest.raises(ConfigError, match="pkcs11.pin_env"):
        KmsLiteConfig.from_settings(settings)


# ------------------------------------------------------------------ ConfigError message


def test_config_error_message_format():
    err = ConfigError("provider", "KMSLITE_PROVIDER")
    msg = str(err)
    assert "kmslite plugin" in msg
    assert "kmslite.provider" in msg
    assert "KMSLITE_PROVIDER" in msg
