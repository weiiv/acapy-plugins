import pytest
from copy import deepcopy

from acapy_agent.config.plugin_settings import PLUGIN_CONFIG_KEY
from acapy_agent.config.settings import Settings

from ..config import Config, ConfigError


@pytest.mark.asyncio
async def test_config(plugin_settings: dict):
    # Test ConfigError
    error = ConfigError("list_size", plugin_settings)
    assert error

    # Test success
    config = Config.from_settings(Settings(plugin_settings))
    assert config

    # Test missing settings
    copied_settings = deepcopy(plugin_settings)
    del copied_settings[PLUGIN_CONFIG_KEY]["status_list"]["list_size"]
    try:
        Config.from_settings(Settings(copied_settings))
    except ConfigError as error:
        assert error

    copied_settings = deepcopy(plugin_settings)
    del copied_settings[PLUGIN_CONFIG_KEY]["status_list"]["shard_size"]
    try:
        Config.from_settings(Settings(copied_settings))
    except ConfigError as error:
        assert error

    copied_settings = deepcopy(plugin_settings)
    del copied_settings[PLUGIN_CONFIG_KEY]["status_list"]["public_uri"]
    try:
        Config.from_settings(Settings(copied_settings))
    except ConfigError as error:
        assert error

    copied_settings = deepcopy(plugin_settings)
    del copied_settings[PLUGIN_CONFIG_KEY]["status_list"]["file_path"]
    config = Config.from_settings(Settings(copied_settings))
    assert config.file_path is None


@pytest.mark.parametrize(
    ("value", "expected"), [(None, 180), ("30", 30), ("0", None), ("x", None)]
)
def test_token_validity_days(plugin_settings: dict, monkeypatch, value, expected):
    monkeypatch.delenv("STATUS_LIST_TOKEN_VALIDITY_DAYS", raising=False)
    settings = deepcopy(plugin_settings)
    if value is not None:
        settings[PLUGIN_CONFIG_KEY]["status_list"]["token_validity_days"] = value
    if expected is None:
        with pytest.raises(ConfigError, match="token_validity_days"):
            Config.from_settings(Settings(settings))
    else:
        assert Config.from_settings(Settings(settings)).token_validity_days == expected


@pytest.mark.parametrize(
    ("setting", "env_var"),
    [
        ("list_size", "STATUS_LIST_SIZE"),
        ("shard_size", "STATUS_LIST_SHARD_SIZE"),
        ("token_validity_days", "STATUS_LIST_TOKEN_VALIDITY_DAYS"),
    ],
)
def test_integer_zero_config_values_are_rejected(
    plugin_settings: dict, monkeypatch, setting, env_var
):
    monkeypatch.delenv(env_var, raising=False)
    settings = deepcopy(plugin_settings)
    settings[PLUGIN_CONFIG_KEY]["status_list"][setting] = 0

    with pytest.raises(ConfigError, match=setting):
        Config.from_settings(Settings(settings))
