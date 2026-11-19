"""Retrieve configuration values."""

from dataclasses import dataclass
from os import getenv
from typing import Optional

from acapy_agent.config.base import BaseSettings
from acapy_agent.config.settings import Settings

DEFAULT_LIST_SIZE = 131072
DEFAULT_SHARD_SIZE = 16384
DEFAULT_TOKEN_VALIDITY_DAYS = 180


class ConfigError(ValueError):
    """Base class for configuration errors."""

    def __init__(self, var: str, env: str):
        """Initialize a ConfigError."""
        super().__init__(
            (
                f"Invalid {var} specified for Status List plugin; "
                f"use either status_list.{var} plugin config value "
                f"or environment variable {env}"
            )
        )


@dataclass
class Config:
    """Configuration for Bitstring Plugin."""

    list_size: int
    shard_size: int
    public_uri: str
    file_path: Optional[str]
    token_validity_days: int = DEFAULT_TOKEN_VALIDITY_DAYS

    @classmethod
    def from_settings(cls, settings: BaseSettings) -> "Config":
        """Retrieve configuration from context."""

        assert isinstance(settings, Settings)
        plugin_settings = settings.for_plugin("status_list")
        list_size_value = plugin_settings.get("list_size")
        if list_size_value is None or list_size_value == "":
            list_size_value = getenv("STATUS_LIST_SIZE") or DEFAULT_LIST_SIZE
        list_size = int(list_size_value)
        shard_size_value = plugin_settings.get("shard_size")
        if shard_size_value is None or shard_size_value == "":
            shard_size_value = getenv("STATUS_LIST_SHARD_SIZE") or DEFAULT_SHARD_SIZE
        shard_size = int(shard_size_value)
        public_uri = plugin_settings.get("public_uri") or getenv("STATUS_LIST_PUBLIC_URI")
        file_path = plugin_settings.get("file_path") or getenv("STATUS_LIST_FILE_PATH")
        try:
            token_validity_value = plugin_settings.get("token_validity_days")
            if token_validity_value is None or token_validity_value == "":
                token_validity_value = (
                    getenv("STATUS_LIST_TOKEN_VALIDITY_DAYS")
                    or DEFAULT_TOKEN_VALIDITY_DAYS
                )
            token_validity_days = int(token_validity_value)
        except ValueError:
            token_validity_days = 0
        if not list_size:
            raise ConfigError("list_size", "STATUS_LIST_SIZE")
        if not shard_size:
            raise ConfigError("shard_size", "STATUS_LIST_SHARD_SIZE")
        if not public_uri:
            raise ConfigError("public_uri", "STATUS_LIST_PUBLIC_URI")
        if token_validity_days < 1:
            raise ConfigError("token_validity_days", "STATUS_LIST_TOKEN_VALIDITY_DAYS")

        return cls(
            list_size, shard_size, public_uri, file_path or None, token_validity_days
        )
