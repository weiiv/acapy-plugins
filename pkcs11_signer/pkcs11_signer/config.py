"""pkcs11_signer plugin configuration.

Read from `settings["plugin_config"]["pkcs11"]` (via `--plugin-config` and
`-o key=value`) with `PKCS11_*` env vars as fallback.
"""

from dataclasses import dataclass
from os import getenv
from typing import Optional

from acapy_agent.config.base import BaseSettings

PLUGIN_CONFIG_KEY = "pkcs11"
DEFAULT_PROVIDER = "pkcs11"
DEFAULT_POOL_SIZE = 4


class ConfigError(ValueError):
    """pkcs11_signer configuration error."""

    def __init__(self, var: str, env: str):
        """Initialize a ConfigError."""
        super().__init__(
            f"Invalid {var} specified for pkcs11_signer plugin; "
            f"use either {PLUGIN_CONFIG_KEY}.{var} plugin config value "
            f"or environment variable {env}"
        )


def _int_or_error(raw, var: str, env: str) -> int:
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise ConfigError(var, env) from None


@dataclass(frozen=True)
class Pkcs11Config:
    """Resolved pkcs11_signer plugin configuration."""

    provider: str
    library_path: str
    token_name: str
    pin: str
    slot: Optional[int] = None
    pool_size: int = DEFAULT_POOL_SIZE

    @classmethod
    def from_settings(cls, settings: BaseSettings) -> Optional["Pkcs11Config"]:
        """Read from settings; return None when the plugin isn't configured."""
        try:
            plugin_settings = settings.for_plugin(PLUGIN_CONFIG_KEY) or {}
        except AttributeError:
            plugin_settings = {}

        library_path = plugin_settings.get("library_path") or getenv(
            "PKCS11_LIBRARY_PATH"
        )
        token_name = plugin_settings.get("token_name") or getenv("PKCS11_TOKEN_NAME")
        if not library_path and not token_name:
            return None
        if not library_path:
            raise ConfigError("library_path", "PKCS11_LIBRARY_PATH")
        if not token_name:
            raise ConfigError("token_name", "PKCS11_TOKEN_NAME")

        pin_env = plugin_settings.get("pin_env")
        pin = getenv(pin_env) if pin_env else getenv("PKCS11_PIN")
        if not pin:
            raise ConfigError("pin_env", pin_env or "PKCS11_PIN")

        provider = (
            plugin_settings.get("provider")
            or getenv("PKCS11_PROVIDER")
            or DEFAULT_PROVIDER
        )

        slot_raw = plugin_settings.get("slot", getenv("PKCS11_SLOT"))
        pool_raw = plugin_settings.get("pool_size", getenv("PKCS11_POOL_SIZE"))

        pool_size = (
            DEFAULT_POOL_SIZE
            if pool_raw in (None, "")
            else _int_or_error(pool_raw, "pool_size", "PKCS11_POOL_SIZE")
        )
        if pool_size < 1:
            raise ConfigError("pool_size", "PKCS11_POOL_SIZE")

        return cls(
            provider=str(provider),
            library_path=str(library_path),
            token_name=str(token_name),
            pin=str(pin),
            slot=(
                None
                if slot_raw in (None, "")
                else _int_or_error(slot_raw, "slot", "PKCS11_SLOT")
            ),
            pool_size=pool_size,
        )
