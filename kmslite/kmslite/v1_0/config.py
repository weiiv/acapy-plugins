"""kmslite plugin configuration.

Read from `settings["plugin_config"]["kmslite"]` (via `--plugin-config` and
`-o key=value`) with `KMSLITE_*` env vars as fallback. See
`docs/architecture.md#configuration` for the full option table.
"""

from dataclasses import dataclass, field
from os import getenv
from typing import Any, Mapping, Optional

from acapy_agent.config.base import BaseSettings

DEFAULT_POOL_SIZE = 4


class ConfigError(ValueError):
    """kmslite configuration error."""

    def __init__(self, var: str, env: str):
        """Initialize a ConfigError."""
        super().__init__(
            f"Invalid {var} specified for kmslite plugin; "
            f"use either kmslite.{var} plugin config value "
            f"or environment variable {env}"
        )


def _resolve_pkcs11_cfg(pkcs11_cfg: Mapping[str, Any]) -> dict:
    library_path = pkcs11_cfg.get("library_path") or getenv(
        "KMSLITE_PKCS11_LIBRARY_PATH"
    )
    if not library_path:
        raise ConfigError("pkcs11.library_path", "KMSLITE_PKCS11_LIBRARY_PATH")

    token_name = pkcs11_cfg.get("token_name") or getenv("KMSLITE_PKCS11_TOKEN_NAME")
    if not token_name:
        raise ConfigError("pkcs11.token_name", "KMSLITE_PKCS11_TOKEN_NAME")

    pin_env = pkcs11_cfg.get("pin_env")
    pin = getenv(pin_env) if pin_env else getenv("KMSLITE_PKCS11_PIN")
    if not pin:
        raise ConfigError("pkcs11.pin_env", "KMSLITE_PKCS11_PIN")

    slot_raw = pkcs11_cfg.get("slot", getenv("KMSLITE_PKCS11_SLOT"))
    pool_raw = pkcs11_cfg.get("pool_size", getenv("KMSLITE_PKCS11_POOL_SIZE"))

    resolved = {
        "library_path": str(library_path),
        "token_name": str(token_name),
        "pin": str(pin),
        "pool_size": int(pool_raw) if pool_raw is not None else DEFAULT_POOL_SIZE,
    }
    if slot_raw not in (None, ""):
        resolved["slot"] = int(slot_raw)
    return resolved


_PROTOCOL_RESOLVERS = {"pkcs11": _resolve_pkcs11_cfg}


@dataclass(frozen=True)
class KmsLiteConfig:
    """Resolved kmslite plugin configuration."""

    provider: str
    protocol: str
    protocol_cfg: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_settings(cls, settings: BaseSettings) -> Optional["KmsLiteConfig"]:
        """Read from settings; return None when the plugin isn't configured."""
        try:
            plugin_settings = settings.for_plugin("kmslite") or {}
        except AttributeError:
            plugin_settings = {}

        provider = plugin_settings.get("provider") or getenv("KMSLITE_PROVIDER")
        protocol = plugin_settings.get("protocol") or getenv("KMSLITE_PROTOCOL")

        if not provider and not protocol:
            return None
        if not provider:
            raise ConfigError("provider", "KMSLITE_PROVIDER")
        if not protocol:
            raise ConfigError("protocol", "KMSLITE_PROTOCOL")

        resolver = _PROTOCOL_RESOLVERS.get(protocol)
        if resolver is None:
            raise ValueError(
                f"kmslite: unknown protocol {protocol!r} "
                f"(supported: {list(_PROTOCOL_RESOLVERS)})"
            )

        return cls(
            provider=str(provider),
            protocol=str(protocol),
            protocol_cfg=resolver(plugin_settings.get(protocol) or {}),
        )
