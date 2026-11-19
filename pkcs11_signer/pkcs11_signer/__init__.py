"""PKCS#11 signer plugin: ACA-Py keys held in an HSM."""

import logging

from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.wallet.signer_registry import SignerRegistry

from .config import Pkcs11Config
from .signer import PKCS11Signer

LOGGER = logging.getLogger(__name__)


def _get_or_create_registry(context: InjectionContext) -> SignerRegistry:
    registry = context.inject_or(SignerRegistry)
    if registry is None:
        registry = SignerRegistry()
        context.injector.bind_instance(SignerRegistry, registry)
    return registry


async def setup(context: InjectionContext) -> None:
    """Register a `PKCS11Signer` with ACA-Py's `SignerRegistry`."""
    registry = _get_or_create_registry(context)

    try:
        cfg = Pkcs11Config.from_settings(context.settings)
    except ValueError as err:
        LOGGER.error("pkcs11_signer: invalid config, no signer registered: %s", err)
        return

    if cfg is None:
        LOGGER.warning("pkcs11_signer: not configured; no signer registered")
        return

    # Broad catch so a token that is down at startup doesn't stop the agent.
    try:
        signer = PKCS11Signer.from_config(cfg)
    except Exception:
        LOGGER.exception(
            "pkcs11_signer: could not open token %r (provider=%r)",
            cfg.token_name,
            cfg.provider,
        )
        return

    registry.register(cfg.provider, signer)
    LOGGER.info("pkcs11_signer: registered PKCS11Signer as provider=%r", cfg.provider)
