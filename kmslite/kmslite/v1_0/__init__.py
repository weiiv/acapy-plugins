"""kmslite plugin v1.0."""

import logging

from acapy_agent.admin.base_server import BaseAdminServer
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.wallet.signer_registry import SignerRegistry

from . import routes
from .config import KmsLiteConfig
from .signers.pkcs11 import PKCS11Signer

LOGGER = logging.getLogger(__name__)

PROTOCOL_IMPLEMENTATIONS = {
    "pkcs11": PKCS11Signer,
}


def _get_or_create_registry(context: InjectionContext) -> SignerRegistry:
    registry = context.inject_or(SignerRegistry)
    if registry is None:
        registry = SignerRegistry()
        context.injector.bind_instance(SignerRegistry, registry)
    return registry


def _register_signer(registry: SignerRegistry, cfg: KmsLiteConfig) -> None:
    signer_cls = PROTOCOL_IMPLEMENTATIONS.get(cfg.protocol)
    if signer_cls is None:
        LOGGER.error(
            "kmslite: unknown protocol %r; supported: %s",
            cfg.protocol,
            sorted(PROTOCOL_IMPLEMENTATIONS),
        )
        return
    try:
        signer = signer_cls.from_config(cfg.protocol_cfg, provider_name=cfg.provider)
    except Exception:
        LOGGER.exception(
            "kmslite: could not build signer (provider=%r protocol=%r)",
            cfg.provider,
            cfg.protocol,
        )
        return
    registry.register(cfg.provider, signer)
    LOGGER.info(
        "kmslite: registered %s as provider=%r", signer_cls.__name__, cfg.provider
    )


async def setup(context: InjectionContext) -> None:
    registry = _get_or_create_registry(context)

    try:
        cfg = KmsLiteConfig.from_settings(context.settings)
    except ValueError as err:
        LOGGER.error("kmslite: invalid config, plugin disabled: %s", err)
        cfg = None

    if cfg is None:
        LOGGER.info("kmslite: not configured; X.509 routes still available")
    else:
        _register_signer(registry, cfg)

    admin_server = context.inject_or(BaseAdminServer)
    if admin_server is None:
        LOGGER.warning("kmslite: no BaseAdminServer; routes not registered")
        return
    await routes.register(admin_server.app)
