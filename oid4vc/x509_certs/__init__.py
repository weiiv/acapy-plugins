"""X.509 certificates and trust anchors for wallet keys.

Other packages import only from this module. It must not import OID4VC modules,
so it can move into ACA-Py as `acapy_agent.x509` with a rename.
"""

import logging

from acapy_agent.config.injection_context import InjectionContext

from .certs import X509Error, embedded_x5c, pem_chain, select_certificate
from .models import (
    ANCHOR_PURPOSE_FOR,
    ANCHOR_PURPOSES,
    CERTIFICATE_PURPOSES,
    X509CertificateRecord,
    X509TrustAnchorRecord,
)

__all__ = [
    "ANCHOR_PURPOSE_FOR",
    "ANCHOR_PURPOSES",
    "CERTIFICATE_PURPOSES",
    "X509CertificateRecord",
    "X509Error",
    "X509TrustAnchorRecord",
    "embedded_x5c",
    "pem_chain",
    "select_certificate",
]

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Set up the plugin; routes are registered from `x509_certs.routes`."""
    LOGGER.info("Setting up x509_certs plugin")
