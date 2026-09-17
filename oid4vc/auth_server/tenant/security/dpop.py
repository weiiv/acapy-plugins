"""DPoP nonce generator using HMAC-SHA256 for multi-node deployments.

Implements authlib's DPoPNonceGenerator protocol with deterministic,
stateless nonces derived from a shared secret + time window.
"""

import hashlib
import hmac
import time

from authlib.oauth2.rfc9449.nonce import DPoPNonceGenerator

from core.utils.encoding import b64url_encode


class HmacDPoPNonceGenerator(DPoPNonceGenerator):
    """Stateless HMAC-based nonce generator safe for multi-node deployments.

    Nonce = base64url(HMAC-SHA256(secret, str(counter)))
    where counter = floor(time / interval).

    Accepts nonces from current window ±1 to tolerate clock skew
    and requests that straddle a rotation boundary.
    """

    def __init__(self, secret: str, interval: int = 60):
        """Initialize with shared secret and rotation interval (seconds)."""
        if not secret:
            raise ValueError("DPOP_NONCE_SECRET must be set when DPoP is enabled")
        self._secret = secret.encode()
        self._interval = interval

    def next(self) -> str:
        """Return the nonce for the current time window."""
        counter = self._current_counter()
        return self._compute(counter)

    def check(self, nonce: str) -> bool:
        """Validate nonce against current ±1 windows."""
        counter = self._current_counter()
        return nonce in (
            self._compute(counter - 1),
            self._compute(counter),
            self._compute(counter + 1),
        )

    def _current_counter(self) -> int:
        return int(time.time() / self._interval)

    def _compute(self, counter: int) -> str:
        digest = hmac.new(self._secret, str(counter).encode(), hashlib.sha256).digest()
        return b64url_encode(digest)
