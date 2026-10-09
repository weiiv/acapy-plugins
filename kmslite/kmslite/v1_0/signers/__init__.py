"""Signer implementations for kmslite."""

from acapy_agent.wallet.error import WalletError


class SignerError(WalletError):
    """The external backend failed.

    Subclasses WalletError so core's sign dispatch is unaffected. Raised only
    for faults the caller cannot fix (token unreachable, session dead, backend
    refused); caller-fixable problems stay plain `WalletError`.
    """
