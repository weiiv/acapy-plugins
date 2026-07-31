#!/usr/bin/env python3
"""End-to-end kmslite ↔ BouncyHsm sanity check.

Runs on the host macOS Python env with the native BouncyHsm .dylib.
Idempotent — safe to run multiple times.

Preconditions:
  - BouncyHsm server up: `docker compose -f docker-compose.bouncyhsm.yml up -d`
  - Native dylib built:  `make -C bouncyhsm-src/build_macos universal`
    (both installed by `./setup.sh`).

Steps:
  1. Provision a slot named `kmslite-dev` via REST if it doesn't exist.
  2. Load the native .dylib with BOUNCY_HSM_CFG_STRING pointing at
     Server=127.0.0.1;Port=8765.
  3. Instantiate PKCS11Signer, generate a P-256 key, sign, verify.
"""

import asyncio
import os
import pathlib
import sys

import requests
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

HERE = pathlib.Path(__file__).resolve().parent
INTEGRATION = HERE
DYLIB = INTEGRATION / "lib" / "BouncyHsm.Pkcs11Lib.dylib"

TOKEN_LABEL = "kmslite-dev"
USER_PIN = "1234"
SO_PIN = "12345678"  # security officer PIN (BouncyHsm minimum length)
BASE_URL = "http://localhost:8080"


def _provision_slot_if_missing() -> None:
    r = requests.get(f"{BASE_URL}/Slot")
    r.raise_for_status()
    slots = r.json()
    slot_list = slots if isinstance(slots, list) else slots.get("Slots", [])
    # /Slot returns objects with a nested `Token.Label`.
    existing = [
        s
        for s in slot_list
        if isinstance(s, dict) and (s.get("Token") or {}).get("Label") == TOKEN_LABEL
    ]
    if existing:
        print(f"  slot with token {TOKEN_LABEL!r} already exists — skipping create")
        return
    body = {
        "IsHwDevice": True,
        "IsRemovableDevice": False,
        "Description": "kmslite dev slot",
        "Token": {
            "Label": TOKEN_LABEL,
            "SimulateHwRng": True,
            "SimulateHwMechanism": True,
            "SimulateQualifiedArea": False,
            "SimulateProtectedAuthPath": False,
            "SpeedMode": 0,
            "UserPin": USER_PIN,
            "SoPin": SO_PIN,
        },
    }
    r = requests.post(f"{BASE_URL}/Slot", json=body)
    r.raise_for_status()
    print(f"  provisioned slot: {r.text!r}")


async def _round_trip() -> None:
    os.environ["BOUNCY_HSM_CFG_STRING"] = "Server=127.0.0.1;Port=8765;"
    # Import here so the env var is set before python-pkcs11 loads the .dylib.
    from kmslite.v1_0.signers.pkcs11 import PKCS11Signer
    from acapy_agent.wallet.key_type import P256
    from acapy_agent.wallet.util import b58_to_bytes

    signer = PKCS11Signer(
        lib_path=str(DYLIB),
        token_label=TOKEN_LABEL,
        pin=USER_PIN,
        pool_size=2,
    )

    key_ref = "kmslite-e2e-key"
    # Idempotency: prefer lookup, generate only if the key doesn't exist yet.
    try:
        verkey = await signer.get_public_key(key_ref, P256)
        print(f"  reusing existing key {key_ref!r}, verkey={verkey}")
    except Exception:
        print(f"  generating new P-256 key: {key_ref}")
        verkey = await signer.generate_keypair(key_ref, P256)
        print(f"    verkey={verkey}")

    assert len(b58_to_bytes(verkey)) == 33, "verkey should be SEC1-compressed"

    payload = b"hello from kmslite-plus-bouncyhsm"
    print(f"  signing {len(payload)} bytes")
    raw_sig = await signer.sign(key_ref, payload, P256)
    assert len(raw_sig) == 64, f"expected 64-byte raw r||s, got {len(raw_sig)}"
    print(f"    signature (raw r||s, hex): {raw_sig.hex()}")

    # Verify locally with `cryptography`, converting raw to DER.
    pub = EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b58_to_bytes(verkey))
    r, s = int.from_bytes(raw_sig[:32], "big"), int.from_bytes(raw_sig[32:], "big")
    der_sig = utils.encode_dss_signature(r, s)
    from cryptography.hazmat.primitives import hashes

    pub.verify(der_sig, payload, ec.ECDSA(hashes.SHA256()))
    print("    ✓ signature verified against public key")


def main() -> int:
    if not DYLIB.exists():
        print(f"ERROR: {DYLIB} not found. Run `./setup.sh` first.", file=sys.stderr)
        return 1

    print("[1/2] Provision slot")
    _provision_slot_if_missing()

    print("[2/2] Round-trip via PKCS11Signer")
    asyncio.run(_round_trip())

    print("\n✓ All good. kmslite can talk to BouncyHsm via the native .dylib.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
