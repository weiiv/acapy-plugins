# Local BouncyHsm setup (macOS, native)

A working local HSM for developing / testing `kmslite`. Everything runs
natively on macOS (Apple Silicon or Intel) — the plugin, ACA-Py, and the
PKCS#11 client library. Only the BouncyHsm **server** runs in Docker
(it's a .NET app; the arm64 `dotnet/aspnet:10.0` image runs natively
under Docker Desktop, no emulation).

```
┌────────────────────────────── macOS host ──────────────────────────────┐
│                                                                        │
│  poetry env  ─────►  kmslite / PKCS11Signer  ─────►  BouncyHsm.Pkcs11  │
│  (Python 3.13)         (native code)                 Lib.dylib         │
│                                                        │               │
│                                                        │ TCP :8765     │
│                                                        ▼               │
│  Docker Desktop  ─────────────────►  BouncyHsm server (container)      │
│                                       :8080 web UI, :8765 PKCS#11      │
└────────────────────────────────────────────────────────────────────────┘
```

## Prerequisites

- macOS (arm64 tested; universal build also produces x86_64 slice)
- Xcode Command Line Tools (`xcode-select --install`)
- Docker Desktop (running)
- `poetry` for the plugin env

.NET SDK is **not** required — the PKCS#11 client is C, and the server is
built from the release ZIP inside the Docker image.

## Bring it up

```sh
cd integration
./setup.sh                              # clones + builds + starts server
poetry run python verify_bouncyhsm.py   # provisions slot + round-trip signs
```

Expected on first successful run:

```
[1/2] Provision slot
  provisioned slot: '{"Id":"...","SlotId":2,"TokenSerialNumber":"..."}'
[2/2] Round-trip via PKCS11Signer
  generating P-256 key: kmslite-e2e-key
    fresh key created, verkey=22VTxDFs...
  signing 33 bytes
    signature (raw r||s, hex): ...
    ✓ signature verified against public key

✓ All good. kmslite can talk to BouncyHsm via the native .dylib.
```

## What `setup.sh` does

| Step | Detail |
|---|---|
| 1 | `git clone --depth 1 --branch v2.3.0 https://github.com/harrison314/BouncyHsm.git bouncyhsm-src` |
| 2 | `make -C bouncyhsm-src/build_macos universal` → produces universal dylib (x86_64 + arm64) → copies into `./lib/` |
| 3 | `docker compose -f docker-compose.bouncyhsm.yml up -d --build` — server on 8080/8765 |

Re-run any time; each step is idempotent.

## Configuring kmslite to use it

Preferred: inline `-o key=value` args to `aca-py start` (repeatable, no
separate file). The BouncyHsm client library also needs a transport
env var pointing at the server.

```sh
# BouncyHsm native transport target (used by the .dylib client)
export BOUNCY_HSM_CFG_STRING="Server=127.0.0.1;Port=8765;"
export HSM_PIN=1234        # matches USER_PIN in verify_bouncyhsm.py

aca-py start \
  -o kmslite.provider=hsm \
  -o kmslite.protocol=pkcs11 \
  -o kmslite.pkcs11.library_path=/Users/YOU/Workspace/di/vc/acapy-plugins/kmslite/integration/lib/BouncyHsm.Pkcs11Lib.dylib \
  -o kmslite.pkcs11.token_name=kmslite-dev \
  -o kmslite.pkcs11.pin_env=HSM_PIN \
  -o kmslite.pkcs11.pool_size=4 \
  --plugin kmslite \
  ...other-args...
```

Alternative (YAML file via `--plugin-config <file>`):

```yaml
plugin_config:
  kmslite:
    provider: hsm
    protocol: pkcs11
    pkcs11:
      library_path: /Users/YOU/Workspace/di/vc/acapy-plugins/kmslite/integration/lib/BouncyHsm.Pkcs11Lib.dylib
      token_name: kmslite-dev
      pin_env: HSM_PIN     # names an env var; set HSM_PIN=1234 separately
      pool_size: 4
```

Alternative (env vars only — no `-o` and no file):

```sh
export KMSLITE_PROVIDER=hsm
export KMSLITE_PROTOCOL=pkcs11
export KMSLITE_PKCS11_LIBRARY_PATH=/Users/YOU/.../lib/BouncyHsm.Pkcs11Lib.dylib
export KMSLITE_PKCS11_TOKEN_NAME=kmslite-dev
export KMSLITE_PKCS11_PIN=1234
```

## Stopping / cleaning

```sh
# stop the server (keeps its volume)
docker compose -f docker-compose.bouncyhsm.yml down

# stop + wipe the token/slot state
docker compose -f docker-compose.bouncyhsm.yml down -v

# throw away everything and start over
docker compose -f docker-compose.bouncyhsm.yml down -v
rm -rf bouncyhsm-src lib
./setup.sh
```

## Files in this directory

| File | Purpose |
|---|---|
| `docker-compose.bouncyhsm.yml` | Server-only compose (this doc's setup) |
| `bouncyhsm-server/Dockerfile`  | Builds the .NET server image from the release ZIP |
| `setup.sh`                     | One-shot bring-up |
| `verify_bouncyhsm.py`          | Round-trip sanity check |
| `lib/`                         | Built `.dylib`s (gitignored) |
| `bouncyhsm-src/`               | Source clone (gitignored) |
| `docker-compose.yml`, `Dockerfile.test.runner`, `tests/` | Pre-existing DIDComm integration tests — unrelated to HSM |
