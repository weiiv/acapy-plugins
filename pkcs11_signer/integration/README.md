# Integration Tests

All plugins should have a suite of integration tests. We use `docker compose` to set up the environment, and make use of the [Dockerfile](../docker/Dockerfile) to produce our ACA-Py/Plugin image. To simplify, we have another [Dockerfile](Dockerfile.test.runner) for running those [tests](tests/).

## Build and run Tests

```sh
cd integration
docker compose build
docker compose up --exit-code-from tests
docker compose down --remove-orphans -v
```

This is what CI runs. Expect `4 passed` and exit code 0. The first build clones and compiles the BouncyHsm PKCS#11 client, so it is slow; later builds are cached.

Extra arguments reach pytest, and `run` reuses already-started agents:

```sh
docker compose run --rm tests -k hsm
```

## Services

| Service | Role |
|---|---|
| `bouncyhsm` | HSM simulator holding the private keys |
| `hsm-init` | Publishes the PKCS#11 client library on a shared volume and provisions the token; stays alive so `--exit-code-from` doesn't abort the stack |
| `alice` | Agent with the plugin configured against `bouncyhsm` |
| `bob` | Same image, plugin unconfigured — the control for the unknown-provider path |
| `tests` (`juggernaut`) | Drives both agents over their admin APIs |

The tests are black-box and deliberately narrow: they only cover what the unit suite cannot reach, since it mocks `pkcs11`.

## Debugging

```sh
docker compose logs alice | grep -i pkcs11_signer
docker compose logs bouncyhsm
```

A healthy `alice` logs `pkcs11_signer: registered PKCS11Signer as provider='bouncyhsm'`. `bob` is meant to log `pkcs11_signer: not configured`.

## BouncyHsm

Everything HSM-specific lives in [bouncyhsm/](bouncyhsm/). For the macOS-native development loop — server on the host, `.dylib` client, no containers for the plugin — see [bouncyhsm/BOUNCYHSM.md](bouncyhsm/BOUNCYHSM.md).
