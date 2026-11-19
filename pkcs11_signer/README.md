# PKCS#11 Signer Plugin

## Description

Keeps ACA-Py signing keys in a hardware security module (HSM) reached through PKCS#11. The plugin registers a `PKCS11Signer` with ACA-Py's `SignerRegistry`. Keys created with that provider are generated on the token, ACA-Py stores only the public key, and `wallet.sign_message` sends signing to the token.

Requires an ACA-Py build with external signer support (`acapy_agent.wallet.signer_registry`). See ACA-Py's `docs/features/ExternalSigners.md` for the dispatch model.

| | |
|---|---|
| Key types | P-256 only |
| Signature | SHA-256 digest computed by the plugin, signed on the token with `CKM_ECDSA`; returned as raw `r‖s` (64 bytes) |
| Private keys | `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`; labelled with the `key_ref` ACA-Py generates |
| Sessions | `pool_size` authenticated read-write sessions opened at startup |
| Audit | `generate_keypair` and `sign` are logged to the `pkcs11_signer.audit` logger |

## Configuration

Values come from `plugin_config.pkcs11` (`--plugin-config` or `-o pkcs11.<key>=<value>`). Each falls back to its environment variable.

| Key | Env var | Required | Default | Meaning |
|---|---|---|---|---|
| `library_path` | `PKCS11_LIBRARY_PATH` | yes | | Path to the vendor PKCS#11 library |
| `token_name` | `PKCS11_TOKEN_NAME` | yes | | Token label |
| `pin_env` | | | `PKCS11_PIN` | Name of the env var holding the user PIN |
| `provider` | `PKCS11_PROVIDER` | | `pkcs11` | Provider name stored in key metadata; keep it stable |
| `slot` | `PKCS11_SLOT` | | | Slot id, when several tokens share a label |
| `pool_size` | `PKCS11_POOL_SIZE` | | `4` | Number of sessions |

The PIN is only read from the environment.

If neither `library_path` nor `token_name` is set, the plugin registers no signer and logs a warning. An invalid configuration, or a token that can't be opened, is logged and the agent still starts without the signer.

```sh
export PKCS11_PIN=1234
aca-py start \
  --plugin pkcs11_signer \
  -o pkcs11.provider=hsm \
  -o pkcs11.library_path=/path/to/vendor-pkcs11.so \
  -o pkcs11.token_name=issuer \
  ...
```

## Usage

Create a key on the token:

```http
POST /wallet/keys
{ "alg": "p256", "provider": "hsm", "kid": "did:web:issuer.example#key-1" }
```

The key is then used like any wallet key, for example by `POST /wallet/jwt/sign` with `"verificationMethod": "did:web:issuer.example#key-1"`.

## Testing

```sh
poetry install --all-extras
poetry run pytest
```

Integration tests run ACA-Py against the BouncyHsm simulator; see [integration/README.md](integration/README.md).
