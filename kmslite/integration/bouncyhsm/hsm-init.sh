#!/bin/sh
# Publishes the PKCS#11 client library on the shared volume and creates the
# token that alice's kmslite plugin logs into during agent startup, then
# reports ready and idles.
set -eu

BOUNCY_HSM_HTTP="${BOUNCY_HSM_HTTP:-http://bouncyhsm:8080}"
SHARED_LIB_DIR="${SHARED_LIB_DIR:-/shared}"
TOKEN_LABEL="${KMSLITE_PKCS11_TOKEN_NAME:-kmslite-test}"
USER_PIN="${KMSLITE_PKCS11_PIN:-1234}"
SO_PIN="${KMSLITE_PKCS11_SO_PIN:-12345678}"

cp /opt/bouncyhsm/BouncyHsm.Pkcs11Lib.so "${SHARED_LIB_DIR}/"
echo "hsm-init: published BouncyHsm.Pkcs11Lib.so to ${SHARED_LIB_DIR}"

until curl -sf "${BOUNCY_HSM_HTTP}/Slot" -o /tmp/slots.json; do
    echo "hsm-init: waiting for BouncyHsm at ${BOUNCY_HSM_HTTP}"
    sleep 2
done

# Idempotent: BouncyHsm allows duplicate labels, which would make the token
# lookup in PKCS11Signer ambiguous.
if grep -q "\"${TOKEN_LABEL}\"" /tmp/slots.json; then
    echo "hsm-init: token ${TOKEN_LABEL} already present"
else
    curl -sf -X POST "${BOUNCY_HSM_HTTP}/Slot" \
        -H 'Content-Type: application/json' \
        -d "{\"Description\":\"kmslite integration test token\",
             \"Token\":{\"Label\":\"${TOKEN_LABEL}\",
                        \"UserPin\":\"${USER_PIN}\",
                        \"SoPin\":\"${SO_PIN}\",
                        \"SerialNumber\":\"kmslite01\",
                        \"SimulateHwRng\":false,
                        \"SimulateQualifiedArea\":false}}"
    echo "hsm-init: created token ${TOKEN_LABEL}"
fi

# `docker compose up --exit-code-from tests` aborts the whole stack the moment
# ANY container exits, so signal readiness through the healthcheck and idle.
touch /tmp/hsm-ready
exec tail -f /dev/null
