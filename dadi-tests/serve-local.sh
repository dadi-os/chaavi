#!/usr/bin/env bash
# Start a throwaway Chaavi for the interop suite: empty vault, self-signed localhost TLS (the
# Bitwarden CLI refuses plain HTTP), signups on, and the suite's test-only unlock account.
#   BIN=path/to/vaultwarden ./serve-local.sh          # then, elsewhere:
#   NODE_EXTRA_CA_CERTS=$DIR/cert.pem CHAAVI_URL=https://localhost:8099 npm test
set -euo pipefail

BIN="${BIN:-${CARGO_TARGET_DIR:-../target}/debug/vaultwarden}"
DIR="${DIR:-/tmp/chaavi-interop}"
PORT="${PORT:-8099}"

rm -rf "$DIR/data"
mkdir -p "$DIR/data"
if [ ! -f "$DIR/cert.pem" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -keyout "$DIR/key.pem" -out "$DIR/cert.pem" 2>/dev/null
fi

export DATA_FOLDER="$DIR/data"
export ROCKET_ADDRESS=0.0.0.0
export ROCKET_PORT="$PORT"
export ROCKET_TLS="{certs=\"$DIR/cert.pem\",key=\"$DIR/key.pem\"}"
export DOMAIN="https://localhost:$PORT"
export SIGNUPS_ALLOWED=true
export WEB_VAULT_ENABLED=false
export EXPERIMENTAL_CLIENT_FEATURE_FLAGS=pm-32009-new-item-types
# Must match EMAIL / PASSWORD in interop.test.mjs (test-only values).
export CHAAVI_EMAIL=interop@chaavi.test
export CHAAVI_PASSWORD="interop-only master password 7"

exec "$BIN"
