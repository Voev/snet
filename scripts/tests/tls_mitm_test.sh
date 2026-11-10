#!/usr/bin/env bash
#
# gen-test-keys.sh — generate keys for TLSMitmTest tests
#
# Usage:
#   ./gen-test-keys.sh [output_dir] [--pss]
#
# Examples:
#   ./gen-test-keys.sh ./keys              # regular RSA keys (2048)
#   ./gen-test-keys.sh ./keys-pss --pss    # RSA-PSS keys (for TLS 1.3)
#
set -euo pipefail

OUT_DIR="${1:-./test-keys}"
USE_PSS=false
[[ "${2:-}" == "--pss" ]] && USE_PSS=true

mkdir -p "$OUT_DIR"

# ---------- algorithm selection ----------
if $USE_PSS; then
    KEY_ALG="rsa-pss"
    PKEYOPTS=(
        -pkeyopt rsa_keygen_bits:2048
        -pkeyopt rsa_pss_keygen_md:sha256
        -pkeyopt rsa_pss_keygen_mgf1_md:sha256
        -pkeyopt rsa_pss_keygen_saltlen:32
    )
    echo ">>> Generating RSA-PSS keys (2048, SHA-256)"
else
    KEY_ALG="RSA"
    PKEYOPTS=( -pkeyopt rsa_keygen_bits:2048 )
    echo ">>> Generating regular RSA keys (2048)"
fi

# ---------- 1. CA key ----------
echo "    -> CA key"
openssl genpkey -algorithm "$KEY_ALG" "${PKEYOPTS[@]}" \
    -out "$OUT_DIR/ca.key"

# ---------- 2. Server key ----------
echo "    -> Server key"
openssl genpkey -algorithm "$KEY_ALG" "${PKEYOPTS[@]}" \
    -out "$OUT_DIR/server.key"

# ---------- 3. MITM key ----------
echo "    -> MITM key"
openssl genpkey -algorithm "$KEY_ALG" "${PKEYOPTS[@]}" \
    -out "$OUT_DIR/mitm.key"

# ---------- verification ----------
echo
echo ">>> Done. Files in $OUT_DIR:"
ls -l "$OUT_DIR"/*.key

echo
echo ">>> Run the test:"
echo "SNET_CA_KEY_FILE=$OUT_DIR/ca.key \\"
echo "SNET_SERVER_KEY_FILE=$OUT_DIR/server.key \\"
echo "SNET_MITM_KEY_FILE=$OUT_DIR/mitm.key \\"
echo "./build/Debug/bin/snet_tls_test --gtest_filter='*Mitm*'"