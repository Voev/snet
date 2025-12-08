#!/bin/bash

set -e

SCRIPT_CMD="generate_key_and_cert.py"
PYTHON_CMD="python3"

mkdir -p certs_rsa certs_ecdsa certs_dss certs_ed25519 certs_ed448

KEY_TYPES=("rsa" "ecdsa" "dss" "ed25519" "ed448")

for key_type in "${KEY_TYPES[@]}"; do
    DIR="certs_${key_type}"

    $PYTHON_CMD $SCRIPT_CMD --mode root \
        --key-type "$key_type" \
        --root-key "$DIR/ca_${key_type}.key" \
        --root-cert "$DIR/ca_${key_type}.crt"
    $PYTHON_CMD $SCRIPT_CMD --mode server \
        --key-type "$key_type" \
        --key "$DIR/server_${key_type}.key" \
        --cert "$DIR/server_${key_type}.crt" \
        --root-key "$DIR/ca_${key_type}.key" \
        --root-cert "$DIR/ca_${key_type}.crt" \
        --common-name "server.${key_type}"
    $PYTHON_CMD $SCRIPT_CMD --mode client \
        --key-type "$key_type" \
        --key "$DIR/client_${key_type}.key" \
        --cert "$DIR/client_${key_type}.crt" \
        --root-key "$DIR/ca_${key_type}.key" \
        --root-cert "$DIR/ca_${key_type}.crt" \
        --client-id "user_${key_type}"
done
