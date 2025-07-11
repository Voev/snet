import os
import argparse
import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.x509 import (
    NameOID,
    CertificateBuilder,
    SubjectAlternativeName,
    Name
)
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import NameOID

def save_key_and_cert(key, cert, key_path, cert_path):
    encoded_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    encoded_cert = cert.public_bytes(serialization.Encoding.PEM)

    with open(key_path, 'wb') as f:
        f.write(encoded_key)
    with open(cert_path, 'wb') as f:
        f.write(encoded_cert)

def load_key_and_cert(key_path, cert_path, key_password=None):
    with open(key_path, "rb") as key_file:
        key_data = key_file.read()
        if key_password:
            key = serialization.load_pem_private_key(
                key_data,
                password=key_password.encode(),
                backend=default_backend()
            )
        else:
            key = serialization.load_pem_private_key(
                key_data,
                password=None,
                backend=default_backend()
            )

    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    return key, cert

def generate_self_signed_cert(key_type='rsa'):
    if key_type == 'rsa':
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
    elif key_type == 'ecdsa':
        key = ec.generate_private_key(
            curve=ec.SECP256R1()
        )
    elif key_type == 'dsa':
        key = dsa.generate_private_key(
            key_size=1024
        )
    else:
        raise ValueError(f"Unsupported key type: {key_type}")

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Root certificate"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=5*365))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False),
            critical=True
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    return key, cert

def generate_server_cert_with_ca(ca_key, ca_cert, key_type='rsa'):
    if key_type == 'rsa':
        server_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
    elif key_type == 'ecdsa':
        server_key = ec.generate_private_key(
            curve=ec.SECP256R1()
        )
    elif key_type == 'dsa':
        server_key = dsa.generate_private_key(
            key_size=1024
        )
    else:
        raise ValueError(f"Unsupported key type: {key_type}")

    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=(key_type != 'ecdsa'),  # ECDSA doesn't use key encipherment
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
                key_cert_sign=False,
                crl_sign=False),
            critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )

    return server_key, server_cert

def main():
    parser = argparse.ArgumentParser(description="TLS server credentials generator")
    parser.add_argument('--key', '-k', default='server.key', type=str, help='Path to private key file')
    parser.add_argument('--cert', '-c', default='server.crt', type=str, help='Path to certificate file')
    parser.add_argument('--root-key', default='root.key', type=str, help='Path to root private key file')
    parser.add_argument('--root-cert', default='root.crt', type=str, help='Path to root certificate file')
    parser.add_argument('--key-type', choices=['rsa', 'ecdsa', 'dsa'], default='rsa',
                       help='Type of key to generate (rsa, ecdsa, dsa)')

    args = parser.parse_args()

    if os.path.isfile(args.root_key) and os.path.isfile(args.root_cert):
        print("[*] Loading root certificate with key...")
        root_key, root_cert = load_key_and_cert(args.root_key, args.root_cert)
    else:
        print(f"[*] Generating self-signed {args.key_type.upper()} certificate...")
        root_key, root_cert = generate_self_signed_cert(args.key_type)
        save_key_and_cert(root_key, root_cert, args.root_key, args.root_cert)
    
    print(f"[*] Generating server credentials with {args.key_type.upper()} key...")
    server_key, server_cert = generate_server_cert_with_ca(root_key, root_cert, args.key_type)
    save_key_and_cert(server_key, server_cert, args.key, args.cert)
    print(f"[*] Done! Certificate: {args.cert}, Key: {args.key} (Type: {args.key_type.upper()})")

if __name__ == "__main__":
    main()