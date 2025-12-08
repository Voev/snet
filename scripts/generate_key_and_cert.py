import os
import argparse
import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from cryptography.x509 import (
    NameOID,
    CertificateBuilder,
    SubjectAlternativeName,
    Name,
    random_serial_number,
    BasicConstraints,
    KeyUsage,
    ExtendedKeyUsage,
    NameAttribute
)
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

def save_key_and_cert(key, cert, key_path, cert_path):
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        encoded_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        encoded_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
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
            key_size=2048,
            backend=default_backend()
        )
    elif key_type == 'ecdsa':
        key = ec.generate_private_key(
            curve=ec.SECP256R1(),
            backend=default_backend()
        )
    elif key_type == 'dss':
        key = dsa.generate_private_key(
            key_size=1024,
            backend=default_backend()
        )
    elif key_type == 'ed25519':
        key = ed25519.Ed25519PrivateKey.generate()
    elif key_type == 'ed448':
        key = ed448.Ed448PrivateKey.generate()
    else:
        raise ValueError("Unsupported key type: {}".format(key_type))

    subject = issuer = Name([
        NameAttribute(NameOID.COMMON_NAME, u"Root certificate"),
    ])

    cert = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=5*365))
        .add_extension(
            KeyUsage(
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
            BasicConstraints(ca=True, path_length=None),
            critical=True
        )
    )
    
    if key_type in ['ed25519', 'ed448']:
        cert = cert.sign(key, None)
    else:
        cert = cert.sign(key, hashes.SHA256(), default_backend())

    return key, cert

def generate_server_cert_with_ca(ca_key, ca_cert, key_type='rsa', common_name="localhost"):
    if key_type == 'rsa':
        server_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
    elif key_type == 'ecdsa':
        server_key = ec.generate_private_key(
            curve=ec.SECP256R1(),
            backend=default_backend()
        )
    elif key_type == 'dss':
        server_key = dsa.generate_private_key(
            key_size=1024,
            backend=default_backend()
        )
    elif key_type == 'ed25519':
        server_key = ed25519.Ed25519PrivateKey.generate()
    elif key_type == 'ed448':
        server_key = ed448.Ed448PrivateKey.generate()
    else:
        raise ValueError("Unsupported key type: {}".format(key_type))

    server_subject = Name([
        NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    if key_type in ['ed25519', 'ed448']:
        key_usage = KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=False,
            crl_sign=False)
    else:
        key_usage = KeyUsage(
            digital_signature=True,
            key_encipherment=(key_type != 'ecdsa'),
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=False,
            crl_sign=False)

    cert_builder = (
        CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False
        )
        .add_extension(
            ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=True
        )
        .add_extension(
            key_usage,
            critical=True
        )
        .add_extension(
            BasicConstraints(ca=False, path_length=None),
            critical=True
        )
    )
    
    if isinstance(ca_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        server_cert = cert_builder.sign(ca_key, None)
    else:
        server_cert = cert_builder.sign(ca_key, hashes.SHA256(), default_backend())

    return server_key, server_cert

def generate_client_cert_with_ca(ca_key, ca_cert, key_type='rsa', client_id="client"):
    if key_type == 'rsa':
        client_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
    elif key_type == 'ecdsa':
        client_key = ec.generate_private_key(
            curve=ec.SECP256R1(),
            backend=default_backend()
        )
    elif key_type == 'dss':
        client_key = dsa.generate_private_key(
            key_size=1024,
            backend=default_backend()
        )
    elif key_type == 'ed25519':
        client_key = ed25519.Ed25519PrivateKey.generate()
    elif key_type == 'ed448':
        client_key = ed448.Ed448PrivateKey.generate()
    else:
        raise ValueError("Unsupported key type: {}".format(key_type))

    client_subject = Name([
        NameAttribute(NameOID.COMMON_NAME, client_id),
        NameAttribute(NameOID.ORGANIZATION_NAME, u"Client Organization"),
        NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    ])

    if key_type in ['ed25519', 'ed448']:
        key_usage = KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=False,
            crl_sign=False)
    else:
        key_usage = KeyUsage(
            digital_signature=True,
            key_encipherment=(key_type != 'ecdsa'),
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=False,
            crl_sign=False)

    cert_builder = (
        CertificateBuilder()
        .subject_name(client_subject)
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True
        )
        .add_extension(
            key_usage,
            critical=True
        )
        .add_extension(
            BasicConstraints(ca=False, path_length=None),
            critical=True
        )
    )

    if isinstance(ca_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        client_cert = cert_builder.sign(ca_key, None)
    else:
        client_cert = cert_builder.sign(ca_key, hashes.SHA256(), default_backend())

    return client_key, client_cert

def generate_certificate_signing_request(key, common_name, key_type='rsa'):
    subject = Name([
        NameAttribute(NameOID.COMMON_NAME, common_name),
        NameAttribute(NameOID.ORGANIZATION_NAME, u"Example Organization"),
        NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    ])
    
    csr_builder = x509.CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(subject)
    
    if key_type in ['ed25519', 'ed448']:
        csr = csr_builder.sign(key, None)
    else:
        csr = csr_builder.sign(key, hashes.SHA256(), default_backend())
    
    return csr

def sign_csr_with_ca(csr, ca_key, ca_cert, cert_type='server'):
    try:
        if not isinstance(csr.public_key(), (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            csr.public_key().verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                hashes.SHA256(),
                None,
                default_backend()
            )
    except Exception as e:
        print("CSR signature verification warning: {}".format(e))

    if cert_type == 'server':
        extended_key_usage = [ExtendedKeyUsageOID.SERVER_AUTH]
        san = None
        try:
            for ext in csr.extensions:
                if isinstance(ext.value, SubjectAlternativeName):
                    san = ext.value
                    break
            if san is None:
                san = SubjectAlternativeName([x509.DNSName(u"localhost")])
        except Exception:
            san = SubjectAlternativeName([x509.DNSName(u"localhost")])
    else:
        # client
        extended_key_usage = [ExtendedKeyUsageOID.CLIENT_AUTH]
        san = None
    
    public_key = csr.public_key()
    if isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key_usage = KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=False,
            crl_sign=False)
    else:
        key_usage = KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=False,
            crl_sign=False)
    
    cert_builder = (
        CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            ExtendedKeyUsage(extended_key_usage),
            critical=True
        )
        .add_extension(
            key_usage,
            critical=True
        )
        .add_extension(
            BasicConstraints(ca=False, path_length=None),
            critical=True
        )
    )
    
    if san:
        cert_builder = cert_builder.add_extension(san, critical=False)
    
    if isinstance(ca_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        cert = cert_builder.sign(ca_key, None)
    else:
        cert = cert_builder.sign(ca_key, hashes.SHA256(), default_backend())
    
    return cert

def main():
    parser = argparse.ArgumentParser(description="TLS certificates generator")
    parser.add_argument('--mode', choices=['server', 'client', 'root', 'csr'], default='server',
                       help='Generation mode: server, client, root, or csr')
    parser.add_argument('--key', '-k', default='server.key', type=str, help='Path to private key file')
    parser.add_argument('--cert', '-c', default='server.crt', type=str, help='Path to certificate file')
    parser.add_argument('--root-key', default='root.key', type=str, help='Path to root private key file')
    parser.add_argument('--root-cert', default='root.crt', type=str, help='Path to root certificate file')
    parser.add_argument('--key-type', choices=['rsa', 'ecdsa', 'dss', 'ed25519', 'ed448'], default='rsa',
                       help='Type of key to generate (rsa, ecdsa, dss, ed25519, ed448)')
    parser.add_argument('--client-id', default='client', type=str, help='Client ID for client certificate')
    parser.add_argument('--common-name', '-cn', default='localhost', type=str, 
                       help='Common Name for certificate')
    parser.add_argument('--csr', default='certificate.csr', type=str, help='Path to CSR file')
    parser.add_argument('--sign-csr', action='store_true', help='Sign a CSR file')
    parser.add_argument('--password', '-p', type=str, help='Password for private key')

    args = parser.parse_args()

    if args.mode == 'root':
        print("[*] Generating self-signed root {} certificate...".format(args.key_type.upper()))
        root_key, root_cert = generate_self_signed_cert(args.key_type)
        save_key_and_cert(root_key, root_cert, args.root_key, args.root_cert)
        print("[*] Done! Root certificate: {}, Root key: {}".format(args.root_cert, args.root_key))
    
    elif args.mode == 'server':
        if os.path.isfile(args.root_key) and os.path.isfile(args.root_cert):
            print("[*] Loading root certificate with key...")
            root_key, root_cert = load_key_and_cert(args.root_key, args.root_cert, args.password)
        else:
            print("[*] Generating self-signed {} root certificate...".format(args.key_type.upper()))
            root_key, root_cert = generate_self_signed_cert(args.key_type)
            save_key_and_cert(root_key, root_cert, args.root_key, args.root_cert)
        
        print("[*] Generating server credentials with {} key...".format(args.key_type.upper()))
        server_key, server_cert = generate_server_cert_with_ca(root_key, root_cert, args.key_type, args.common_name)
        save_key_and_cert(server_key, server_cert, args.key, args.cert)
        print("[*] Done! Certificate: {}, Key: {} (Type: {})".format(args.cert, args.key, args.key_type.upper()))
    
    elif args.mode == 'client':
        if not os.path.isfile(args.root_key) or not os.path.isfile(args.root_cert):
            print("[!] Root certificate and key are required for client certificate generation")
            print("[*] Generating root certificate first...")
            root_key, root_cert = generate_self_signed_cert(args.key_type)
            save_key_and_cert(root_key, root_cert, args.root_key, args.root_cert)
        else:
            print("[*] Loading root certificate with key...")
            root_key, root_cert = load_key_and_cert(args.root_key, args.root_cert, args.password)
        
        print("[*] Generating client credentials with {} key...".format(args.key_type.upper()))
        client_key, client_cert = generate_client_cert_with_ca(root_key, root_cert, args.key_type, args.client_id)
        save_key_and_cert(client_key, client_cert, args.key, args.cert)
        print("[*] Done! Client certificate: {}, Client key: {}".format(args.cert, args.key))
        print("[*] Client ID: {}".format(args.client_id))
    
    elif args.mode == 'csr':
        if args.sign_csr:
            if not os.path.isfile(args.root_key) or not os.path.isfile(args.root_cert):
                print("[!] Root certificate and key are required for signing CSR")
                return
            
            print("[*] Loading root certificate with key...")
            root_key, root_cert = load_key_and_cert(args.root_key, args.root_cert, args.password)
            
            print("[*] Loading CSR from {}...".format(args.csr))
            with open(args.csr, 'rb') as f:
                csr_data = f.read()
                csr = x509.load_pem_x509_csr(csr_data, default_backend())
            
            print("[*] Signing CSR...")
            cert_type = 'client' if 'client' in args.cert.lower() else 'server'
            cert = sign_csr_with_ca(csr, root_key, root_cert, cert_type)
            
            with open(args.cert, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            print("[*] Done! Signed certificate: {}".format(args.cert))
        else:
            print("[*] Generating {} key and CSR...".format(args.key_type.upper()))
            
            if args.key_type == 'rsa':
                key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            elif args.key_type == 'ecdsa':
                key = ec.generate_private_key(curve=ec.SECP256R1(), backend=default_backend())
            elif args.key_type == 'dsa':
                key = dsa.generate_private_key(key_size=1024, backend=default_backend())
            elif args.key_type == 'ed25519':
                key = ed25519.Ed25519PrivateKey.generate()
            elif args.key_type == 'ed448':
                key = ed448.Ed448PrivateKey.generate()
            
            csr = generate_certificate_signing_request(key, args.common_name, args.key_type)

            if isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
                encoded_key = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            else:
                encoded_key = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            
            with open(args.key, 'wb') as f:
                f.write(encoded_key)

            encoded_csr = csr.public_bytes(serialization.Encoding.PEM)
            with open(args.csr, 'wb') as f:
                f.write(encoded_csr)
            
            print("[*] Done! Private key: {}, CSR: {}".format(args.key, args.csr))

if __name__ == "__main__":
    main()