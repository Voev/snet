import argparse
import subprocess
import time
import os
import signal
import sys
from pathlib import Path

def find_cert_files(key_type, cert_type):
    # First check certs_<type>/ structure
    cert_dir = f"certs_{key_type}"
    
    if Path(cert_dir).exists():
        key_file = Path(cert_dir) / f"{cert_type}_{key_type}.key"
        cert_file = Path(cert_dir) / f"{cert_type}_{key_type}.crt"
        ca_file = Path(cert_dir) / f"ca_{key_type}.crt"
    else:
        # Check alternative structure
        cert_dir = f"{key_type}_certs"
        if Path(cert_dir).exists():
            key_file = Path(cert_dir) / f"{cert_type}.key"
            cert_file = Path(cert_dir) / f"{cert_type}.crt"
            ca_file = Path(cert_dir) / f"ca.crt"
        else:
            # Look for files in current directory
            key_file = Path(f"{cert_type}.{key_type}.key")
            cert_file = Path(f"{cert_type}.{key_type}.crt")
            ca_file = Path(f"ca.{key_type}.crt")
            
            if not key_file.exists():
                key_file = Path(f"{cert_type}.key")
                cert_file = Path(f"{cert_type}.crt")
                ca_file = Path("ca.crt")
    
    return str(key_file), str(cert_file), str(ca_file)

def run_tcpdump(output_file):
    """Starts tcpdump to capture traffic on port 8443"""
    try:
        # Check if tcpdump exists
        result = subprocess.run(["which", "tcpdump"], capture_output=True, text=True)
        if result.returncode != 0:
            print("[!] tcpdump not found.")
            return None
        
        # Create output directory if needed
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        cmd = [
            "sudo",
            "tcpdump",
            "-i", "lo",           # Loopback interface
            "-w", output_file,    # Output file
            "port", "8443",       # Port filter
            "-U",                 # Unbuffered output
            "-s", "0",            # Capture full packets
            "-q"                  # Quiet mode (less output)
        ]
        
        print(f"[*] Command: {' '.join(cmd)}")
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            time.sleep(1)

            if process.poll() is None:
                print(f"[+] tcpdump started!")
                return process
            else:
                return None
        except Exception as e:
            print(f"[!] Error starting tcpdump: {e}")
            return None
        
    except Exception as e:
        print(f"[!] Error: {e}")
        return None

def run_openssl_server(tls_cipher, tls_version, keylog, key_type):
    """Starts OpenSSL server"""
    server_key, server_cert, ca_cert = find_cert_files(key_type, "server")

    if not Path(server_key).exists():
        raise FileNotFoundError(f"Server key file not found: {server_key}")
    if not Path(server_cert).exists():
        raise FileNotFoundError(f"Server certificate not found: {server_cert}")
    
    keylog_path = Path(keylog)
    keylog_path.parent.mkdir(parents=True, exist_ok=True)
    

    cmd = [
        "openssl", "s_server",
        "-accept", "127.0.0.1:8443",
        "-cert", server_cert,
        "-key", server_key,
        "-keylogfile", keylog,
        "-no_ticket",
        "-quiet"
    ]
        
    if Path(ca_cert).exists():
        cmd += ["-CAfile", ca_cert, "-Verify", "5"]  # Using -Verify instead of -verify
    else:
        print(f"[!] CA certificate not found, disabling client verification")
        cmd += ["-verify", "0"]  # Disable client certificate verification

    cmd += tls_cipher
    cmd += tls_version

    print(f"[*] Server command: {' '.join(cmd)}...")

    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

def run_openssl_client(tls_cipher, tls_version, data_size, message_count, key_type):
    """Starts OpenSSL client"""
    # Find client certificate files
    client_key, client_cert, ca_cert = find_cert_files(key_type, "client")
    
    print(f"[*] Client key: {client_key}")
    print(f"[*] Client certificate: {client_cert}")
    
    # Check if client files exist
    if not Path(client_key).exists() or not Path(client_cert).exists():
        print(f"[!] Client files not found")
        print(f"[*] Starting client without authentication")
        use_client_cert = False
    else:
        use_client_cert = True
    
    test_data = b"A" * data_size + b"\n"
    end_marker = b"Q\r\n"

    cmd = [
        "openssl", "s_client",
        "-connect", "127.0.0.1:8443",
        "-quiet",
    ]
    
    if use_client_cert:
        cmd += ["-cert", client_cert, "-key", client_key]
    
    # Add CA file if exists
    if Path(ca_cert).exists():
        cmd += ["-CAfile", ca_cert]
        cmd += ["-verify_return_error"]
    
    # Add cipher and TLS version parameters
    cmd += tls_cipher
    cmd += tls_version

    try:
        print(f"[*] Client command: {' '.join(cmd)}")
        
        # Start client
        client = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False
        )

        # Check if client is still running
        if client.poll() is not None:
            stdout, stderr = client.communicate()
            print(f"[!] Client terminated unexpectedly")
            if stderr:
                error_msg = stderr.decode('utf-8', errors='ignore')
                print(f"    Error: {error_msg[:200]}")
            return False

        print(f"[+] Connection established, sending {message_count} messages...")

        # Send test data
        for i in range(message_count):
            client.stdin.write(test_data)
            client.stdin.flush()
            print(f"[+] Sent message {i+1}/{message_count} ({data_size} bytes)")
            time.sleep(0.1)  # Increase delay
        
        # Send termination marker
        client.stdin.write(end_marker)
        print("[+] Sent termination marker 'Q'")
        
        # Give time for data transmission
        time.sleep(2)
        
        # Close client
        client.stdin.close()
        
        # Read output with timeout
        try:
            stdout, stderr = client.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            print("[!] Client response timeout")
            client.terminate()
            stdout, stderr = client.communicate()

        # Print result
        if stdout:
            stdout_str = stdout.decode('utf-8', errors='ignore')
            if "CONNECTED" in stdout_str:
                print(f"[+] TLS handshake successful!")
            elif "Verify return code" in stdout_str:
                print(f"[+] Certificate verification successful!")
            else:
                # Show first few lines
                lines = stdout_str.split('\n')
                for line in lines[:5]:
                    if line.strip():
                        print(f"    {line}")
        
        if stderr:
            stderr_str = stderr.decode('utf-8', errors='ignore')
            if stderr_str.strip():
                print(f"[*] Client stderr output:")
                lines = stderr_str.split('\n')
                for line in lines[:10]:
                    if line.strip():
                        print(f"    {line}")
        
        return True

    except Exception as e:
        print(f"[!] Client error: {e}")
        return False
    finally:
        if 'client' in locals():
            try:
                client.terminate()
            except:
                pass

def main():
    parser = argparse.ArgumentParser(description="TLS handshake test with tcpdump capture")
    parser.add_argument("--cipher", required=True, help="Ciphersuite")
    parser.add_argument("--tls-version", required=True, help="TLS version (tls1, tls1_1, tls1_2, tls1_3)")
    parser.add_argument("--key-type", choices=['rsa', 'ecdsa', 'dss', 'ed25519', 'ed448'], 
                       help="Key type (auto-detected from cipher if not specified)")
    parser.add_argument("--keylog", default="keylog.txt", help="Keylog dump file")
    parser.add_argument("--pcap", default="tls_capture.pcap", help="PCAP file path")
    parser.add_argument("--data-size", type=int, default=256, help="Sending data buffer size")
    parser.add_argument("--message-count", type=int, default=10, help="Message count")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    # Determine key type
    if args.key_type:
        key_type = args.key_type
    else:
        # Simplified key type detection logic
        cipher_lower = args.cipher.lower()
        if 'ecdsa' in cipher_lower:
            key_type = 'ecdsa'
        elif 'dss' in cipher_lower:
            key_type = 'dss'
        elif 'ed25519' in cipher_lower:
            key_type = 'ed25519'
        elif 'ed448' in cipher_lower:
            key_type = 'ed448'
        else:
            key_type = 'rsa'
        print(f"[*] Auto-detected key type: {key_type}")

    # Check certificate existence
    print(f"[*] Looking for certificates for key type: {key_type}")
    
    server_key, server_cert, _ = find_cert_files(key_type, "server")
    
    if not Path(server_key).exists():
        print(f"[!] ERROR: Server key not found: {server_key}")
        print(f"[*] Check certificate availability:")
        print(f"    - certs_{key_type}/server_{key_type}.key")
        print(f"    - certs_{key_type}/server_{key_type}.crt")
        print(f"    - or {key_type}_certs/server.key")
        return 1
    
    if not Path(server_cert).exists():
        print(f"[!] ERROR: Server certificate not found: {server_cert}")
        return 1
    
    print(f"[+] Found server files: {server_key}, {server_cert}")

    try:
        if args.tls_version == "tls1_3":
            cipher_cmd = ["-ciphersuites", args.cipher]
        else:
            cipher_cmd = ["-cipher", args.cipher]
        
        version_cmd = [f"-{args.tls_version}"]

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        pcap_file = f"{args.pcap.replace('.pcap', '')}_{key_type}_{timestamp}.pcap"
        keylog_file = f"{args.keylog.replace('.txt', '')}_{key_type}_{timestamp}.txt"
        
        print(f"\n{'='*60}")
        print(f"STARTING TLS TEST")
        print(f"{'='*60}")
        print(f"[*] Cipher: {args.cipher}")
        print(f"[*] TLS Version: {args.tls_version}")
        print(f"[*] Key Type: {key_type}")
        print(f"[*] Data Size: {args.data_size} bytes")
        print(f"[*] Message Count: {args.message_count}")
        
        tcpdump_proc = None
        print(f"\n[*] Starting tcpdump...")
        tcpdump_proc = run_tcpdump(pcap_file)
        if tcpdump_proc:
            time.sleep(2)
        else:
            print(f"[*] Packet capture not started")

        print(f"\n[*] Starting OpenSSL server...")
        server_proc = run_openssl_server(cipher_cmd, version_cmd, keylog_file, key_type)
        time.sleep(2)

        if server_proc.poll() is not None:
            stdout, stderr = server_proc.communicate()
            print(f"[!] Server failed to start!")
            if stderr:
                error_msg = stderr[:500]
                print(f"    Error: {error_msg}")
            return 1
        
        print(f"[+] Server running on 127.0.0.1:8443")

        print(f"\n[*] Starting OpenSSL client...")
        success = run_openssl_client(cipher_cmd, version_cmd, args.data_size, args.message_count, key_type)
        time.sleep(2)
        
        if success:
            print(f"\n[+] TEST COMPLETED SUCCESSFULLY!")
        else:
            print(f"\n[!] TEST COMPLETED WITH ERRORS!")

        server_proc.terminate()

    except KeyboardInterrupt:
        print(f"\n[!] Test interrupted by user")
        return 1
    except Exception as e:
        print(f"[!] Error during test: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        print("[*] Stopping processes...")
        if 'server_proc' in locals():
            server_proc.terminate()
        if 'tcpdump_proc' in locals():
            os.killpg(os.getpgid(tcpdump_proc.pid), signal.SIGTERM)
        print(f"[*] PCAP file path: {args.pcap}")
        print(f"[*] Keylog file path: {args.keylog}")

    return 0

if __name__ == "__main__":
    sys.exit(main())