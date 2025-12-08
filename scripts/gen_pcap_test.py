import argparse
import subprocess
import time
import os
import signal
from pathlib import Path

def run_tcpdump(output_file):
    try:
        cmd = [
            "sudo", "tcpdump",
            "-i", "lo",
            "-w", output_file,
            "port", "8443"
        ]
        return subprocess.Popen(cmd, preexec_fn=os.setsid)
    except Exception as e:
        print(f"[!] Failed to start tcpdump: {e}")
        raise

def run_openssl_server(tls_cipher, tls_version, keylog, key_file, cert_file):

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
        "-cert", cert_file,
        "-key", key_file,
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
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def run_openssl_client(tls_cipher, tls_version, data_size, message_count):
    test_data = b"A" * data_size + b"\n"
    end_marker = b"Q\r\n"

    cmd = [
        "openssl", "s_client",
        "-connect", "127.0.0.1:8443",
    ]

    cmd += tls_cipher
    cmd += tls_version

    try:
        print("Client args: ", cmd)
        client = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False
        )
        
        for i in range(message_count):
            client.stdin.write(test_data)
            client.stdin.flush()
            print(f"[+] Sent message {i+1}/{message_count}")
            time.sleep(0.1)

        client.stdin.write(end_marker)
        client.stdin.flush()
        print("[+] Sent termination marker 'Q'")

        time.sleep(1)

        client.stdin.close()
        client.wait(timeout=5)

    except Exception as e:
        print(f"[!] Client error: {e}")

def main():
    parser = argparse.ArgumentParser(description="TLS handshake test with tcpdump capture")
    parser.add_argument("--cipher", required=True, help="Ciphersuite")
    parser.add_argument("--tls-version", required=True, help="TLS version (tls1, tls1_1, tls1_2, tls1_3)")
    parser.add_argument("--keylog", default="keylog.txt", help="Keylog dump file")
    parser.add_argument("--server-key", default="server.key", help="Server private key file")
    parser.add_argument("--server-cert", default="server.crt", help="Server certificate file")
    parser.add_argument("--pcap", default="tls_capture.pcap", help="PCAP file path")
    parser.add_argument("--data-size", type=int, default=256, help="Sending data buffer size")
    parser.add_argument("--message-count", type=int, default=10, help="Message count")
    args = parser.parse_args()

    try:
        if args.tls_version == "tls1_3":
            cipher_cmd = ["-ciphersuites", f"{args.cipher}"]
        else:
            cipher_cmd = ["-cipher", f"{args.cipher}@SECLEVEL=0"]

        version_cmd = [f"-{args.tls_version}"]

        print(f"[*] Run tcpdump, writing in {args.pcap}...")
        tcpdump_proc = run_tcpdump(args.pcap)
        time.sleep(2)

        print(f"[*] Running openssl s_server...")
        server_proc = run_openssl_server(cipher_cmd, version_cmd, args.keylog, 
                                         args.server_key, args.server_cert)
        time.sleep(2)
        
        print(f"[*] Running openssl s_client...")
        run_openssl_client(cipher_cmd, version_cmd, args.data_size, args.message_count)

    except Exception as e:
        print(f"[!] Error during test: {e}")
    finally:
        print("[*] Stopping processes...")
        if 'server_proc' in locals():
            server_proc.terminate()
        if 'tcpdump_proc' in locals():
            os.killpg(os.getpgid(tcpdump_proc.pid), signal.SIGTERM)
        print(f"[*] PCAP file path: {args.pcap}")
        print(f"[*] Keylog file path: {args.keylog}")

if __name__ == "__main__":
    main()