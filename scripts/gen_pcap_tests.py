#!/usr/bin/env python3

import subprocess
import time
import os
import signal
from pathlib import Path
import argparse

TLS_VERSION = "tls1_2"
DATA_SIZE = 256
MESSAGE_COUNT = 10
DELAY_BETWEEN_TESTS = 2

def load_ciphersuites(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def run_test(ciphersuite, tls_version, data_size, message_count):
    safe_cipher = ciphersuite.replace('/', '_').replace('+', '_')
    keylog_file = f"keylog_{safe_cipher}.txt"
    pcap_file = f"tls_{safe_cipher}.pcap"
    
    print(f"\n\033[1mTesting cipher: {ciphersuite}\033[0m")
    
    try:
        result = subprocess.run([
            "sudo", "python3", "gen_pcap_test.py",
            "--cipher", ciphersuite,
            "--tls-version", tls_version,
            "--keylog", keylog_file,
            "--pcap", pcap_file,
            "--data-size", str(data_size),
            "--message-count", str(message_count)
        ], check=True)
        
        print("Test completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Test failed for cipher: {ciphersuite}")
        with open("failed_tests.log", "a") as f:
            f.write(f"{ciphersuite}\n")
        return False

def main():
    parser = argparse.ArgumentParser(description='Iterative TLS handshake tests with tcpdump capture')
    parser.add_argument('-i', '--input', required=True,
                       help='Input TLS cipher suites list file path')

    args = parser.parse_args()
    if not shutil.which("openssl"):
        print("Error: openssl not found!")
        return 1
        
    if not Path("gen_pcap_test.py").exists():
        print("Error: gen_pcap_test.py not found!")
        return 1

    print(f"Starting TLS cipher tests for {TLS_VERSION}...")
    print("=" * 50)

    try:
        ciphersuites = load_ciphersuites(args.input)
    except FileNotFoundError:
        print(f"Error: File {args.input} not found!")
        return 1

    for cipher in ciphersuites:
        run_test(cipher, TLS_VERSION, DATA_SIZE, MESSAGE_COUNT)
        time.sleep(DELAY_BETWEEN_TESTS)

    print("\nAll tests completed!")

if __name__ == "__main__":
    import shutil
    main()