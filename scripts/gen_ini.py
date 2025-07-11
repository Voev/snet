import argparse
import sys

def generate_ini(count, input_file, output_file):
    """Generate INI file with TLS cipher suite configurations.
    
    Args:
        input_file (str): Path to file containing cipher suites (one per line)
        output_file (str): Path where to save the generated INI file
    """
    try:
        # Read cipher suites from input file, ignoring empty lines
        with open(input_file, 'r') as f:
            ciphersuites = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found", file=sys.stderr)
        sys.exit(1)

    # Generate INI file with sections for each cipher suite
    with open(output_file, 'w') as f:
        for cipher in ciphersuites:
            # Format each section according to specifications
            section = f"[decrypt_by_keylog.{cipher}]\n"
            pcap = f"pcap = ./tests/pcap/data/decrypt_by_keylog/tls_{cipher}.pcap\n"
            keylog = f"keylog = ./tests/pcap/data/decrypt_by_keylog/keylog_{cipher}.txt\n"
            records = f"decrypted_records_count = {count}\n"
            
            # Write section to output file
            f.write(section)
            f.write(pcap)
            f.write(keylog)
            f.write(records)
            f.write("\n")  # Add empty line between sections

    print(f"Successfully generated INI file: {output_file}")

if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description='Generate INI file for TLS cipher suites')
    parser.add_argument('-i', '--input', required=True,
                       help='Input file containing cipher suites (one per line)')
    parser.add_argument('-o', '--output', default='tls_ciphersuites.ini',
                       help='Output INI file (default: tls_ciphersuites.ini)')
    parser.add_argument('-c', '--count', default=13,
                       help='Decrypted record count (default: 13)')

    args = parser.parse_args()
    generate_ini(args.count, args.input, args.output)