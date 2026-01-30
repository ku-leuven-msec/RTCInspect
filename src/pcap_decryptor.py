import subprocess
import os
import sys

# --- Configuration ---
# Update these paths to match your system and files as needed.
# You might need the full path to tshark if it's not in your system's PATH.
TSHARK_PATH = "tshark"  # or "C:\\Program Files\\Wireshark\\tshark.exe" on Windows
INPUT_PCAP = "encrypted_traffic.pcapng"
KEYLOG_FILE = "ssl_keys.log"
OUTPUT_PCAP = "decrypted_traffic.pcap"
# --- End of Configuration ---

def decrypt_pcap(tshark_path, input_pcap, keylog_file, output_pcap):
    """
    Uses TShark to decrypt a PCAP file using an SSL key log file.
    
    Args:
        tshark_path (str): The path to the tshark executable.
        input_pcap (str): The path to the encrypted input pcap file.
        keylog_file (str): The path to the SSL key log file.
        output_pcap (str): The path where the decrypted pcap will be saved.
    """
    print("--- PCAP Decryption Utility ---")

    # 1. Validate that the necessary files exist
    if not os.path.exists(input_pcap):
        print(f"Error: Input PCAP file not found at '{input_pcap}'")
        sys.exit(1)
        
    if not os.path.exists(keylog_file):
        print(f"Error: Key log file not found at '{keylog_file}'")
        sys.exit(1)

    print(f"[*] Input file:  {input_pcap}")
    print(f"[*] Key log file: {keylog_file}")
    print(f"[*] Output file: {output_pcap}")

    # 2. Construct the TShark command
    # Using a list of arguments is safer than a single command string
    command = [
        tshark_path,
        "-r", input_pcap,
        "-o", f"ssl.keylog_file:{keylog_file}",
        "-w", output_pcap
    ]

    print("\n[+] Running TShark command...")
    print(f"    > {' '.join(command)}")

    # 3. Execute the command
    try:
        process = subprocess.run(
            command,
            check=True,  # This will raise a CalledProcessError if tshark returns a non-zero exit code
            capture_output=True,
            text=True
        )
        print("\n[SUCCESS] Decryption complete!")
        print(f"Decrypted file saved to '{output_pcap}'")
        if process.stderr:
            print("\nTShark Warnings/Info:")
            print(process.stderr)
            
    except FileNotFoundError:
        print(f"\n[ERROR] TShark executable not found at '{tshark_path}'.")
        print("Please ensure Wireshark is installed and tshark is in your system's PATH,")
        print("or update the TSHARK_PATH variable in the script.")
        sys.exit(1)
        
    except subprocess.CalledProcessError as e:
        print("\n[ERROR] TShark failed to execute.")
        print(f"Return Code: {e.returncode}")
        print("TShark Output (stderr):")
        print(e.stderr)
        sys.exit(1)

if __name__ == "__main__":
    # Ensure the script is being run from the correct directory or paths are absolute
    # For simplicity, this example assumes all files are in the same directory.
    decrypt_pcap(TSHARK_PATH, INPUT_PCAP, KEYLOG_FILE, OUTPUT_PCAP)
