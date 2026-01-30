import sys
import os
import subprocess
import json
import argparse
from pathlib import Path

# --- Configuration ---
# All scripts are now in a single list to be run unconditionally.
ANALYSIS_SCRIPTS = [
    {"name": "src/signaling.py", "description": "Analyzing Signaling Traffic..."},
    {"name": "src/stun.py",      "description": "Analyzing STUN Traffic..."},
    {"name": "src/turn.py",      "description": "Analyzing TURN Traffic..."},
    #{"name": "src/ice.py",       "description": "Analyzing ICE Connectivity Checks..."},
    {"name": "src/certs.py",     "description": "Analyzing All TLS/DTLS Certificates..."},
    {"name": "src/webrtc.py",    "description": "Analyzing for WebRTC (DTLS/SRTP)..."},
    {"name": "src/stream.py",    "description": "Analyzing for heavy media streams (RTP, etc.)..."}
]

def run_analysis_script(script_name, pcap_path, output_path):
    """
    Executes a given analysis script using the same Python interpreter.
    Returns True on success, False on failure.
    """
    command = [
        sys.executable,
        script_name,
        str(pcap_path),
        str(output_path)
    ]
    
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        return True
    except FileNotFoundError:
        print(f"    [ERROR] Script not found: {script_name}. Make sure it's in the same directory.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"    [ERROR] Script '{script_name}' failed with exit code {e.returncode}.")
        print("    ------- SCRIPT ERROR OUTPUT -------")
        print(e.stderr)
        print("    -----------------------------------")
        return False

def main(pcap_file, output_dir):
    pcap_path = Path(pcap_file)
    output_path = Path(output_dir)

    if not pcap_path.exists():
        print(f"[FATAL] Input PCAP file not found: {pcap_path}")
        sys.exit(1)

    # Create nested output directory if needed
    output_path.mkdir(parents=True, exist_ok=True)
    print(f"[INFO] Analysis results will be saved in: {output_path.resolve()}")
    print("="*60)

    # --- Run ALL Analysis Scripts from the list ---
    for script_info in ANALYSIS_SCRIPTS:
        script_name = script_info["name"]
        description = script_info["description"]
        # Create output filename based on the script name (e.g., signaling.py -> signaling_analysis.json)
        output_file = output_path / f"{Path(script_name).stem}_analysis.json"
        
        print(f"[+] Running: {description}")
        if run_analysis_script(script_name, pcap_path, output_file):
            print(f"    [SUCCESS] Report saved to {output_file.name}")
        else:
            # Use split to get the core name without the "..."
            print(f"    [FAILURE] Could not complete {description.split('...')[0]}.")
        print("-"*60)

    print("="*60)
    print("[+] All analysis complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A master script to run a full STUN/TURN/ICE/WebRTC security analysis pipeline.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("pcap_file", help="The input PCAP or PCAPNG file to analyze.")
    parser.add_argument("-o", "--output-dir", default="analysis_results", help="The directory to save all JSON reports (default: analysis_results).")
    args = parser.parse_args()
    
    main(args.pcap_file, args.output_dir)

    # Example usage:
    # python main.py '.\pcaps\Eufy\Homebase2\Opstart_Homebase_WEBVIEWER -External.pcapng' --output-dir .\results\eufyResults\Homebase2\Webviewer
