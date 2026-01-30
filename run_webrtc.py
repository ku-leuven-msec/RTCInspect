import os
import subprocess
import pathlib
import sys

# --- Configuration ---
# Set to True to see commands without running them.
DRY_RUN = False

WEBRTC_SCRIPT_PATH = "./src/connection_analyzer.py"
OUTPUT_FILENAME = "connection_analysis.json"
PCAPS_BASE_DIR = pathlib.Path("./pcaps")
RESULTS_BASE_DIR = pathlib.Path("./results")

# --- EXCLUSION LIST ---
# Add folder or device names here to skip them during the analysis.
# The script will check if a pcap's relative path STARTS WITH any of these strings.
#
# Example:
#   'digitus'        -> excludes everything in the 'pcaps/digitus/' folder
#   'eufy/Homebase1' -> excludes only the 'Homebase1' subfolder within 'eufy'
#
# Note: Use forward slashes '/' for paths, even on Windows, for consistency.
EXCLUDE_LIST = [
     "googlemeet",
     "jitsi",
     "messenger",
     "Zoom",
     "slack",
     "teams",
     "snapchat",
     "discord",
     "webex",
     "whereby",
]


# --- Main Logic ---
def main():
    """
    Reruns the webrtc.py script on all pcap files, skipping any paths
    defined in the EXCLUDE_LIST.
    """
    print(f"--- Starting WebRTC Analysis Rerun ---")
    
    python_executable = sys.executable
    print(f"Using Python interpreter: {python_executable}")

    # --- Pre-run Checks and file gathering ---
    # ... (rest of the pre-run checks remain the same) ...
    if not pathlib.Path(WEBRTC_SCRIPT_PATH).is_file():
        print(f"Error: The script '{WEBRTC_SCRIPT_PATH}' was not found.")
        return
    if not PCAPS_BASE_DIR.is_dir():
        print(f"Error: The pcaps directory '{PCAPS_BASE_DIR}' was not found.")
        return
    
    pcap_files = list(PCAPS_BASE_DIR.rglob("*.pcap")) + list(PCAPS_BASE_DIR.rglob("*.pcapng"))
    if not pcap_files:
        print(f"No .pcap or .pcapng files found in '{PCAPS_BASE_DIR}'.")
        return

    print(f"\nFound {len(pcap_files)} total pcap files.")
    if EXCLUDE_LIST:
        print(f"Exclusion rules are active: {EXCLUDE_LIST}")
    print("")

    # --- Processing Loop ---
    processed_count = 0
    for i, pcap_path in enumerate(pcap_files):
        
        # --- Exclusion Check ---
        relative_pcap_path = pcap_path.relative_to(PCAPS_BASE_DIR)
        # Use as_posix() to ensure consistent forward slashes for path comparison
        relative_path_str = relative_pcap_path.as_posix()
        
        is_excluded = False
        for exclusion_path in EXCLUDE_LIST:
            if relative_path_str.startswith(exclusion_path):
                print(f"--- File {i+1}/{len(pcap_files)}: {pcap_path} ---")
                print(f"--> SKIPPING: Path '{relative_path_str}' matches exclusion rule '{exclusion_path}'.\n")
                is_excluded = True
                break # Found a match, no need to check other rules
        
        if is_excluded:
            continue # Move to the next pcap file
        
        # --- If not excluded, proceed with processing ---
        processed_count += 1
        print(f"--- Processing file {i+1}/{len(pcap_files)} ({processed_count} to be run) ---")
        print(f"Input pcap: {pcap_path}")
        
        # 1. Calculate the final output JSON path
        pcap_id = pcap_path.stem
        sub_path = relative_pcap_path.parent
        output_json_path = RESULTS_BASE_DIR / sub_path / pcap_id / OUTPUT_FILENAME
        print(f"Output JSON: {output_json_path}")

        # 2. Construct the command to execute
        command = [
            python_executable,
            WEBRTC_SCRIPT_PATH,
            str(pcap_path),
            str(output_json_path)
        ]
        pretty_command = " ".join(f'"{os.path.normpath(arg)}"' if " " in arg else os.path.normpath(arg) for arg in command)
        print(f"Command: {pretty_command}")

        if not DRY_RUN:
            # 3. Ensure the parent directory exists and execute
            output_json_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                result = subprocess.run(command, check=True, capture_output=True, text=True, encoding='utf-8')
                print("Status: SUCCESS - webrtc_analysis.json has been overwritten.")
                if result.stdout:
                    print(f"Output from {WEBRTC_SCRIPT_PATH}:\n{result.stdout.strip()}")
            except subprocess.CalledProcessError as e:
                print(f"Status: FAILED (Exit code: {e.returncode})")
                print(f"--- Error output from {WEBRTC_SCRIPT_PATH} ---\n{e.stderr.strip()}\n---------------------------------")
        else:
            print("Status: SKIPPED (Dry Run)")
        
        print("")

    print(f"--- WebRTC rerun script finished. Processed {processed_count} files. ---")


if __name__ == "__main__":
    main()