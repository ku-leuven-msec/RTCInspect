import os
import subprocess
import pathlib
import sys # <-- Import the sys module

# --- Configuration ---
# Set to True to see commands without running them.
# Set to False to execute commands.
DRY_RUN = False

# Base directories
# The script assumes it's being run from the root of your project.
PCAPS_BASE_DIR = pathlib.Path("./pcaps")
RESULTS_BASE_DIR = pathlib.Path("./results")
MAIN_SCRIPT_PATH = "main_webapp.py"

# --- Main Logic ---
def main():
    """
    Finds all pcap files and runs the analysis script on them,
    organizing the results as requested.
    """
    print("--- Starting PCAP Analysis Automation ---")
    
    # --- Pre-run Checks ---
    # Find the Python interpreter that is running THIS script
    python_executable = sys.executable
    print(f"Using Python interpreter: {python_executable}")

    if not pathlib.Path(MAIN_SCRIPT_PATH).is_file():
        print(f"Error: The main script '{MAIN_SCRIPT_PATH}' was not found.")
        print("Please make sure this automation script is in the same directory as main.py.")
        return

    if not PCAPS_BASE_DIR.is_dir():
        print(f"Error: The pcaps directory '{PCAPS_BASE_DIR}' was not found.")
        return

    # Find all .pcap and .pcapng files recursively
    pcap_files = list(PCAPS_BASE_DIR.rglob("*.pcap")) + list(PCAPS_BASE_DIR.rglob("*.pcapng"))

    if not pcap_files:
        print(f"No .pcap or .pcapng files found in '{PCAPS_BASE_DIR}'.")
        return

    print(f"\nFound {len(pcap_files)} pcap files to process.\n")

    # --- Processing Loop ---
    for i, pcap_path in enumerate(pcap_files):
        print(f"--- Processing file {i+1}/{len(pcap_files)} ---")
        print(f"Input file: {pcap_path}")

        # 1. Determine the output directory structure
        relative_pcap_path = pcap_path.relative_to(PCAPS_BASE_DIR)
        pcap_id = pcap_path.stem
        sub_path = relative_pcap_path.parent
        output_dir = RESULTS_BASE_DIR / sub_path / pcap_id

        print(f"Output dir: {output_dir}")

        # 2. Construct the command to execute
        # THE KEY CHANGE: Use sys.executable instead of "python"
        command = [
            python_executable,      # <-- Use the full path to the correct Python
            MAIN_SCRIPT_PATH,
            str(pcap_path),
            "--output-dir",
            str(output_dir)
        ]
        
        pretty_command = " ".join(f'"{os.path.normpath(arg)}"' if " " in arg else os.path.normpath(arg) for arg in command)
        print(f"Executing: {pretty_command}")

        if not DRY_RUN:
            # 3. Create the output directory
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # 4. Execute the command
            try:
                # subprocess.run waits for the command to complete.
                result = subprocess.run(
                    command,
                    check=True,          # Raises an error if the command fails
                    capture_output=True, # Captures stdout and stderr
                    text=True,           # Decodes stdout/stderr as text
                    encoding='utf-8'     # Specify encoding for cross-platform compatibility
                )
                print("Status: SUCCESS")
                if result.stdout:
                    print("--- Output from main.py ---")
                    print(result.stdout.strip())
                    print("--------------------------")

            except subprocess.CalledProcessError as e:
                # This block runs if main.py returns a non-zero exit code (i.e., it crashed)
                print(f"Status: FAILED (Exit code: {e.returncode})")
                print("--- Error output from main.py ---")
                # Print both stdout and stderr from the failed process for better debugging
                if e.stdout:
                    print("--- STDOUT ---")
                    print(e.stdout.strip())
                if e.stderr:
                    print("--- STDERR ---")
                    print(e.stderr.strip())
                print("---------------------------------")
                # Optional: you might want to stop the whole script if one file fails
                # print("\nStopping automation due to error.")
                # break 
        else:
            print("Status: SKIPPED (Dry Run)")
        
        print("") # Add a newline for better readability

    print("--- Automation script finished. ---")

if __name__ == "__main__":
    main()