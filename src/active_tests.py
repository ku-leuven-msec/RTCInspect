import json
import sys
import argparse
import subprocess
import re

def run_command(command, timeout=60):
    """A helper function to run a command and capture its output."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr
    except FileNotFoundError:
        return None, f"Command '{command[0]}' not found. Make sure stunner is installed and in your system PATH."
    except subprocess.TimeoutExpired:
        return None, f"Command '{' '.join(command)}' timed out after {timeout} seconds."
    except Exception as e:
        return None, str(e)

def parse_stunner_info(output):
    """Extracts the SOFTWARE attribute from the stunner info output, searching the entire text."""
    match = re.search(r"SOFTWARE: (.*)", output)
    if match:
        return match.group(1).strip()
    return "Unknown"

def parse_brute_transports(output):
    """Extracts the supported transport protocols."""
    supported = []
    for line in output.splitlines():
        if "found supported protocol" in line.lower():
            print(f"    [MATCH] Found supported")
            match = re.search(r'protocol (\d+) which is (\w+)', line)
            if match:
                supported.append(f"{match.group(2)} (ID: {match.group(1)})")
    return supported if supported else ["None Found"]

def parse_pwd_brute(output):
    """Parses the password brute force output to identify successful attempts."""
    successful_attempts = []
    pattern = re.compile(r'Found valid credentials: (\w+):([^"]+)')

    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            credentials = {
                'username': match.group(1),
                'password': match.group(2)
            }
            successful_attempts.append(credentials)
            
    return successful_attempts


def parse_range_scan(output):
    """Parses the range-scan output to identify vulnerabilities."""
    vulnerable_ips = []
    forbidden_ips = []
    for line in output.splitlines():
        if "was successful" in line:
            match = re.search(r'UDP ([\d\.]+) was successful', line)
            if match:
                vulnerable_ips.append(match.group(1))
        elif "forbidden ip" in line.lower():
            forbidden_ips.append(line)
            
    return {
        "is_ssrf_vulnerable": len(vulnerable_ips) > 0,
        "allowed_relay_to_private_ips": vulnerable_ips,
        "correctly_forbidden_ip_count": len(forbidden_ips)
    }

def main(server, user, password, stunner_path, output_file, invasive_level):
    """Orchestrates the active probing tests with a credential pre-check."""
    print(f"[+] Starting active probe against TURN server: {server}")
    print(f"    Using Username: {user}")

    final_report = {
        "target_server": server,
        "credentials_used": {"username": user, "password": password},
        "authentication_check": {},
        "server_information": {},
        "supported_transports": [],
        "vulnerability_assessment": {}
    }
    
    # --- Step 1: Unauthenticated Info Check (Fingerprinting) ---
    print("  [INFO] Running unauthenticated 'stunner info' to fingerprint server...")
    info_command_unauth = [stunner_path, "info", "-s", server]
    info_stdout, info_stderr = run_command(info_command_unauth)
    software_version = parse_stunner_info(info_stdout) if info_stdout else "Error"
    final_report["server_information"]["software"] = software_version
    print(f"    [RESULT] Server Software: {software_version}")

    # --- Step 2: Authenticated Check (Credential Verification) ---
    authenticated = False
    failed = False
    if invasive_level > 1:
        print("  [INFO] Running authenticated 'brute-transports' to verify credentials and check transports...")
        auth_check_command = [stunner_path, "brute-transports", "-s", server, "-u", user, "-p", password]
        auth_stdout, auth_stderr = run_command(auth_check_command)
        if auth_stderr or "unauthorized" in (auth_stdout + auth_stderr).lower():
            print("    [FAIL] Credentials appear to be WRONG. Received an unauthorized error. See logs for details.")
            failed = True
            final_report["authentication_check"] = {
                "status": "Failed",
                "reason": "Received '401 Unauthorized' or other error during authenticated check.",
                "error_output": auth_stderr or auth_stdout
            }
            if invasive_level > 3 and not authenticated:
                print("  [INFO] Running: stunner password brute forcer...")
                scan_command = [stunner_path, "brute-password", "-s", server, "-u", user, "-p", "passes.txt"]
                scan_stdout, _ = run_command(scan_command, timeout=500)
                scan_results = parse_pwd_brute(scan_stdout) if scan_stdout else {"error": "Command failed"}
                if scan_results:
                    print(f"    [SUCCESS] Found valid credentials:")
                    authenticated = True
                    for creds in scan_results:
                        print(f"      - Username: {creds['username']}, Password: {creds['password']}")
                        user = creds['username']
                        password = creds['password']
                else:
                    print("    [FAIL] No valid credentials found in password brute force attempt.")
            # Write the partial report and exit early
            if not authenticated:
                with open(output_file, "w") as f: json.dump(final_report, f, indent=2)
                print("\n[+] Probe halted due to invalid credentials.")
                print(f"[+] Partial report saved to '{output_file}'")
                return

        print(f"    [SUCCESS] Credentials appear to be CORRECT. with username: {user} and password: {password}")
        authenticated = True
        final_report["authentication_check"]["status"] = "Successful"


        if failed:
            auth_check_command = [stunner_path, "brute-transports", "-s", server, "-u", user, "-p", password]
            auth_stdout, auth_stderr = run_command(auth_check_command)

            
        supported_transports = parse_brute_transports(auth_stdout)
        final_report["supported_transports"] = supported_transports
        print(f"    [RESULT] Supported Transports: {', '.join(supported_transports)}")

    # --- Step 4: Scan for SSRF Vulnerability ---
    if invasive_level > 2:
        print("  [INFO] Running: stunner range-scan...")
        scan_command = [stunner_path, "range-scan", "-s", server, "-u", user, "-p", password]
        print( f"    [CMD] {' '.join(scan_command)}")
        scan_stdout, _ = run_command(scan_command, timeout=120)
        scan_results = parse_range_scan(scan_stdout) if scan_stdout else {"error": "Command failed"}
        final_report["vulnerability_assessment"] = scan_results
        if scan_results.get("is_ssrf_vulnerable"):
            print(f"    [CRITICAL] Vulnerability Found! Server allows relaying to private IPs.")
        else:
            print(f"    [SUCCESS] Server appears correctly configured against SSRF.")

    # --- Consolidate and Save Report ---
    with open(output_file, "w") as f:
        json.dump(final_report, f, indent=2)
    
    print("\n" + "="*50 + "\nACTIVE PROBE COMPLETE\n" + "="*50)
    print(f"[+] Full active probe report saved to '{output_file}'")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Actively probes a TURN server for security misconfigurations.")
    parser.add_argument("-s", "--server", required=True, help="TURN server address and port (e.g., 10.129.176.35:3478)")
    parser.add_argument("-u", "--user", required=True, help="TURN username")
    parser.add_argument("-p", "--password", required=True, help="TURN password")
    parser.add_argument("--stunner-path", default="stunner", help="Path to the stunner executable (if not in system PATH)")
    parser.add_argument("-o", "--output-file", default="active_probe_report.json", help="Output JSON file for the report")
    parser.add_argument("-i", "--invasive", default=3, help="Invasive level of the test (1-3, default 3).")
    args = parser.parse_args()

    main(args.server, args.user, args.password, args.stunner_path, args.output_file, int(args.invasive))

    # Example usage:
    #  python active_tests.py --server 10.129.176.35:3478 --user testuser --password testpwd --output-file ./results/test_report.json --invasive 4