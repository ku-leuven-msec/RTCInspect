# credential_verifier.py
import json
import sys
import argparse
import hashlib
import hmac
from tqdm import tqdm

def find_attribute(payload_bytes, attr_type_code):
    """Finds the starting offset of a specific attribute in a STUN/TURN payload."""
    offset = 20  # Attributes start after the 20-byte header
    while offset < len(payload_bytes):
        try:
            current_attr_type = int.from_bytes(payload_bytes[offset:offset+2], 'big')
            if current_attr_type == attr_type_code:
                return offset
            attr_len = int.from_bytes(payload_bytes[offset+2:offset+4], 'big')
            offset += 4 + ((attr_len + 3) & ~3) # Move to next attribute, accounting for padding
        except IndexError:
            break
    return None

def verify_message_integrity(turn_packet, password, realm):
    """
    Calculates and verifies the MESSAGE-INTEGRITY of a TURN packet using the provided password.
    Returns True if the verification succeeds, False otherwise.
    """
    try:
        # We need the username and realm from the packet's parsed attributes
        creds = turn_packet.get("credentials", {})
        username = creds.get("username")
        if not all([username, realm, password]):
            return False

        # Step 1: Calculate the HMAC key
        key_string = f"{username}:{realm}:{password}".encode('utf-8')
        key = hashlib.md5(key_string).digest()

        # Step 2: Prepare the message for hashing
        payload_bytes = bytes.fromhex(turn_packet["raw_payload_hex"])
        
        # The HMAC is calculated over the message *before* the MESSAGE-INTEGRITY attribute
        integrity_offset = find_attribute(payload_bytes, 0x0008) # 0x0008 is MESSAGE-INTEGRITY
        if integrity_offset is None:
            return False
            
        message_to_hash_prefix = payload_bytes[:integrity_offset]
        
        # The message length in the header must be temporarily adjusted
        # It should reflect the length of the message up to the integrity attribute + 24 bytes (for the integrity attribute itself)
        new_length = len(message_to_hash_prefix) - 20 + 24
        new_length_bytes = new_length.to_bytes(2, 'big')

        # Construct the message that will be hashed
        # STUN Header (first 2 bytes) + Modified Length + Rest of Header and Attributes
        message_for_hmac = payload_bytes[:2] + new_length_bytes + payload_bytes[4:integrity_offset]
        
        # Step 3: Calculate the HMAC-SHA1
        calculated_hmac = hmac.new(key, message_for_hmac, hashlib.sha1).digest()
        
        # Step 4: Compare with the original HMAC from the packet
        original_hmac = payload_bytes[integrity_offset + 4 : integrity_offset + 24]
        
        # Debug prints omitted to avoid leaking cryptographic material
        return hmac.compare_digest(calculated_hmac, original_hmac)

    except Exception:
        return False

# --- Main Logic ---
def main(username, password, turn_file, output_file):
    try:
        with open(turn_file, 'r') as f:
            turn_data = json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        print(f"[ERROR] Could not read input JSON files: {e}"); sys.exit(1)


    # 2. Iterate through TURN packets and try to verify them
    verification_results = []
    for tx_id, packets in tqdm(turn_data.items(), desc="Verifying TURN packets"):
        for packet in packets:
            # We only verify requests that use long-term auth
            if packet.get("authentication_type") != "Long-Term":
                continue
            usernameT = packet.get("credentials", {}).get("username")
            if usernameT == username:
                realm = packet.get("credentials", {}).get("realm", "")
                is_verified = verify_message_integrity(packet, password, realm)
                
                verification_results.append({
                    "transaction_id": tx_id,
                    "timestamp": packet["timestamp"],
                    "src": packet["src"],
                    "dst": packet["dst"],
                    "username": username,
                    # Do not record raw password in outputs to avoid leakage
                    "password_used": "[redacted]",
                    "realm": realm,
                    "verification_successful": is_verified
                })

    with open(output_file, "w") as f:
        json.dump(verification_results, f, indent=2)

    successful_verifications = sum(1 for r in verification_results if r["verification_successful"])
    print("\n" + "="*50 + "\nANALYSIS COMPLETE\n" + "="*50)
    print(f"[+] Found and verified {successful_verifications} TURN packet(s) using credentials from signaling.")
    print(f"[+] Full verification report saved to '{output_file}'")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify TURN MESSAGE-INTEGRITY for a given username/password against a TURN analysis JSON.")
    parser.add_argument("username", help="TURN username to verify")
    parser.add_argument("password", help="TURN password to use for verification")
    parser.add_argument("turn_results", help="Path to turn_analysis.json")
    parser.add_argument("--out", dest="output", default="message_integrity.json", help="Output JSON path (default: message_integrity.json)")
    args = parser.parse_args()

    main(args.username, args.password, args.turn_results, args.output)
