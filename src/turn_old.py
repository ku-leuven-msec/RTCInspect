import json
import sys
import socket
import os
import ipaddress # The definitive tool for IP address analysis
from scapy.all import rdpcap, UDP, IP, IPv6
from tqdm import tqdm
from dotenv import load_dotenv
from pathlib import Path
try:
    from geoip_lookup import safe_get_ip_details
    import ipinfo
except ImportError:
    print("[WARN] Could not import geoip_lookup.py or ipinfo library. Geolocation will be skipped.")
    safe_get_ip_details = None
    ipinfo = None


# --- Configuration ---
STUN_MAGIC_COOKIE = b'\x21\x12\xa4\x42'

VALID_TURN_TYPES = {
    0x0003: "Allocate Request", 0x0103: "Allocate Success Response", 0x0113: "Allocate Error Response",
    0x0004: "Refresh Request", 0x0104: "Refresh Success Response", 0x0114: "Refresh Error Response",
    0x0006: "Send Indication", 0x0007: "Data Indication",
    0x0008: "CreatePermission Request", 0x0108: "CreatePermission Success Response", 0x0118: "CreatePermission Error Response",
    0x0009: "ChannelBind Request", 0x0109: "ChannelBind Success Response", 0x0119: "ChannelBind Error Response",
}

ATTR_TYPES = {
    0x0006: "USERNAME", 0x0008: "MESSAGE-INTEGRITY", 0x0014: "REALM",
    0x0015: "NONCE", 0x0016: "XOR-RELAYED-ADDRESS", 0x0020: "XOR-MAPPED-ADDRESS",
    0x8022: "SOFTWARE",
}


def is_private_ip(ip_str):
    """Checks if an IP address string is private (RFC 1918), loopback, or link-local."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        # Handle cases where the input is not a valid IP address
        return False

# --- Helper Functions ---
def parse_attributes(payload):
    """Manually parses STUN/TURN attributes, decoding text fields where appropriate."""
    attributes = {}
    offset = 20
    while offset < len(payload):
        try:
            attr_type = int.from_bytes(payload[offset:offset+2], 'big')
            attr_len = int.from_bytes(payload[offset+2:offset+4], 'big')
            offset += 4
            attr_value = payload[offset:offset+attr_len]

            attr_name = ATTR_TYPES.get(attr_type)
            # Decode text-based attributes to strings, others to hex
            if attr_name in ["SOFTWARE", "USERNAME", "REALM"]:
                attributes[attr_name] = attr_value.decode('utf-8', errors='ignore')
            elif attr_name:
                attributes[attr_name] = attr_value.hex()

            offset += (attr_len + 3) & ~3
        except Exception:
            break
    return attributes

def analyze_turn_packet(pkt, attributes):
    """Analyzes a single TURN packet and populates the checklist answers."""
    ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    udp_layer = pkt.getlayer(UDP)
    payload = bytes(udp_layer.payload)

    msg_type_code = int.from_bytes(payload[0:2], 'big')
    tx_id = payload[8:20].hex()

    # Determine auth type
    auth_type = "None"
    if "MESSAGE-INTEGRITY" in attributes:
        if "REALM" in attributes and "NONCE" in attributes:
            auth_type = "Long-Term"
        else:
            auth_type = "Short-Term"

    library_str = attributes.get("SOFTWARE", "Unknown")
    lib_name, lib_version = "Unknown", "Unknown"
    if '-' in library_str:
        parts = library_str.split('-', 1)
        lib_name = parts[0]
        lib_version = parts[1].split(' ')[0].strip("'")
       

    analysis = {
        "timestamp": float(pkt.time),
        "src": f"{ip_layer.src}:{udp_layer.sport}",
        "dst": f"{ip_layer.dst}:{udp_layer.dport}",
        "message_type": VALID_TURN_TYPES.get(msg_type_code, "Unknown TURN Message"),
        "transaction_id": tx_id,
        "turn_version_standard": "RFC 5766 / 8656",
        "message_authentication_type": auth_type,
        "internal_ip_exposure_via_mapped_address": "XOR-MAPPED-ADDRESS" in attributes,
        "library_name": lib_name,
        "library_version": lib_version,
        "raw_payload_hex": payload.hex()
    }

    # Add credentials if they exist
    creds = {}
    if attributes.get("USERNAME"): creds["username"] = attributes.get("USERNAME")
    if attributes.get("REALM"): creds["realm"] = attributes.get("REALM")
    if attributes.get("NONCE"): creds["nonce"] = attributes.get("NONCE")
    if creds:
        analysis["credentials"] = creds
    

    return analysis

def detect_turn_sessions(pcap_file, output_file):
    """Reads a pcap, finds TURN packets, groups them, and saves to JSON."""
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        return

    grouped_turn = {}
    IPs = set()  # To track unique IPs for geolocation
    for pkt in packets:
        is_udp = pkt.haslayer(UDP)
        if not is_udp or len(bytes(pkt[UDP].payload)) < 20:
            continue      
      
        payload = bytes(pkt[UDP].payload)
        if payload[4:8] != STUN_MAGIC_COOKIE:
            continue

        msg_type_code = int.from_bytes(payload[0:2], 'big')
        if msg_type_code not in VALID_TURN_TYPES:
            continue

        try:
            #print(f"[+] Processing packet ...")
            attributes = parse_attributes(payload)
            info = analyze_turn_packet(pkt, attributes)
            tx_id = info["transaction_id"]
            grouped_turn.setdefault(tx_id, []).append(info)
            if pkt.haslayer(IP):
                if not is_private_ip(pkt[IP].dst):
                    IPs.add(pkt[IP].dst)
        except Exception as e:
            # print(f"Skipping packet due to parse error: {e}")
            pass
    
    print("\n[+] Post-processing transactions to refine authentication type...")
    for tx_id, packets in grouped_turn.items():
        
        is_long_term_session = any(p.get("message_authentication_type") == "Long-Term" for p in packets)
        
        if is_long_term_session:
            # If it is, label every packet in the transaction consistently
            for packet_dict in packets:
                packet_dict["transaction_authentication_type"] = "Long-Term"
        else:
            # Check for short-term or none
            is_short_term_session = any(p.get("message_authentication_type") == "Short-Term" for p in packets)
            for packet_dict in packets:
                packet_dict["transaction_authentication_type"] = "Short-Term" if is_short_term_session else "None"

    # Convert grouped_turn to a more readable format
     # --- Geolocation Phase ---
    geoip_summary = {}
    if safe_get_ip_details and ipinfo:
        # Ensure .env takes precedence over any pre-set environment variable
        load_dotenv(dotenv_path=Path('.') / '.env', override=True)
        ipinfo_token = os.getenv('IPINFO_TOKEN')
        if ipinfo_token:
            handler = ipinfo.getHandler(ipinfo_token, request_options={"timeout": 5})
            print(f"\n[+] Performing GeoIP lookup for {len(IPs)} unique server IP(s)...")
            for ip in tqdm(IPs, desc="Looking up IPs"):
                geoip_summary[ip] = safe_get_ip_details(handler, ip)
        else:
            print("\n[WARN] IPINFO_TOKEN environment variable not set. Skipping GeoIP lookup.")
            geoip_summary["error"] = "IPINFO_TOKEN not configured."

    final_report = {
        "geoip_summary": geoip_summary,
        "turn_transactions": grouped_turn
    }

    with open(output_file, "w") as f:
        json.dump(final_report, f, indent=2)

    total_packets = sum(len(v) for v in grouped_turn.values())
    print(f"[+] Extracted {total_packets} TURN packets into {len(grouped_turn)} transactions.")
    print(f"[+] Results saved to '{output_file}'")


# --- Main Execution ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python turn_analyzer.py <input.pcap> [output.json]")
        sys.exit(1)

    pcap_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "turn_results.json"

    detect_turn_sessions(pcap_path, output_path)
