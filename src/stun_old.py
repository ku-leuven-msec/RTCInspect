import json
import sys
import socket
import struct
import os
from scapy.all import rdpcap, UDP, IP, IPv6
import ipaddress # The definitive tool for IP address analysis
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

# --- STUN/TURN Definitions ---
STUN_MAGIC_COOKIE = b'\x21\x12\xa4\x42'

# We'll recognize all STUN and TURN message types to differentiate them
# This helps us filter for STUN-only later if needed
MESSAGE_TYPES = {
    # STUN
    0x0001: "Binding Request",
    0x0101: "Binding Success Response",
    0x0111: "Binding Error Response",
    # TURN
    0x0003: "Allocate Request",
    0x0103: "Allocate Success Response",
    0x0113: "Allocate Error Response",
    0x0004: "Refresh Request",
    0x0104: "Refresh Response",
    0x0006: "Send Indication",
    0x0007: "Data Indication",
    0x0008: "CreatePermission Request",
    0x0108: "CreatePermission Response",
    0x0009: "ChannelBind Request",
    0x0109: "ChannelBind Response",
}

# We only care about pure STUN messages for this script
VALID_STUN_TYPES = {0x0001, 0x0101, 0x0111}

ATTRIBUTE_TYPES = {
    0x0001: "MAPPED-ADDRESS",
    0x0003: "CHANGE-REQUEST",               # RFC 5780 / legacy testing
    0x0006: "USERNAME",
    0x0008: "MESSAGE-INTEGRITY",
    0x0009: "ERROR-CODE",
    0x000A: "UNKNOWN-ATTRIBUTES",
    0x0014: "REALM",
    0x0015: "NONCE",
    0x001C: "MESSAGE-INTEGRITY-SHA256",     # STUNbis
    0x001E: "USERHASH",                     # STUNbis
    0x0020: "XOR-MAPPED-ADDRESS",
    0x0024: "PRIORITY",                     # ICE
    0x0025: "USE-CANDIDATE",                # ICE (flag)
    0x0027: "RESPONSE-PORT",                # RFC 5780
    0x8022: "SOFTWARE",
    0x8028: "FINGERPRINT",
    0x8029: "ICE-CONTROLLED",               # ICE (8‑byte tie-breaker)
    0x802A: "ICE-CONTROLLING",              # ICE (8‑byte tie-breaker)
    0x802B: "RESPONSE-ORIGIN",              # RFC 5780
    0x802C: "OTHER-ADDRESS",                # RFC 5780
}

# --- Main Logic ---

def decode_xored_address(xored_ip_bytes, transaction_id):
    """Decodes an XOR-MAPPED-ADDRESS attribute."""
    xored_port = int.from_bytes(xored_ip_bytes[2:4], 'big')
    xored_ip = xored_ip_bytes[4:]
    
    magic_cookie_bytes = STUN_MAGIC_COOKIE
    
    # Port is XORed with the first 2 bytes of the magic cookie
    port = xored_port ^ int.from_bytes(magic_cookie_bytes[:2], 'big')
    
    # IP is XORed with the full magic cookie (for IPv4) or cookie+txid (for IPv6)
    if len(xored_ip) == 4: # IPv4
        ip_int = int.from_bytes(xored_ip, 'big') ^ int.from_bytes(magic_cookie_bytes, 'big')
        ip = socket.inet_ntoa(struct.pack('!L', ip_int))
    else: # IPv6
        # This part is more complex, skipping full implementation for brevity
        ip = "IPv6 (decode not implemented)"
        
    return f"{ip}:{port}"

def parse_attributes_manually(payload, transaction_id):
    """A robust manual parser for STUN/TURN attributes."""
    attributes = {}
    index = 0
    while index < len(payload):
        try:
            attr_type = int.from_bytes(payload[index:index+2], 'big')
            attr_length = int.from_bytes(payload[index+2:index+4], 'big')
            value_start = index + 4
            value_end = value_start + attr_length
            attr_value = payload[value_start:value_end]
            
            attr_name = ATTRIBUTE_TYPES.get(attr_type, f"Unknown(0x{attr_type:04x})")
            
            # Simple decoding for known attributes
            if attr_name == "USERNAME":
                attributes[attr_name] = attr_value.decode('utf-8', errors='ignore')
            elif attr_name == "SOFTWARE":
                attributes[attr_name] = attr_value.decode('utf-8', errors='ignore')
            elif attr_name == "XOR-MAPPED-ADDRESS":
                attributes[attr_name] = decode_xored_address(attr_value, transaction_id)
            else:
                 attributes[attr_name] = attr_value.hex()

            # Move to the next attribute (with padding to 4-byte boundary)
            index += 4 + (attr_length + 3) & ~3
        except Exception:
            # If parsing fails, break to avoid infinite loop on malformed packet
            break
            
    return attributes

def is_private_ip(ip_str):
    """Checks if an IP address string is private (RFC 1918), loopback, or link-local."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        # Handle cases where the input is not a valid IP address
        return False
    
def analyze_stun_transaction(packets):
    """
    Analyzes a list of packets in a single transaction to generate a summary.
    This version correctly identifies the client and server based on IP type.
    """
    summary = {
        "is_stun_used": True,
        "stun_standard": "RFC 5389 (inferred by magic cookie)",
        "authentication_type": "None",
        "cleartext_passwords_in_stun": "N/A (Passwords are not sent in STUN)",
        "client_lan_ip": "Unknown",
        "stun_server_ip": "Unknown",
        "exposed_ip_address": "Not detected",
        "library_info": "Not detected",
        "asn_info": "Unknown",
        "packets": packets
    }

    # Get the two IPs involved from the first packet
    if not packets:
        return summary
    
    ip1 = packets[0]['src_ip']
    ip2 = packets[0]['dst_ip']

    # Determine roles based on IP address type (private vs public)
    if is_private_ip(ip1) and not is_private_ip(ip2):
        summary['client_lan_ip'] = ip1
        summary['stun_server_ip'] = ip2
    elif not is_private_ip(ip1) and is_private_ip(ip2):
        summary['client_lan_ip'] = ip2
        summary['stun_server_ip'] = ip1
    else:
        # Edge case: both are public or both are private.
        # Fallback to assigning based on who sent the first request.
        summary['client_lan_ip'] = ip1
        summary['stun_server_ip'] = ip2
        summary['note'] = "Could not definitively determine roles; assuming first sender is client."

    # Iterate again to fill in other details
    for pkt_info in packets:
        if pkt_info['attributes'].get("XOR-MAPPED-ADDRESS"):
            summary["exposed_ip_address"] = pkt_info['attributes']["XOR-MAPPED-ADDRESS"]
        if pkt_info['attributes'].get("SOFTWARE"):
            summary["library_info"] = pkt_info['attributes']["SOFTWARE"]

    # (The rest of the authentication logic can stay the same)
    all_attrs = {k for p in packets for k in p['attributes']}
    if "MESSAGE-INTEGRITY" in all_attrs:
        # ... your existing logic for short-term vs long-term auth
        # (This part was already good)
        username_present = any(p['attributes'].get("USERNAME") for p in packets)
        if "REALM" in all_attrs and "NONCE" in all_attrs:
            summary["authentication_type"] = "Long-term (Realm/Nonce)"
        elif username_present:
            summary["authentication_type"] = "Short-term (ICE Credentials)"


    return summary

def main(pcap_path, output_path):

    packets = rdpcap(pcap_path)
    transactions = {}
    IPs = set()  # To track unique IPs for geolocation
    
    for pkt in packets:
        # Basic STUN check
        if not (pkt.haslayer(UDP) and len(pkt[UDP].payload) >= 20 and bytes(pkt[UDP].payload)[4:8] == STUN_MAGIC_COOKIE):
            continue

        payload = bytes(pkt[UDP].payload)
        msg_type = int.from_bytes(payload[0:2], 'big')

        # Filter for PURE STUN messages only
        if msg_type not in VALID_STUN_TYPES:
            continue
        
        try:
            transaction_id = payload[8:20]
            attributes = parse_attributes_manually(payload[20:], transaction_id)
            ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
            server_ip = pkt[IP].dst # Or however you determine the server

            IPs.add(server_ip)

            pkt_info = {
                "timestamp": float(pkt.time),
                "src_ip": ip_layer.src,
                "src_port": pkt[UDP].sport,
                "dst_ip": ip_layer.dst,
                "dst_port": pkt[UDP].dport,
                "message_type": MESSAGE_TYPES.get(msg_type, f"Unknown(0x{msg_type:04x})"),
                "attributes": attributes
            }
           
            
            transactions.setdefault(transaction_id.hex(), []).append(pkt_info)

        except Exception as e:
            # This block will now catch fewer errors
            # print(f"Skipping packet due to error: {e}")
            continue
    
 # --- Geolocation Phase ---
    geoip_summary = {}
    if safe_get_ip_details and ipinfo:
        # Ensure .env takes precedence over any pre-set environment variable
        load_dotenv(dotenv_path=Path('.') / '.env', override=True)
        ipinfo_token = "c5e82516cfad4a"
        if ipinfo_token:
            handler = ipinfo.getHandler(ipinfo_token, request_options={"timeout": 5})
            print(f"\n[+] Performing GeoIP lookup for {len(IPs)} unique server IP(s)...")
            for ip in tqdm(IPs, desc="Looking up IPs"):
                geoip_summary[ip] = safe_get_ip_details(handler, ip)
        else:
            print("\n[WARN] IPINFO_TOKEN environment variable not set. Skipping GeoIP lookup.")
            geoip_summary["error"] = "IPINFO_TOKEN not configured."


    # Analyze and enrich transactions
    analyzed_transactions = {txid: analyze_stun_transaction(pkts) for txid, pkts in transactions.items()}
    final_report = {
        "geoip_summary": geoip_summary,
        "stun_transactions": analyzed_transactions
    }


    with open(output_path, "w") as f:
        json.dump(final_report, f, indent=2)

    print(f"[+] Detection complete. Found {len(final_report)} STUN transactions.")
    print(f"[+] Results saved to '{output_path}'")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python stun_analyzer.py <input.pcap> [output.json]")
        sys.exit(1)
        
    pcap_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "stun_analysis.json"
    
    main(pcap_file, output_file)
