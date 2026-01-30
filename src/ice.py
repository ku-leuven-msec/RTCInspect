import json
import sys
from scapy.all import rdpcap, UDP, IP, IPv6
import ipinfo
# --- Configuration ---
STUN_MAGIC_COOKIE = b'\x21\x12\xa4\x42'

ICE_MESSAGE_TYPES = {
    0x0001: "Binding Request",
    0x0101: "Binding Success Response",
    0x0111: "Binding Error Response",
}

ATTR_TYPES = {
    0x0006: "USERNAME",
    0x0008: "MESSAGE-INTEGRITY",
    0x0024: "PRIORITY",
    0x0025: "USE-CANDIDATE",
    0x8022: "SOFTWARE",
    0x8029: "ICE-CONTROLLED",
    0x802A: "ICE-CONTROLLING",
}

def parse_attributes(payload: bytes):
    """
    Parse STUN attributes from a full STUN message (expects the 20-byte header at the start of 'payload').
    Returns a dict with properly decoded types.
    """
    attributes = {}
    # Length comes from header (bytes 2:4), but since we don't trust capture truncation,
    # we'll just iterate until we run out.
    offset = 20
    n = len(payload)
    while offset + 4 <= n:
        try:
            attr_type = int.from_bytes(payload[offset:offset+2], 'big')
            attr_len  = int.from_bytes(payload[offset+2:offset+4], 'big')
            offset += 4
            if offset + attr_len > n:
                break
            raw = payload[offset:offset+attr_len]
            offset += (attr_len + 3) & ~3  # 32-bit padding

            name = ATTR_TYPES.get(attr_type)
            if not name:
                # Unknown — keep as hex
                attributes[f"0x{attr_type:04x}"] = raw.hex()
                continue

            if name in ("USERNAME", "SOFTWARE"):
                attributes[name] = raw.decode('utf-8', errors='ignore')
            elif name == "PRIORITY" and attr_len == 4:
                attributes[name] = int.from_bytes(raw, 'big')
            elif name in ("ICE-CONTROLLING", "ICE-CONTROLLED") and attr_len == 8:
                attributes[name] = int.from_bytes(raw, 'big')
            elif name == "USE-CANDIDATE":
                # flag attribute — presence only
                attributes[name] = True
            else:
                attributes[name] = raw.hex()
        except Exception:
            break
    return attributes

def analyze_ice_packet(pkt, attributes):
    """Analyzes a single ICE-related STUN packet."""
    ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    udp_layer = pkt.getlayer(UDP)
    payload = bytes(udp_layer.payload)
    msg_type_code = int.from_bytes(payload[0:2], 'big')
    tx_id = payload[8:20].hex()

    # --- Improved Library Parsing Logic ---
    library_str = attributes.get("SOFTWARE", "Unknown")
    lib_name = "Unknown"
    lib_version = "Unknown"
    versions_behind = "Cannot be determined automatically. Requires manual lookup."
    
    if library_str != "Unknown":
        if '-' in library_str:
            # Handles "Coturn-4.5.2 'dan Eider'"
            parts = library_str.split('-', 1)
            lib_name = parts[0].strip()
            lib_version = parts[1].split(' ')[0].strip("'")
        else:
            # Handles "libcoreice"
            lib_name = library_str.strip()
            # lib_version remains "Unknown"
        
    analysis = {
        "timestamp": float(pkt.time),
        "src": f"{ip_layer.src}:{udp_layer.sport}",
        "dst": f"{ip_layer.dst}:{udp_layer.dport}",
        "transaction_id": tx_id,
        "username": attributes.get("USERNAME"),  # Username parsed from attributes if present
        "is_ice_used": True,
        "ice_version_standard": "RFC 8445 (modern ICE)",
        "cleartext_passwords_in_check": False,
        "notes_on_passwords": "ICE passwords (ice-pwd) are not sent in checks. They are used to generate the MESSAGE-INTEGRITY HMAC. Check the signaling phase (SDP) for cleartext credentials.",
        "candidate_types_used": "Cannot be determined from this packet. This is defined in the signaling (SDP) 'a=candidate' lines.",
        "mdns_obfuscation_used": "Cannot be determined from this packet. Look for '.local' hostnames in signaling (SDP) 'a=candidate' lines.",
        "library_name": lib_name,
        "library_version": lib_version,
        "versions_behind": versions_behind
    }
    return analysis

def detect_ice_sessions(pcap_file, output_file):
    """Reads a pcap, finds ICE connectivity checks, and saves a report keyed by transaction_id."""
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        return

    # Temporary indexes by txid
    requests_by_tx = {}    # txid -> pkt_info
    success_by_tx  = {}    # txid -> pkt_info

    grouped_by_tx = {}     # txid -> list[pkt_info] (for UI details)

    for pkt in packets:
        if not pkt.haslayer(UDP):
            continue
        udp = pkt[UDP]
        if len(udp.payload) < 20:
            continue

        payload = bytes(udp.payload)
        if payload[4:8] != STUN_MAGIC_COOKIE:
            continue

        msg_type_code = int.from_bytes(payload[0:2], 'big')
        if msg_type_code not in ICE_MESSAGE_TYPES:
            continue

        # Parse attrs from the full message (this function expects header)
        attrs = parse_attributes(payload)

        # Heuristic: only consider ICE checks if we see ICE fields (PRIORITY or USERNAME with colon)
        #if "PRIORITY" not in attrs and not (("USERNAME" in attrs) and (":" in attrs["USERNAME"])):
        #    continue

        is_request = (msg_type_code == 0x0001)
        is_success = (msg_type_code == 0x0101)
        is_error   = (msg_type_code == 0x0111)

        looks_like_ice_req = ("PRIORITY" in attrs) or (":" in attrs.get("USERNAME",""))
        if not ( (is_request and looks_like_ice_req) or is_success or is_error ):
            continue


        ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        tx_id = payload[8:20].hex()
        msg_name = ICE_MESSAGE_TYPES[msg_type_code]

        # Library parsing (unchanged)
        library_str = attrs.get("SOFTWARE", "Unknown")
        lib_name, lib_version = "Unknown", "Unknown"
        if library_str != "Unknown":
            if '-' in library_str:
                parts = library_str.split('-', 1)
                lib_name = parts[0].strip()
                lib_version = parts[1].split(' ')[0].strip("'")
            else:
                lib_name = library_str.strip()

        pkt_info = {
            "timestamp": float(pkt.time),
            "src": f"{ip_layer.src}:{udp.sport}",
            "dst": f"{ip_layer.dst}:{udp.dport}",
            "transaction_id": tx_id,
            "message_type": msg_name,
            "username": attrs.get("USERNAME"),
            "attributes": attrs,
            "is_ice_used": True,
            "ice_version_standard": "RFC 8445 (modern ICE)",
            "library_name": lib_name,
            "library_version": lib_version,
            "cleartext_passwords_in_check": False,
            "notes_on_passwords": "ICE passwords (ice-pwd) are not sent in checks; they key MESSAGE-INTEGRITY.",
            "candidate_types_used": "N/A (see SDP a=candidate)",
            "mdns_obfuscation_used": "N/A (see SDP a=candidate)",
        }

        grouped_by_tx.setdefault(tx_id, []).append(pkt_info)

        if msg_name == "Binding Request":
            requests_by_tx[tx_id] = pkt_info
        elif msg_name == "Binding Success Response":
            success_by_tx[tx_id] = pkt_info

    # Post-process verdicts per txid
    report = {}
    for txid, msgs in grouped_by_tx.items():
        req = requests_by_tx.get(txid)
        suc = success_by_tx.get(txid)

        has_request = req is not None
        has_success = suc is not None

        role = None
        used_use_candidate = False
        if req:
            a = req["attributes"]
            if "ICE-CONTROLLING" in a:
                role = "controlling"
            elif "ICE-CONTROLLED" in a:
                role = "controlled"
            used_use_candidate = bool(a.get("USE-CANDIDATE"))

        selected = bool(used_use_candidate and has_success)  # classic nomination heuristic

        # Per-transaction header summary for your UI
        summary = {
            "txid": txid,
            "has_request": has_request,
            "has_success": has_success,
            "role": role or "unknown",
            "used_use_candidate": used_use_candidate,
            "selected": selected,
            # Convenience endpoint hint (from the request)
            "request_path": (req["src"] + " → " + req["dst"]) if req else "N/A",
            "response_path": (suc["src"] + " → " + suc["dst"]) if suc else "N/A",
            # Keep the packet list as-is (sorted by time)
            "messages": sorted(msgs, key=lambda m: m["timestamp"]),
        }
        report[txid] = summary

    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)

    total_packets = sum(len(v["messages"]) for v in report.values())
    print(f"[+] Extracted {total_packets} ICE-related STUN packets across {len(report)} transactions.")
    print(f"[+] Results saved to '{output_file}'")

# --- Main Execution ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ice_analyzer.py <input.pcap> [output.json]")
        sys.exit(1)

    pcap_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "ice_results.json"

    detect_ice_sessions(pcap_path, output_path)
