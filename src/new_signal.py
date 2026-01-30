import json
import sys
import argparse
import re
from tqdm import tqdm
import pyshark

# --- Configuration (Re-using parts of your signaling analyzer) ---
SDP_REGEX = {
    "ice-ufrag": re.compile(r"a=ice-ufrag:([^\r\n]+)"),
    "ice-pwd": re.compile(r"a=ice-pwd:([^\r\n]+)"),
    "turn_user": re.compile(r"a=turn_user:([^\r\n]+)"),
    "turn_password": re.compile(r"a=turn_password:([^\r\n]+)"),
    "turn_addr": re.compile(r"a=turn_addr:([^\r\n]+)"),
    "turn_port": re.compile(r"a=turn_port:([^\r\n]+)"),
    "candidate": re.compile(r"a=candidate:([^\r\n]+)"),
    "dtls-fingerprint": re.compile(r"a=fingerprint:sha-256\s+([A-F0-9:]{95})", re.IGNORECASE)
}

# Specific regex for headers (re-defined here for completeness in this file)
HTTP_HEADER_REGEXES = {
    "x-skypetoken": re.compile(r"x-skypetoken:\s*([^\r\n]+)", re.IGNORECASE),
    "authorization": re.compile(r"authorization:\s*(Bearer\s+[^\r\n]+)", re.IGNORECASE),
}

# Regex for XMPP/Jingle attributes (used in Jitsi, etc.)
XMPP_JINGLE_REGEX = {
    "jingle-ufrag": re.compile(r'ufrag="([^"]+)"'),
    "jingle-pwd": re.compile(r'pwd="([^"]+)"'),
    "jingle-fingerprint": re.compile(r'<fingerprint.*?hash="sha-256".*?>([^<]+)</fingerprint>', re.IGNORECASE),
}


# --- Helper Functions ---
def extract_important_info(payload_str):
    """Extracts values from JSON and SDP within a payload."""
    info = {}
    # Find top-level JSON objects in the payload
    for match in re.finditer(r'{[^{}]*(?:{[^{}]*})*[^{}]*}', payload_str):
        try:
            json_data = json.loads(match.group(0))
            if "turn" in json_data and isinstance(json_data["turn"], dict):
                for key in ["turn_addr", "turn_password", "turn_user", "turn_port"]:
                    if key in json_data["turn"]: info[key] = json_data[key]
            for key in ["token", "account"]:
                if key in json_data: info[key] = json_data[key]
            if 'sdp' in json_data and isinstance(json_data['sdp'], str):
                for key, pattern in SDP_REGEX.items():
                    if (sdp_match := pattern.search(json_data['sdp'])): info[key] = sdp_match.group(1)
        except (json.JSONDecodeError, KeyError): continue
    # Fallback to searching for SDP attributes in the raw payload string
    for key, pattern in SDP_REGEX.items():
        if key not in info and (sdp_match := pattern.search(payload_str)): info[key] = sdp_match.group(1)

    for key, pattern in XMPP_JINGLE_REGEX.items():
        if key not in info and (xmpp_match := pattern.search(payload_str)): info[key] = xmpp_match.group(1)
    return info

def get_session_key(pkt, protocol="TCP"):
    """Creates a unique session key based on IP/Port and protocol."""
    try:
        # ## <<< CHANGE START: Added protocol prefix for clarity in output >>>
        if hasattr(pkt, 'tcp'):
            proto_prefix = "WS" if protocol == "WebSocket" else "HTTP2"
            return f"{proto_prefix}:{pkt.ip.src}:{pkt.tcp.srcport}-{pkt.ip.dst}:{pkt.tcp.dstport}"
        elif hasattr(pkt, 'udp'):
            return f"QUIC:{pkt.ip.src}:{pkt.udp.srcport}-{pkt.ip.dst}:{pkt.udp.dstport}"
        # ## <<< CHANGE END >>>
        return None
    except AttributeError: return None

def analyze_http_signaling(decrypted_pcap_file, output_file):
    """
    Analyzes a DECRYPTED pcap file for signaling data within HTTP/1.1 (for WS), HTTP/2, or HTTP/3 frames.
    """
    print("[+] Analyzing decrypted pcap for signaling...")

    try:
        cap = pyshark.FileCapture(decrypted_pcap_file, display_filter="http or http2 or http3 or websocket")
        cap.load_packets()
    except Exception as e:
        print(f"[ERROR] Could not run pyshark. Error: {e}")
        return

    sessions = {}
    for pkt in tqdm(cap, desc="Processing Packets"):
        try:
            payload_str = ""
            protocol = "Unknown"
            
            # 1. Prioritize WebSocket
            if hasattr(pkt, 'websocket'):
                protocol = "WebSocket"
                if hasattr(pkt.websocket, 'payload_text'):
                    payload_str = pkt.websocket.payload_text
                elif hasattr(pkt.websocket, 'payload'):
                    hex_payload = str(pkt.websocket.payload).replace(':', '')
                    if hex_payload:
                        payload_str = bytes.fromhex(hex_payload).decode('utf-8', errors='replace')

            # 2. Check for HTTP/2 data frames
            elif hasattr(pkt, 'http2') and hasattr(pkt.http2, 'data_data'):
                protocol = "HTTP/2"
                hex_payload = str(pkt.http2.data_data).replace(':', '')
                payload_str = bytes.fromhex(hex_payload).decode('utf-8', errors='replace')

            # 3. Check for HTTP/3 data frames
            elif hasattr(pkt, 'http3') and hasattr(pkt.http3, 'data_data'):
                protocol = "HTTP/3"
                hex_payload = str(pkt.http3.data_data).replace(':', '')
                payload_str = bytes.fromhex(hex_payload).decode('utf-8', errors='replace')

            # --- Extract from headers (Works for WS handshake and HTTP/2) ---
            header_info = {}
            # ## <<< CHANGE START: This whole block is now more robust >>>
            if hasattr(pkt, 'http'):
                # Get the entire header block field, which is more reliable.
                header_block_field = getattr(pkt.http, 'request_full_header', None) or getattr(pkt.http, 'response_full_header', None)
                
                # CRUCIAL CHECK: Only proceed if the header block field actually exists.
                if header_block_field:
                    # str() is the safest way to get the text representation from a pyshark field.
                    header_str = str(header_block_field)
                    for key, regex in HTTP_HEADER_REGEXES.items():
                        match = regex.search(header_str)
                        if match:
                            header_info[key] = match.group(1)
            # ## <<< CHANGE END >>>

            # --- Extract from payload body ---
            body_info = extract_important_info(payload_str) if payload_str else {}
            
            # Combine header and body info
            extracted_info = {**header_info, **body_info}

            if extracted_info:
                session_key = get_session_key(pkt, protocol)
                if not session_key: continue

                if session_key not in sessions:
                    sessions[session_key] = {
                        "detection_method": f"Decrypted {protocol}",
                        "important_info": {},
                        "packets_with_info": []
                    }
                
                if protocol not in sessions[session_key]['detection_method']:
                     sessions[session_key]['detection_method'] += f" / {protocol}"

                sessions[session_key]["important_info"].update(extracted_info)
                sessions[session_key]["packets_with_info"].append({
                    "packet_number": pkt.number,
                    "protocol": protocol,
                    "payload_snippet": payload_str[:500] if payload_str else "No payload body in this packet."
                })

        except (AttributeError, KeyError, ValueError) as e:
            # Uncomment the next line for deep debugging if needed
            # print(f"Skipping packet {pkt.number} due to parsing issue: {e}")
            continue

    with open(output_file, "w") as f:
        json.dump(sessions, f, indent=2)

    print("\n" + "="*50 + "\nANALYSIS COMPLETE\n" + "="*50)
    print(f"[+] Found potential signaling in {len(sessions)} decrypted session(s).")
    print(f"[+] Full report saved to '{output_file}'")

# --- Main Execution ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python stun_analyzer.py <input.pcap> [output.json]")
        sys.exit(1)
        
    pcap_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "stun_analysis.json"

    analyze_http_signaling(pcap_file, output_file)