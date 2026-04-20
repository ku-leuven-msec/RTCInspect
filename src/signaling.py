import json
import sys
import os
import re
import math
from collections import Counter
from scapy.all import rdpcap, TCP, UDP, Raw, IP, IPv6
from scapy.layers.tls.all import TLS
from tqdm import tqdm
import ipaddress
from dotenv import load_dotenv
from pathlib import Path
try:
    from geoip_lookup import safe_get_ip_details
    import ipinfo
except ImportError:
    print("[WARN] Could not import geoip_lookup.py or ipinfo library. Geolocation will be skipped.")
    safe_get_ip_details = None
    ipinfo = None
# --- Configuration for Keyword Analysis ---
SIGNALING_PATTERNS = {
    "SIP": [b"SIP/2.0", b"INVITE"], 
    "XMPP": [b"<stream:stream"], 
    "SDP": [b"v=0", b"m=audio", b"a=ice-ufrag", b"a=ice-pwd", b"a=candidate", b"a=fingerprint:"],
    "WebRTC_JSON": [b'"sdp":', b'"candidate":'], 
    "WebSocket_Upgrade": [b"Upgrade: websocket"], 
    "OAuth": [b"Authorization: Bearer"],
}
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

# --- Configuration for Heuristic Analysis ---
TIMESTAMP_REGEX = re.compile(b'1[6-7]\d{8}')
HEX_STRING_REGEX = re.compile(b'[a-f0-9]{20,}')
BASE64_LIKE_REGEX = re.compile(b'(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
FINGERPRINT_REGEX = re.compile(b'fingerprint:sha-256', re.IGNORECASE)
FINGERPRINT_REGEX2 =  re.compile(rb'(?:[a-f0-9]{2}:){31}[a-f0-9]{2}', re.IGNORECASE)

# --- STUN/TURN Magic Cookie ---
STUN_MAGIC_COOKIE = b'\x21\x12\xa4\x42'

# --- Initialize IPInfo Handler ---
# Ensure .env takes precedence over any pre-set environment variable
load_dotenv(dotenv_path=Path('.') / '.env', override=True)
ipinfo_token = "c5e82516cfad4a"
handler = ipinfo.getHandler(ipinfo_token, request_options={"timeout": 5}) if (ipinfo_token and 'ipinfo' in globals() and ipinfo) else None
# --- Shared Helper Functions ---
def get_session_key(pkt):
    try:
        ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        transport_layer = pkt.getlayer(TCP) or pkt.getlayer(UDP)
        protocol = "TCP" if pkt.haslayer(TCP) else "UDP"
        
        # --- FIX: Filter out broadcast/multicast destinations ---
        dst_ip_str = ip_layer.dst
        if not dst_ip_str: return None
        dst_ip = ipaddress.ip_address(dst_ip_str)
        if dst_ip.is_multicast or dst_ip.is_link_local or str(dst_ip).endswith('.255'):
            return None

        key_parts = sorted([(ip_layer.src, transport_layer.sport), (dst_ip_str, transport_layer.dport)])
        return f"{protocol}:{key_parts[0][0]}:{key_parts[0][1]}-{key_parts[1][0]}:{key_parts[1][1]}"
    except (AttributeError, ValueError): return None

def is_private_ip(ip_str):
    """Checks if an IP address string is private (RFC 1918), loopback, or link-local."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        # Handle cases where the input is not a valid IP address
        return False
    
def calculate_entropy(data):
    if not data: return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counter.values())

def extract_important_info(payload_str):
    info = {} # (Your robust extraction logic here)
    for match in re.finditer(r'{[^{}]*(?:{[^{}]*})*[^{}]*}', payload_str):
        try:
            json_data = json.loads(match.group(0))
            if "turn" in json_data and isinstance(json_data["turn"], dict):
                for key in ["turn_addr", "turn_password", "turn_user", "turn_port"]:
                    if key in json_data["turn"]: info[key] = json_data["turn"][key]
            for key in ["token", "account"]:
                if key in json_data: info[key] = json_data[key]
            if 'sdp' in json_data and isinstance(json_data['sdp'], str):
                for key, pattern in SDP_REGEX.items():
                    if (sdp_match := pattern.search(json_data['sdp'])): info[key] = sdp_match.group(1)
        except (json.JSONDecodeError, KeyError): continue
    for key, pattern in SDP_REGEX.items():
        if key not in info and (sdp_match := pattern.search(payload_str)): info[key] = sdp_match.group(1)
    return info
    
def fingerprint_protocol(key, payloads):
    """Identifies common protocols to filter them out as false positives."""
    if not payloads: return "Unknown"
    first_payload = payloads[0]

    protocol, endpoints = key.split(':', 1)
    try:
        ep1, ep2 = endpoints.split('-')
        ports = {int(ep1.rsplit(':', 1)[1]), int(ep2.rsplit(':', 1)[1])}
    except ValueError: return "Malformed Key"

    if 53 in ports: return "DNS"
    if 123 in ports: return "NTP"
    if 1900 in ports or b"M-SEARCH" in first_payload or b"NOTIFY" in first_payload: return "SSDP"
    
    # Check for the /SERVERPUSH protocol
    if b"SERVERPUSH / HTTP/1.1" in first_payload :
        return "Proprietary Push/Discovery"
    # ---    # Check for STUN/TURN Magic Cookie at byte offset 4
    if len(first_payload) >= 8 and first_payload[4:8] == STUN_MAGIC_COOKIE:
        return "STUN/TURN"
        
    if first_payload.startswith(b'\x16\x03\x01') or first_payload.startswith(b'\x16\xfe\xff'): return "TLS/DTLS Handshake"
    return "Unknown"

# --- Analysis Methods ---
def analyze_keyword_sessions(packets):
    sessions = {} 
    for pkt in tqdm(packets, desc="Phase 1a: Keyword Analysis"):
        if not pkt.haslayer(Raw): continue
        session_key = get_session_key(pkt)
        if not session_key: continue
        payload = bytes(pkt[Raw].load)
        # if fingerprint_protocol(session_key, [payload]) != "Unknown": continue

        proto_hits = {p for p, ptns in SIGNALING_PATTERNS.items() if any(ptn in payload for ptn in ptns)}
        payload_str = payload.decode(errors='replace')
        extracted_info = extract_important_info(payload_str)

        if proto_hits or extracted_info:
            if session_key not in sessions: sessions[session_key] = {"summary": {}, "important_info": {}, "packets": [], "endpoints": set(), "_all_proto_hits": set(), "_is_encrypted": False}
            transport_layer = pkt.getlayer(TCP) or pkt.getlayer(UDP)
            sessions[session_key]["packets"].append({"timestamp": float(pkt.time), "src_port": transport_layer.sport, "dst_port": transport_layer.dport, "transport_proto": "TCP" if pkt.haslayer(TCP) else "UDP", "proto_hits": list(proto_hits), "payload_snippet": payload_str[:500]})
            ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            sessions[session_key]["endpoints"].add(ip_layer.src)
            sessions[session_key]["endpoints"].add(ip_layer.dst)
            sessions[session_key]["_all_proto_hits"].update(proto_hits)
            if pkt.haslayer(TLS): sessions[session_key]["_is_encrypted"] = True
            sessions[session_key]["important_info"].update(extracted_info)
    return sessions

def analyze_heuristic_sessions(packets):
    conversations = {}
    for pkt in tqdm(packets, desc="Phase 1b: Gathering Heuristic Stats"):
        if not pkt.haslayer(Raw):
            continue
         
        session_key = get_session_key(pkt)
        if not session_key: 
            continue
        if session_key not in conversations:
            conversations[session_key] = {"packet_count": 0, "total_bytes": 0, "payloads": []}
        payload = bytes(pkt[Raw].load)
        if not payload:
            continue
        #payload = bytes(pkt.getlayer(TCP).payload if pkt.haslayer(TCP) else pkt.getlayer(UDP).payload)
        conversations[session_key]["packet_count"] += 1; 
        conversations[session_key]["total_bytes"] += len(payload); 
        conversations[session_key]["payloads"].append(payload)

    scored_sessions = []
    for key, data in tqdm(conversations.items(), desc="Phase 2b: Scoring Heuristic Sessions"):
        if fingerprint_protocol(key, data["payloads"]) != "Unknown": continue
        

        score, reasons = 0, []
        if data["packet_count"] > 0: 
            avg_size = data["total_bytes"] / data["packet_count"]
        else: avg_size = 0.

        protocol, endpoints = key.split(':', 1)
        ep1, ep2 = endpoints.split('-')

        if ep1 and ep2:
            ep1 = re.sub(r':\d+$', '', ep1)  
            ep2 = re.sub(r':\d+$', '', ep2)  
            public_ip = ""
            ip1_is_private = is_private_ip(ep1)
            ip2_is_private = is_private_ip(ep2)
            if ip1_is_private and not ip2_is_private:
                score += 2
                #print(f"[+] Scoring {key} as Client-Server (LAN to WAN)")
                reasons.append(f"Client-Server (LAN to WAN)")
                public_ip = ep2
            elif not ip1_is_private and ip2_is_private:
                score += 2
                #print(f"[+] Scoring {key} as Client-Server (WAN to LAN)")
                reasons.append(f"Client-Server (WAN to LAN)")
                public_ip = ep1

        if 10 < avg_size < 1000:
            score += 2; reasons.append(f"Chatty (avg size: {int(avg_size)} bytes)")
        
        blob = b''.join(data["payloads"])
        extracted_strings = {}


        timestamps = TIMESTAMP_REGEX.findall(blob)
        if timestamps:
            score += 2; reasons.append("Contains likely Unix timestamps")

        hex_strings = HEX_STRING_REGEX.findall(blob)
        base64_strings = BASE64_LIKE_REGEX.findall(blob)
        if hex_strings or base64_strings:
            score += 3; reasons.append("Contains long ID-like strings")
            extracted_strings["hex_strings"] = [s.decode() for s in hex_strings]
            extracted_strings["base64_strings"] = [s.decode() for s in base64_strings]

        fingerprints = FINGERPRINT_REGEX.findall(blob)
        fingerprints2 = FINGERPRINT_REGEX2.findall(blob)
        if fingerprints or fingerprints2:
           

            score += 4  # Give a very high score for this, as it's a strong signal
            reasons.append("Contains DTLS fingerprint")

        if b"a=ice-ufrag" in blob or b"a=candidate" in blob or b"a=ice-pwd" in blob:
            score += 3
            reasons.append("Contains ICE/SDP fields")

        entropy = calculate_entropy(blob)
        if 4.0 < entropy < 7.8:
            score += 1; reasons.append(f"Medium entropy ({entropy:.2f})")
            
        if score > 4:
            geoip_info = {}
            ipinfo_token = "c5e82516cfad4a"
            try:
                if public_ip:
                    if ipinfo_token:
                        #print(f"[+] Performing GeoIP lookup for {public_ip} ...")
                        if handler and safe_get_ip_details:
                            geoip_info = safe_get_ip_details(handler, public_ip)
            except ValueError:
                pass
            
            scored_sessions.append({
                "session_id": key,
                "protocol": protocol,
                "endpoints": endpoints,
                "likelihood_score": score,
                "evidence": reasons,
                "extracted_strings": extracted_strings,
                "fingerprint": fingerprints + fingerprints2,
                "payload_snippet": blob[:200].decode('latin-1'),
                "geoip_info":  (
    geoip_info.get('country', 'N/A') + ", " +
    geoip_info.get('city', 'N/A') + ", " +
    geoip_info.get('region', 'N/A') + ", " +
    geoip_info.get('organization', 'N/A')
    if geoip_info else "Not available"
                )
            })

    return sorted(scored_sessions, key=lambda x: x["likelihood_score"], reverse=True)

# --- Main Orchestrator ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python stun_analyzer.py <input.pcap> [output.json]")
        sys.exit(1)
        
    pcap_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "stun_analysis.json"
    threshold = sys.argv[3] if len(sys.argv) > 3 else 4
    try:
        all_packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[ERROR] Could not read PCAP file: {e}")
        sys.exit(1)

    keyword_sessions = analyze_keyword_sessions(all_packets)
    total_keyword_packets = sum(len(s['packets']) for s in keyword_sessions.values())

    final_report = {}
    if total_keyword_packets >= int(threshold):
        print(f"\n[INFO] High-confidence signaling found ({total_keyword_packets} packets). Using keyword/pattern analysis.")
        for key, data in keyword_sessions.items():
            protocol = "Proprietary"; auth_method = "No auth detected"
            if "SIP" in data["_all_proto_hits"]: protocol = "SIP"
            elif "XMPP" in data["_all_proto_hits"]: protocol = "XMPP"
            elif "SDP" in data["_all_proto_hits"]: protocol = "Proprietary (SDP/JSON based)"
            if "token" in data["important_info"]: auth_method = "Token-based"
            
            endpoints = list(data["endpoints"]); server_ip = "Unknown"

            server_ip = "Unknown"
            connection_type = "Unknown"
            geoip_info = None
            
            if len(endpoints) == 2:
                ips = [ipaddress.ip_address(e) for e in endpoints]
                
                ip1_is_private = is_private_ip(endpoints[0])
                ip2_is_private = is_private_ip(endpoints[1])
                if ip1_is_private and not ip2_is_private:
                    connection_type = "Client-Server (LAN to WAN)"
                    public_endpoint = endpoints[1]
                    server_ip = str(ips[1])
                    if ipinfo_token and handler and safe_get_ip_details:
                        geoip_info = safe_get_ip_details(handler, server_ip) 

                elif not ip1_is_private and ip2_is_private:
                    connection_type = "Client-Server (LAN to WAN)"
                    public_endpoint = endpoints[0]
                    server_ip = str(ips[0])
                    if ipinfo_token and handler and safe_get_ip_details:
                        geoip_info = safe_get_ip_details(handler, server_ip)

                elif ip1_is_private and ip2_is_private:
                    connection_type = "Peer-to-Peer (LAN)"
                elif not ip1_is_private and not ip2_is_private:
                    connection_type = "Server-to-Server (WAN)"

                

            data["summary"] = {
                "detection_method": "Keyword/Pattern-Based",
                "how_is_signaling_done": protocol,
                "presence_of_authentication": auth_method,
                "is_cleartext_or_encrypted": "Encrypted (TLS)" if data["_is_encrypted"] else "Cleartext",
                "servers_contacted": server_ip,
                "connection_type": connection_type,
                "geo_location": (
                    geoip_info if geoip_info is not None
                    else ("GeoIP lookup skipped" if not ipinfo_token else "geoIP failed")
                )
            }
            del data["endpoints"], data["_all_proto_hits"], data["_is_encrypted"]
        final_report = keyword_sessions
   
    else:
        # --- Heuristic Analysis Fallback ---
        print(f"\n[INFO] Found only {total_keyword_packets} packets with keyword analysis (threshold is {threshold}). Falling back to heuristics.")
        heuristic_report = analyze_heuristic_sessions(all_packets)
        final_report = {"detection_method": "Heuristic-Based", "sessions": heuristic_report}
        if not heuristic_report: print("[WARN] Heuristic analysis also found no strong candidates for signaling.")

    with open(output_file, "w") as f: json.dump(final_report, f, indent=2)
    print("\n" + "="*50 + "\nANALYSIS SUMMARY\n" + "="*50)
    if isinstance(final_report, dict) and "sessions" in final_report: print(f"[+] Heuristic analysis complete. Found {len(final_report['sessions'])} potential signaling session(s).")
    else: print(f"[+] Keyword analysis complete. Found {len(final_report)} unique signaling session(s).")
    print(f"[+] Full report saved to '{output_file}'")
