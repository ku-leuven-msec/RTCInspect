import json
import sys
import argparse
import re
import math
from collections import Counter
from tqdm import tqdm
import pyshark

# --- Configuration for Heuristic Analysis ---
TIMESTAMP_REGEX = re.compile(b'1[6-7]\d{8}')
HEX_STRING_REGEX = re.compile(b'[a-f0-9]{20,}')
BASE64_LIKE_REGEX = re.compile(b'[A-Za-z0-9+/=]{20,}')
ASCII_STRING_REGEX = re.compile(b'[ -~]{5,}')

# --- Helper Functions ---
def get_session_key(pkt):
    try:
        # Use info from the pyshark packet object
        return f"QUIC:{pkt.ip.src}:{pkt.udp.srcport}-{pkt.ip.dst}:{pkt.udp.dstport}"
    except AttributeError:
        return None

def calculate_entropy(data):
    if not data: return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counter.values())

def analyze_quic_heuristics(decrypted_pcap_file, output_file, score_threshold=3):
    """
    Finds potential proprietary signaling in decrypted QUIC streams using heuristics.
    """
    print("[+] Analyzing decrypted pcap for proprietary QUIC signaling...")
    
    try:
        # Broad filter to get all HTTP/3 packets
        cap = pyshark.FileCapture(decrypted_pcap_file, display_filter="http3")
        cap.load_packets()
    except Exception as e:
        print(f"[ERROR] Could not run pyshark. Error: {e}")
        return

    conversations = {}
    for pkt in tqdm(cap, desc="Phase 1: Gathering Decrypted Payloads"):
        session_key = get_session_key(pkt)
        if not session_key: continue
            
        try:
            payload_hex = None
            if hasattr(pkt.http3, 'data_data'):
                payload_hex = pkt.http3.data_data
            elif hasattr(pkt.http3, 'data') and isinstance(pkt.http3.data, str):
                payload_hex = pkt.http3.data

            if payload_hex:
                if session_key not in conversations:
                    conversations[session_key] = {"packet_count": 0, "total_bytes": 0, "payloads": []}
                
                payload_bytes = bytes.fromhex(payload_hex.replace(':', ''))
                conversations[session_key]["packet_count"] += 1
                conversations[session_key]["total_bytes"] += len(payload_bytes)
                conversations[session_key]["payloads"].append(payload_bytes)
        except (AttributeError, KeyError):
            continue
    
    cap.close()

    # --- Phase 2: Score each conversation ---
    print("\n[+] Phase 2: Scoring conversations based on signaling heuristics...")
    scored_sessions = []
    for key, data in tqdm(conversations.items(), desc="Scoring sessions"):
        score, reasons, extracted_strings = 0, [], {}
        avg_size = data["total_bytes"] / data["packet_count"]
        
        if 10 < avg_size < 1500: # QUIC packets can be larger
            score += 2; reasons.append(f"Chatty (avg size: {int(avg_size)} bytes)")
        
        blob = b''.join(data["payloads"])
        
    
        id_strings = HEX_STRING_REGEX.findall(blob) + BASE64_LIKE_REGEX.findall(blob)
        if id_strings:
            score += 2; reasons.append("Contains long ID-like strings")
            extracted_strings["id_strings"] = [s.decode() for s in id_strings]

        ascii_strings = [s.decode() for s in ASCII_STRING_REGEX.findall(blob) if not any(s.decode() in ids for ids in extracted_strings.get("id_strings", []))]
        if ascii_strings:
            score += 1; reasons.append("Contains printable ASCII strings")
            extracted_strings["ascii_strings"] = ascii_strings

        entropy = calculate_entropy(blob)
        if 4.0 < entropy < 7.9: # High entropy is normal for encrypted QUIC, but decrypted payload should be structured.
            score += 1; reasons.append(f"Medium entropy ({entropy:.2f})")
            
        if score >= score_threshold:
            scored_sessions.append({
                "session_id": key,
                "likelihood_score": score,
                "evidence": reasons,
                "extracted_strings": extracted_strings,
                "payload_snippet": blob[:200].decode('latin-1')
            })

    # --- Phase 3: Report high-scoring sessions ---
    scored_sessions.sort(key=lambda x: x["likelihood_score"], reverse=True)
    with open(output_file, "w") as f:
        json.dump(scored_sessions, f, indent=2)

    print("\n" + "="*60 + "\nANALYSIS COMPLETE\n" + "="*60)
    print(f"[+] Found {len(scored_sessions)} high-confidence candidate(s) for proprietary signaling over QUIC.")
    print(f"[+] Full report saved to '{output_file}'")

# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Finds potential proprietary signaling in DECRYPTED QUIC traffic using heuristics.")
    parser.add_argument("pcap_file", help="Input DECRYPTED PCAP or PCAPNG file.")
    parser.add_argument("-o", "--output-file", default="quic_heuristic_analysis.json", help="Output JSON file.")
    parser.add_argument("-t", "--threshold", type=int, default=3, help="Minimum score to be considered a candidate.")
    args = parser.parse_args()
    
    analyze_quic_heuristics(args.pcap_file, args.output_file, args.threshold)