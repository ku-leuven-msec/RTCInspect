import json
import sys
import argparse
import math
from collections import Counter
from scapy.all import rdpcap, TCP, UDP, IP, IPv6
from tqdm import tqdm

# --- Configuration ---
# Number of initial packets to consider as potential setup/handshake
SETUP_PACKET_WINDOW = 50
# How much larger a packet must be than the average setup packet to be considered "media"
MEDIA_SIZE_THRESHOLD_MULTIPLIER = 1.5
# Number of sample media payloads to collect for entropy analysis
PAYLOAD_SAMPLE_SIZE = 50

# --- Helper Functions ---
def get_session_key(pkt):
    try:
        ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        transport_layer = pkt.getlayer(TCP) or pkt.getlayer(UDP)
        key_parts = sorted([(ip_layer.src, transport_layer.sport), (ip_layer.dst, transport_layer.dport)])
        protocol = "TCP" if pkt.haslayer(TCP) else "UDP"
        return f"{protocol}:{key_parts[0][0]}:{key_parts[0][1]}-{key_parts[1][0]}:{key_parts[1][1]}"
    except AttributeError: return None

def calculate_entropy(data):
    if not data: return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counter.values())

def interpret_entropy(score):
    if score > 7.5: return "Very High (Strongly indicates strong encryption or compression)"
    elif score > 6.0: return "High (Likely encrypted or compressed)"
    elif score > 4.0: return "Medium (Could be simple structured data, headers, or weak compression)"
    else: return "Low (Strongly indicates unencrypted, cleartext data)"

def analyze_media_stream(pcap_file, output_file):
    """Finds the heaviest stream and intelligently analyzes its media-only payload."""
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[ERROR] Could not read PCAP file: {e}"); return

    conversations = {}
    print("[+] Phase 1: Analyzing conversations and data volume...")
    for pkt in tqdm(packets, desc="Processing packets"):
        session_key = get_session_key(pkt)
        if not session_key: continue
        if session_key not in conversations: conversations[session_key] = {"packet_count": 0, "total_bytes": 0, "packets": []}
        
        payload = bytes(pkt.getlayer(TCP).payload if pkt.haslayer(TCP) else pkt.getlayer(UDP).payload)
        conversations[session_key]["packet_count"] += 1
        conversations[session_key]["total_bytes"] += len(payload)
        conversations[session_key]["packets"].append(payload)

    if not conversations:
        print("[-] No TCP or UDP conversations found."); return

    # --- Phase 2: Find the heaviest stream ---
    print("\n[+] Phase 2: Identifying the heaviest media stream...")
    heaviest_key = max(conversations, key=lambda k: conversations[k]["total_bytes"])
    heaviest_stream_packets = conversations[heaviest_key]["packets"]
    
    # --- Phase 3: Intelligently sample the media payload ---
    print("[+] Phase 3: Separating setup from media and analyzing encryption grade...")
    
    # Calculate the average size of the first few packets (the likely setup phase)
    setup_packets = heaviest_stream_packets[:SETUP_PACKET_WINDOW]
    avg_setup_size = sum(len(p) for p in setup_packets) / len(setup_packets) if setup_packets else 0
    media_size_threshold = avg_setup_size * MEDIA_SIZE_THRESHOLD_MULTIPLIER

    # Collect samples ONLY from the "steady state" media packets
    media_payload_samples = []
    for payload in heaviest_stream_packets:
        if len(payload) > media_size_threshold:
            media_payload_samples.append(payload)
            if len(media_payload_samples) >= PAYLOAD_SAMPLE_SIZE:
                break
    
    if not media_payload_samples:
        print("[WARN] Could not distinguish a 'steady state' media phase. Analyzing all packets instead.")
        media_payload_samples = heaviest_stream_packets[:PAYLOAD_SAMPLE_SIZE]
    
    # Calculate entropy on the media-only samples
    entropies = [calculate_entropy(p) for p in media_payload_samples]
    avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
    
    # Attempt to identify protocol
    protocol_info = "Generic " + heaviest_key.split(':')[0] + " Stream"
    if heaviest_key.startswith("UDP"):
        first_byte = media_payload_samples[0][0] if media_payload_samples else 0
        if 128 <= first_byte <= 191: # Heuristic for RTP (version 2)
            protocol_info = "UDP Stream (Likely RTP)"
        elif 20 <= first_byte <= 63: # Heuristic for DTLS (handshake/app_data)
            protocol_info = "UDP Stream (Likely DTLS/WebRTC)"

    report = {
        "identified_media_stream": {
            "session_id": heaviest_key,
            "protocol": heaviest_key.split(':')[0],
            "total_packets": conversations[heaviest_key]["packet_count"],
            "total_data_volume_mb": round(conversations[heaviest_key]["total_bytes"] / (1024*1024), 2)
        },
        "encryption_analysis": {
            "average_payload_entropy": round(avg_entropy, 4),
            "encryption_grade": interpret_entropy(avg_entropy),
            "analysis_note": f"Entropy calculated on {len(media_payload_samples)} media-only packets, ignoring initial setup phase."
        },
        "extra_info": {
            "protocol_identification": protocol_info,
            "notes": "This analysis identifies the conversation with the highest data volume. The 'Encryption Grade' is based on the randomness (entropy) of the steady-state media payload, excluding initial handshake packets."
        }
    }

    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)

    print("\n" + "="*50 + "\nANALYSIS COMPLETE\n" + "="*50)
    print(f"[SUCCESS] Heaviest stream identified and analyzed.")
    print(f"[INFO]    Session: {report['identified_media_stream']['session_id']}")
    print(f"[INFO]    Encryption Grade: {report['encryption_analysis']['encryption_grade']} (Entropy: {report['encryption_analysis']['average_payload_entropy']})")
    print(f"[+] Full report saved to '{output_file}'")

# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Identifies and analyzes the primary media stream in a PCAP file.")
    parser.add_argument("pcap_file", help="Input PCAP or PCAPNG file")
    parser.add_argument("output_file", nargs='?', default="media_analysis.json", help="Output JSON file")
    args = parser.parse_args()
    
    analyze_media_stream(args.pcap_file, args.output_file)