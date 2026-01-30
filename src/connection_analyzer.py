import json
import sys
import argparse
from datetime import datetime, timezone
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, Raw, ICMP
# Attempt to import specific TLS/DTLS/QUIC layers if available in Scapy
from scapy.layers.tls.all import TLS
try:
    from scapy.layers.tls.dtls import DTLS
except ImportError:
    DTLS = None # DTLS layer might not be directly importable in some Scapy setups
try:
    from scapy.layers.inet.quic import QUIC # Or scapy.layers.tls.quic
except ImportError:
    QUIC = None # QUIC layer might not be directly importable

from tqdm import tqdm
import ipaddress

# --- Helper Functions ---
def get_conversation_key(pkt):
    """
    Creates a unique, canonical key for a conversation based on IPs, ports, and transport protocol.
    Key format: TRANSPORT_PROTO:IP1:PORT1-IP2:PORT2 (IPs/Ports sorted for canonical key)
    """
    ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if not ip_layer: return None

    transport_layer_name = "Other"
    src_port, dst_port = None, None

    if pkt.haslayer(TCP):
        transport_layer_name = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        transport_layer_name = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        transport_layer_name = "ICMP"
        src_port, dst_port = "N/A", "N/A" # ICMP does not use ports
    
    if src_port is None: # No recognized transport layer
        return None

    addr1 = (str(ip_layer.src), str(src_port))
    addr2 = (str(ip_layer.dst), str(dst_port))

    # Sort the addresses to make the key canonical (direction-independent)
    sorted_addrs = tuple(sorted([addr1, addr2]))

    return f"{transport_layer_name}:{sorted_addrs[0][0]}:{sorted_addrs[0][1]}-{sorted_addrs[1][0]}:{sorted_addrs[1][1]}"

def identify_app_protocols(pkt):
    """Identifies higher-level application protocols in a packet."""
    protocols = set()
    if pkt.haslayer('DNS'):
        protocols.add("DNS")
    if pkt.haslayer('HTTP'): # HTTP/1.x over TCP
        protocols.add("HTTP")
    if pkt.haslayer(TLS): # TLS over TCP
        protocols.add("TLS")
    if DTLS and pkt.haslayer(DTLS): # DTLS over UDP
        protocols.add("DTLS")
    if QUIC and pkt.haslayer(QUIC): # QUIC over UDP
        protocols.add("QUIC")
    # Note: HTTP/2, HTTP/3, WebSocket are often inside TLS/QUIC and not directly dissected by Scapy.
    return list(protocols)

def is_private_ip(ip_str):
    """Checks if an IP address is private."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False

# --- Main Logic ---
def extract_conversation_info(pcap_file, output_file):
    """
    Extracts high-level conversation information from a PCAP file.
    """
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[ERROR] Could not read PCAP file: {e}")
        return

    conversations = {} # Key: conversation_id, Value: dict of aggregated data

    print("[+] Extracting conversation information...")
    for pkt_idx, pkt in enumerate(tqdm(packets, desc="Processing packets")):
        conv_key = get_conversation_key(pkt)
        if not conv_key: continue

        # Get IP and transport layer info for initial conversation creation
        ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        transport_layer = pkt.getlayer(TCP) or pkt.getlayer(UDP) # Will be None for ICMP

        if conv_key not in conversations:
            conversations[conv_key] = {
                "conversation_id": conv_key,
                "transport_protocol": conv_key.split(':')[0], # Extract TCP/UDP/ICMP
                "src_ip": str(ip_layer.src),
                "src_port": str(transport_layer.sport) if transport_layer else "N/A",
                "dst_ip": str(ip_layer.dst),
                "dst_port": str(transport_layer.dport) if transport_layer else "N/A",
                "total_packets": 0,
                "total_bytes": 0, # Total bytes of the entire packet
                "start_time": datetime.fromtimestamp(pkt.time, tz=timezone.utc).isoformat(),
                "end_time": datetime.fromtimestamp(pkt.time, tz=timezone.utc).isoformat(), # Will be updated
                "application_protocols": set(), # Use a set to avoid duplicates
                "notes": []
            }
        
        conv_data = conversations[conv_key]

        # Update aggregated metrics
        conv_data["total_packets"] += 1
        conv_data["total_bytes"] += len(pkt) # Total packet length (including Ethernet/IP headers)
        conv_data["end_time"] = datetime.fromtimestamp(pkt.time, tz=timezone.utc).isoformat()
        
        # Identify application protocols in this packet and add to set
        conv_data["application_protocols"].update(identify_app_protocols(pkt))

    # --- Finalize and Add Notes ---
    final_conversations = []
    for key, data in conversations.items():
        data["application_protocols"] = list(data["application_protocols"]) # Convert set to list
        data["total_data_mb"] = round(data["total_bytes"] / (1024 * 1024), 2)
        
        # Add notes about potential encrypted layers requiring deeper analysis
        if "TLS" in data["application_protocols"] and data["transport_protocol"] == "TCP":
            data["notes"].append("TLS detected. Higher-layer protocols (e.g., HTTP/2, WebSocket) within TLS are encrypted and require decryption for analysis.")
        elif "DTLS" in data["application_protocols"] and data["transport_protocol"] == "UDP":
            data["notes"].append("DTLS detected. Higher-layer protocols (e.g., WebRTC) within DTLS are encrypted and require decryption for analysis.")
        elif "QUIC" in data["application_protocols"] and data["transport_protocol"] == "UDP":
            data["notes"].append("QUIC detected. Higher-layer protocols (e.g., HTTP/3) within QUIC are encrypted and require decryption for analysis.")
        
        # Add IP type notes
        src_ip_private = is_private_ip(data["src_ip"])
        dst_ip_private = is_private_ip(data["dst_ip"])
        
        if src_ip_private and dst_ip_private:
            data["notes"].append("Local network (private IP to private IP) conversation.")
        elif not src_ip_private and not dst_ip_private:
            data["notes"].append("Public internet (public IP to public IP) conversation.")
        elif src_ip_private and not dst_ip_private:
            data["notes"].append(f"Client ({data['src_ip']}) to Server ({data['dst_ip']}) conversation.")
        elif not src_ip_private and dst_ip_private:
            data["notes"].append(f"Server ({data['src_ip']}) to Client ({data['dst_ip']}) conversation.")

        data["notes"] = list(set(data["notes"])) # Remove duplicate notes
        final_conversations.append(data)

    # Sort conversations by total_bytes (largest first)
    final_conversations.sort(key=lambda x: x["total_bytes"], reverse=True)

    with open(output_file, "w") as f:
        json.dump(final_conversations, f, indent=2)

    print("\n" + "="*50 + "\nANALYSIS COMPLETE\n" + "="*50)
    print(f"[+] Extracted information for {len(final_conversations)} unique conversations.")
    print(f"[+] Full report saved to '{output_file}'")

# --- Main Execution ---
if __name__ == "__main__":
       
    pcap_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "connection_analysis.json"
    verbose = True if len(sys.argv) > 3 else False
    
    extract_conversation_info(pcap_file, output_file)