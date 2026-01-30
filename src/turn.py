import json
import sys
import socket
import os
import ipaddress  # The definitive tool for IP address analysis
from scapy.all import rdpcap, UDP, IP, IPv6
from typing import Optional

from collections import defaultdict

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

# TURN/STUN methods (classes folded into names as you had them)
VALID_TURN_TYPES = {
    0x0003: "Allocate Request", 0x0103: "Allocate Success Response", 0x0113: "Allocate Error Response",
    0x0004: "Refresh Request", 0x0104: "Refresh Success Response", 0x0114: "Refresh Error Response",
    0x0006: "Send Indication", 0x0007: "Data Indication",
    0x0008: "CreatePermission Request", 0x0108: "CreatePermission Success Response", 0x0118: "CreatePermission Error Response",
    0x0009: "ChannelBind Request", 0x0109: "ChannelBind Success Response", 0x0119: "ChannelBind Error Response",
}

# IANA STUN attributes (RFC 8489/8656/7635)
ATTR_TYPES = {
    0x0006: "USERNAME",
    0x0008: "MESSAGE-INTEGRITY",
    0x0009: "ERROR-CODE",
    0x0014: "REALM",
    0x0015: "NONCE",
    0x0016: "XOR-RELAYED-ADDRESS",
    0x001B: "ACCESS-TOKEN",                  # RFC 7635
    0x001C: "MESSAGE-INTEGRITY-SHA256",      # RFC 8489
    0x001E: "USERHASH",                      # RFC 8489
    0x0020: "XOR-MAPPED-ADDRESS",
    0x8022: "SOFTWARE",
    0x8028: "FINGERPRINT",
    0x802E: "THIRD-PARTY-AUTHORIZATION",     # RFC 7635
    0x000C: "CHANNEL-NUMBER",
    0x000D: "LIFETIME",
    0x0012: "XOR-PEER-ADDRESS",
    0x0013: "DATA",
    0x0018: "EVEN-PORT",
    0x0019: "REQUESTED-TRANSPORT",   # RFC 5766 §14.7
    0x001A: "DONT-FRAGMENT",
    0x0022: "RESERVATION-TOKEN",
}
PROTO_MAP = {17: "UDP", 6: "TCP"}  # requested-transport first byte


OAUTH_ALLOWED_METHODS = {"Allocate Request", "Refresh Request"}  # RFC 7635 §8/§9


def is_private_ip(ip_str):
    """Checks if an IP address string is private (RFC 1918), loopback, or link-local."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False


# --- Helper Functions ---
def parse_attributes(payload: bytes):
    attributes = {}
    txid = payload[8:20]  # needed for XOR address decoding
    offset = 20
    while offset + 4 <= len(payload):
        try:
            at = int.from_bytes(payload[offset:offset+2], "big")
            ln = int.from_bytes(payload[offset+2:offset+4], "big")
            offset += 4
            if offset + ln > len(payload): break
            raw = payload[offset:offset+ln]
            name = ATTR_TYPES.get(at, f"0x{at:04x}")

            if name in {"SOFTWARE", "USERNAME", "REALM", "NONCE", "THIRD-PARTY-AUTHORIZATION"}:
                attributes[name] = raw.decode("utf-8", errors="ignore")

            elif name in {"MESSAGE-INTEGRITY", "MESSAGE-INTEGRITY-SHA256", "USERHASH", "RESERVATION-TOKEN"}:
                attributes[name] = raw.hex()

            elif name in {"XOR-RELAYED-ADDRESS", "XOR-MAPPED-ADDRESS", "XOR-PEER-ADDRESS"}:
                decoded = _decode_xor_addr(raw, txid)
                attributes[name] = decoded or raw.hex()

            elif name == "REQUESTED-TRANSPORT" and ln >= 4:
                # first byte is protocol (17=UDP, 6=TCP)
                proto = raw[0]
                attributes[name] = {"protocol_num": proto, "protocol": PROTO_MAP.get(proto, f"0x{proto:02x}")}

            elif name == "LIFETIME" and ln >= 4:
                attributes[name] = int.from_bytes(raw[:4], "big")

            elif name == "CHANNEL-NUMBER" and ln >= 4:
                ch = int.from_bytes(raw[:2], "big")
                rsv = int.from_bytes(raw[2:4], "big")
                attributes[name] = {"channel": ch, "rsv": rsv}

            elif name == "EVEN-PORT" and ln >= 1:
                attributes[name] = {"reserve_next": bool(raw[0] & 0x80)}

            elif name == "DONT-FRAGMENT":
                attributes[name] = True

            elif name == "DATA":
                attributes[name] = {"length": len(raw)}  # don’t dump payload

            elif name == "ERROR-CODE" and ln >= 4:
                error_class = raw[2] & 0x07
                number = error_class * 100 + raw[3]
                reason = raw[4:].decode("utf-8", errors="ignore") if ln > 4 else ""
                attributes[name] = {"code": number, "reason": reason}

            elif name == "ACCESS-TOKEN":
                tok_b64 = raw.decode("utf-8", errors="ignore")
                attributes[name] = {"present": True, "length": len(tok_b64), "preview": tok_b64[:16] + ("…" if len(tok_b64) > 16 else "")}

            else:
                attributes[name] = raw.hex()

            offset += (ln + 3) & ~3
        except Exception:
            break
    return attributes

def _decode_xor_addr(raw: bytes, txid: bytes) -> Optional[str]:
    """
    TURN/STUN address format per RFC 5389/5766:
    family(1), port(2), address(4/16); port ^= cookie[:2]; v4 ^= cookie; v6 ^= cookie+txid
    """
    try:
        if len(raw) < 4: return None
        family = raw[1]
        xport = int.from_bytes(raw[2:4], "big") ^ int.from_bytes(STUN_MAGIC_COOKIE[:2], "big")
        if family == 0x01:  # IPv4
            if len(raw) < 8: return None
            xip = int.from_bytes(raw[4:8], "big") ^ int.from_bytes(STUN_MAGIC_COOKIE, "big")
            ip = socket.inet_ntoa(xip.to_bytes(4, "big"))
            return f"{ip}:{xport}"
        elif family == 0x02:  # IPv6
            if len(raw) < 20: return None
            mask = STUN_MAGIC_COOKIE + txid  # 16 bytes
            xip = bytes(a ^ b for a, b in zip(raw[4:20], mask))
            ip = socket.inet_ntop(socket.AF_INET6, xip)
            return f"{ip}:{xport}"
    except Exception:
        return None
    return None


def analyze_turn_packet(pkt, attributes):
    ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    udp_layer = pkt.getlayer(UDP)
    payload = bytes(udp_layer.payload)

    msg_type_code = int.from_bytes(payload[0:2], 'big')
    tx_id = payload[8:20].hex()
    msg_name = VALID_TURN_TYPES.get(msg_type_code, "Unknown TURN Message")

    # Determine auth type (traditional STUN/TURN)
    auth_type = "None"
    if "MESSAGE-INTEGRITY" in attributes or "MESSAGE-INTEGRITY-SHA256" in attributes:
        if "REALM" in attributes and "NONCE" in attributes:
            auth_type = "Long-Term"
        else:
            auth_type = "Short-Term"

    # Detect OAuth (RFC 7635)
    oauth = {
        "supported_hint_seen": "THIRD-PARTY-AUTHORIZATION" in attributes,
        "used": ("ACCESS-TOKEN" in attributes) and ("USERNAME" in attributes),
        "kid": attributes.get("USERNAME") if ("ACCESS-TOKEN" in attributes and "USERNAME" in attributes) else None,
        "integrity_algorithm": "SHA-256" if "MESSAGE-INTEGRITY-SHA256" in attributes else ("HMAC-SHA1" if "MESSAGE-INTEGRITY" in attributes else None),
        "policy_violation": False,
    }
    if oauth["used"] and msg_name not in OAUTH_ALLOWED_METHODS:
        oauth["policy_violation"] = True

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
        "message_type": msg_name,
        "transaction_id": tx_id,
        "turn_version_standard": "RFC 5766 / 8656",
        "message_authentication_type": auth_type,
        "integrity_attribute": (
            "MESSAGE-INTEGRITY-SHA256" if "MESSAGE-INTEGRITY-SHA256" in attributes
            else ("MESSAGE-INTEGRITY" if "MESSAGE-INTEGRITY" in attributes else None)
        ),
        "internal_ip_exposure_via_mapped_address": "XOR-MAPPED-ADDRESS" in attributes,
        "library_name": lib_name,
        "library_version": lib_version,
        "oauth": oauth,
        "raw_payload_hex": payload.hex()
    }

    # Compact, safe attribute view (add AFTER analysis is created)
    safe_attrs = {}
    for k in ("XOR-RELAYED-ADDRESS","XOR-MAPPED-ADDRESS","XOR-PEER-ADDRESS",
              "REQUESTED-TRANSPORT","LIFETIME","CHANNEL-NUMBER","DATA"):
        if k in attributes:
            safe_attrs[k] = attributes[k]
    if safe_attrs:
        analysis["attrs_view"] = safe_attrs

    # Hints (put after analysis exists)
    if isinstance(attributes.get("ERROR-CODE"), dict):
        if attributes["ERROR-CODE"].get("code") == 438 and "NONCE" in attributes:
            analysis.setdefault("hints", []).append(
                "Stale Nonce: client should retry Allocate/Refresh with new NONCE"
            )

    if (analysis["message_type"] == "Allocate Request"
        and analysis["integrity_attribute"]
        and not (attributes.get("REALM") and attributes.get("NONCE"))):
        analysis.setdefault("hints", []).append(
            "Allocate with MESSAGE-INTEGRITY but missing REALM/NONCE (pre-401?)"
        )

    # Credentials
    creds = {}
    if attributes.get("USERNAME"): creds["username"] = attributes.get("USERNAME")
    if attributes.get("REALM"):    creds["realm"]    = attributes.get("REALM")
    if attributes.get("NONCE"):    creds["nonce"]    = attributes.get("NONCE")
    if "ACCESS-TOKEN" in attributes:
        creds["oauth_access_token_meta"] = attributes["ACCESS-TOKEN"]
    if attributes.get("THIRD-PARTY-AUTHORIZATION"):
        creds["third_party_authz_hint"] = attributes.get("THIRD-PARTY-AUTHORIZATION")
    if creds:
        analysis["credentials"] = creds

    # Error details (copy through)
    if isinstance(attributes.get("ERROR-CODE"), dict):
        analysis["error"] = attributes["ERROR-CODE"]

    # Optional reflexive address note
    if "XOR-MAPPED-ADDRESS" in attributes:
        analysis["reflexive_address_observed"] = attributes["XOR-MAPPED-ADDRESS"]

    return analysis


def _alloc_key_str(src_ip, src_port, dst_ip, dst_port) -> str:
    # stable, human-readable key
    return f"{src_ip}:{src_port}|{dst_ip}:{dst_port}"

def derive_turn_allocations(grouped_turn: dict) -> dict:
    """
    Build allocation-centric view:
      - client/server 5-tuple (as a string key)
      - relayed address from Allocate Success
      - latest lifetime, refresh count
      - requested transport (UDP/TCP)
      - permissions (peers), channels {channel -> peer}
      - data indications count/bytes
      - auth modes seen, oauth used, errors seen
    """
    allocs = {}

    for txid, msgs in grouped_turn.items():
        for m in msgs:
            # Make a per-flow key that is stable regardless of message direction:
            src_ip, src_port = m["src"].rsplit(":", 1)
            dst_ip, dst_port = m["dst"].rsplit(":", 1)
            # For requests, client -> server; for responses, flip so key always is client|server
            if "Request" in m["message_type"]:
                key_client_ip, key_client_port = src_ip, int(src_port)
                key_server_ip, key_server_port = dst_ip, int(dst_port)
            else:
                key_client_ip, key_client_port = dst_ip, int(dst_port)
                key_server_ip, key_server_port = src_ip, int(src_port)

            key = _alloc_key_str(key_client_ip, key_client_port, key_server_ip, key_server_port)

            # init allocation entry if needed
            alloc = allocs.setdefault(key, {
                "client": f"{key_client_ip}:{key_client_port}",
                "server": f"{key_server_ip}:{key_server_port}",
                "relayed_address": None,
                "requested_transport": None,   # "UDP"/"TCP"
                "lifetime": None,              # seconds
                "allocated": False,            # set True once we see Allocate Success
                "refresh_count": 0,
                "first_seen": m["timestamp"],
                "last_seen": m["timestamp"],
                "auth_modes": set(),
                "oauth_used": False,
                "permissions": set(),          # set of peers
                "channels": {},                # channel(int) -> peer(str)
                "data": {"count": 0, "bytes": 0},
                "errors": [],
            })
            alloc["last_seen"] = max(alloc["last_seen"], m["timestamp"])

            # auth / oauth rollups
            if m.get("message_authentication_type"):
                alloc["auth_modes"].add(m["message_authentication_type"])
            if m.get("oauth", {}).get("used"):
                alloc["oauth_used"] = True

            av = m.get("attrs_view") or {}  # tolerate missing

            mt = m["message_type"]
            if mt == "Allocate Success Response":
                alloc["allocated"] = True
                if av.get("XOR-RELAYED-ADDRESS"):
                    alloc["relayed_address"] = av["XOR-RELAYED-ADDRESS"]
                if av.get("LIFETIME") is not None:
                    alloc["lifetime"] = av["LIFETIME"]
                if av.get("REQUESTED-TRANSPORT"):
                    alloc["requested_transport"] = av["REQUESTED-TRANSPORT"].get("protocol")

            elif mt == "Refresh Success Response":
                # refresh count and lifetime update
                alloc["refresh_count"] += 1
                if av.get("LIFETIME") is not None:
                    alloc["lifetime"] = av["LIFETIME"]

            elif mt in ("CreatePermission Request", "CreatePermission Success Response"):
                peer = av.get("XOR-PEER-ADDRESS")
                if peer:
                    alloc["permissions"].add(peer)

            elif mt in ("ChannelBind Request", "ChannelBind Success Response"):
                ch = av.get("CHANNEL-NUMBER", {}).get("channel")
                peer = av.get("XOR-PEER-ADDRESS")
                if ch and peer:
                    alloc["channels"][int(ch)] = peer  # channel keys as ints are JSON-safe

            elif mt == "Data Indication":
                alloc["data"]["count"] += 1
                alloc["data"]["bytes"] += int(av.get("DATA", {}).get("length", 0))

            if "error" in m:
                alloc["errors"].append(m["error"])

    # convert sets to lists for JSON
    for alloc in allocs.values():
        alloc["auth_modes"] = sorted(list(alloc["auth_modes"]))
        alloc["permissions"] = sorted(list(alloc["permissions"]))

    return allocs


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
        if not pkt.haslayer(UDP):
            continue
        udp_payload = bytes(pkt[UDP].payload)
        if len(udp_payload) < 20:
            continue
        if udp_payload[4:8] != STUN_MAGIC_COOKIE:
            continue

        msg_type_code = int.from_bytes(udp_payload[0:2], 'big')
        if msg_type_code not in VALID_TURN_TYPES:
            continue

        try:
            attributes = parse_attributes(udp_payload)
            info = analyze_turn_packet(pkt, attributes)
            tx_id = info["transaction_id"]
            grouped_turn.setdefault(tx_id, []).append(info)
            if pkt.haslayer(IP):
                if not is_private_ip(pkt[IP].dst):
                    IPs.add(pkt[IP].dst)
        except Exception:
            pass

    print("\n[+] Post-processing transactions to refine authentication type...")
    for tx_id, pkts in grouped_turn.items():
        is_long_term = any(p.get("message_authentication_type") == "Long-Term" for p in pkts)
        is_short_term = any(p.get("message_authentication_type") == "Short-Term" for p in pkts)
        for p in pkts:
            if is_long_term:
                p["transaction_authentication_type"] = "Long-Term"
            else:
                p["transaction_authentication_type"] = "Short-Term" if is_short_term else "None"

        # Mark transaction-level OAuth status
        used_oauth = any(p["oauth"]["used"] for p in pkts if "oauth" in p)
        hinted_oauth = any(p["oauth"]["supported_hint_seen"] for p in pkts if "oauth" in p)
        violation = any(p["oauth"]["policy_violation"] for p in pkts if "oauth" in p)
        for p in pkts:
            p["transaction_oauth"] = {
                "used": used_oauth,
                "hint_seen": hinted_oauth,
                "policy_violation": violation
            }

    # --- GeoIP Phase ---
    geoip_summary = {}
    if safe_get_ip_details and ipinfo:
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

    turn_allocations = derive_turn_allocations(grouped_turn)


    final_report = {
        "geoip_summary": geoip_summary,
        "turn_transactions": grouped_turn,
        "turn_allocations": turn_allocations
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
