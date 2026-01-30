import json
import sys
import socket
import struct
import os
import binascii
from typing import Optional
from collections import defaultdict, deque

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


def derive_ice_transactions_from_stun(transactions):
    """
    Build a per-transaction ICE view from your canonical STUN packets.
    Filters out plain STUN server discovery (srflx pings), keeps only ICE checks.
    """
    ice_tx = {}

    for txid, pkts in transactions.items():
        # first Request and first Success for this tx
        req = next((p for p in pkts if p["message_type"] == "Binding Request"), None)
        suc = next((p for p in pkts if p["message_type"] == "Binding Success Response"), None)

        # pull attrs (safe defaults)
        req_attrs = (req or {}).get("attributes", {}) or {}
        suc_attrs = (suc or {}).get("attributes", {}) or {}
        username = req_attrs.get("USERNAME")

        # Heuristic: Request looks like ICE if it has typical ICE hints
        looks_ice = (
            ("PRIORITY" in req_attrs) or
            ("ICE-CONTROLLING" in req_attrs) or
            ("ICE-CONTROLLED"  in req_attrs) or
            (isinstance(username, str) and ":" in username)
        )

        # Heuristic: STUN server discovery (non-ICE) success usually carries RFC 5780 bits
        # Peer ICE Success won't include MAPPED-ADDRESS/RESPONSE-ORIGIN.
        is_server_ping = bool(
            suc and
            ("MAPPED-ADDRESS" in suc_attrs or "RESPONSE-ORIGIN" in suc_attrs) and
            not looks_ice
        )

        # Skip anything that is neither ICE nor a success (non-ICE Binding reqs)
        if not looks_ice and not suc:
            continue

        # Also skip STUN server discovery from ICE view
        if is_server_ping:
            continue

        # role + nomination from Request
        role = "unknown"
        if "ICE-CONTROLLING" in req_attrs:
            role = "controlling"
        elif "ICE-CONTROLLED" in req_attrs:
            role = "controlled"

        used_use_candidate = bool("USE-CANDIDATE" in req_attrs)

        # Pretty path strings
        def fmt_path(p):
            return f'{p["src_ip"]}:{p["src_port"]} \u2192 {p["dst_ip"]}:{p["dst_port"]}'

        request_path  = fmt_path(req) if req else "N/A"
        response_path = fmt_path(suc) if suc else "N/A"

        # Build the projected message list (only the ICE-relevant STUN types)
        msgs = []
        for p in sorted(pkts, key=lambda x: x["timestamp"]):
            if p["message_type"] not in ("Binding Request", "Binding Success Response", "Binding Error Response"):
                continue
            pattrs = p.get("attributes", {}) or {}
            sw = pattrs.get("SOFTWARE", "") or "Unknown"
            lib_name, lib_ver = "Unknown", "Unknown"
            if "-" in sw:
                parts = sw.split("-", 1)
                lib_name = parts[0].strip() or "Unknown"
                lib_ver = (parts[1].split(" ")[0].strip("'") if len(parts) > 1 else "Unknown")
            elif sw and sw != "Unknown":
                lib_name = sw

            # normalize USE-CANDIDATE to True
            if "USE-CANDIDATE" in pattrs and pattrs["USE-CANDIDATE"] in ("", None):
                pattrs = dict(pattrs)  # copy before mutating
                pattrs["USE-CANDIDATE"] = True

            msgs.append({
                "timestamp": p["timestamp"],
                "src": f'{p["src_ip"]}:{p["src_port"]}',
                "dst": f'{p["dst_ip"]}:{p["dst_port"]}',
                "transaction_id": txid,
                "message_type": p["message_type"],
                "username": pattrs.get("USERNAME"),
                "attributes": pattrs,
                "is_ice_used": True,
                "ice_version_standard": "RFC 8445 (modern ICE)",
                "library_name": lib_name,
                "library_version": lib_ver,
            })

        # If nothing is left (e.g., all were filtered), skip
        if not msgs:
            continue

        ice_tx[txid] = {
            "txid": txid,
            "has_request": bool(req),
            "has_success": bool(suc),
            "role": role,
            "used_use_candidate": used_use_candidate,
            "selected": bool(used_use_candidate and suc),  # nomination heuristic
            "request_path": request_path,
            "response_path": response_path,
            "messages": msgs,
        }

    return ice_tx

def _decode_address(value: bytes) -> str:
    """Decode (non‑XOR) MAPPED‑ADDRESS style attribute."""
    if len(value) < 4:
        return "Malformed"
    family = value[1]
    port = int.from_bytes(value[2:4], "big")
    if family == 0x01 and len(value) >= 8:  # IPv4
        ip = socket.inet_ntoa(value[4:8])
    elif family == 0x02 and len(value) >= 20:  # IPv6
        ip = socket.inet_ntop(socket.AF_INET6, value[4:20])
    else:
        return "Malformed"
    return f"{ip}:{port}"

def _decode_xor_address(value: bytes, transaction_id: bytes) -> str:
    """Decode XOR‑MAPPED‑ADDRESS / XOR‑RELAYED‑ADDRESS for IPv4/IPv6."""
    if len(value) < 4:
        return "Malformed"
    family = value[1]
    xport = int.from_bytes(value[2:4], "big") ^ int.from_bytes(STUN_MAGIC_COOKIE[:2], "big")

    if family == 0x01 and len(value) >= 8:  # IPv4
        xip = bytes(a ^ b for a, b in zip(value[4:8], STUN_MAGIC_COOKIE))
        ip = socket.inet_ntoa(xip)
    elif family == 0x02 and len(value) >= 20:  # IPv6
        mask = STUN_MAGIC_COOKIE + transaction_id  # 16 bytes
        xip = bytes(a ^ b for a, b in zip(value[4:20], mask))
        ip = socket.inet_ntop(socket.AF_INET6, xip)
    else:
        return "Malformed"
    return f"{ip}:{xport}"

def parse_attributes_manually(payload: bytes, transaction_id: bytes):
    """
    Parse attributes and also return 'meta' with offsets for fingerprint verification.
    Returns: (attributes: dict, meta: list[dict])
    """
    attributes = {}
    meta = []
    index = 0
    while index + 4 <= len(payload):
        try:
            t = int.from_bytes(payload[index:index+2], "big")
            l = int.from_bytes(payload[index+2:index+4], "big")
            vstart = index + 4
            vend = vstart + l
            if vend > len(payload):
                break
            raw = payload[vstart:vend]
            name = ATTRIBUTE_TYPES.get(t, f"Unknown(0x{t:04x})")

            # Decode commonly useful attributes
            if name in ("USERNAME", "SOFTWARE", "REALM", "NONCE"):
                attributes[name] = raw.decode("utf-8", errors="ignore")
            elif name == "XOR-MAPPED-ADDRESS":
                attributes[name] = _decode_xor_address(raw, transaction_id)
            elif name == "MAPPED-ADDRESS":
                attributes[name] = _decode_address(raw)
            elif name == "ERROR-CODE" and l >= 4:
                cls = raw[2] & 0x07
                num = cls * 100 + raw[3]
                reason = raw[4:].decode("utf-8", errors="ignore") if l > 4 else ""
                attributes[name] = {"code": num, "reason": reason}
            elif name == "UNKNOWN-ATTRIBUTES":
                attributes[name] = [f"0x{int.from_bytes(raw[i:i+2], 'big'):04x}" for i in range(0, l, 2)]
            elif name == "PRIORITY" and l == 4:
                attributes[name] = int.from_bytes(raw, "big")
            elif name in ("ICE-CONTROLLING", "ICE-CONTROLLED") and l == 8:
                attributes[name] = int.from_bytes(raw, "big")
            elif name in ("MESSAGE-INTEGRITY", "MESSAGE-INTEGRITY-SHA256", "USERHASH"):
                attributes[name] = raw.hex()
            elif name == "FINGERPRINT" and l == 4:
                attributes[name] = f"0x{int.from_bytes(raw, 'big'):08x}"
            else:
                attributes[name] = raw.hex()

            # Save offsets (relative to start of attribute section)
            padded = 4 + ((l + 3) & ~3)
            meta.append({"type": t, "name": name, "len": l, "start": index, "end": index + padded})
            index += padded

        except Exception:
            break
    return attributes, meta

def is_private_ip(ip_str):
    """Checks if an IP address string is private (RFC 1918), loopback, or link-local."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        # Handle cases where the input is not a valid IP address
        return False

def verify_fingerprint(full_msg: bytes, meta: list) -> Optional[bool]:
    """
    Returns True/False if FINGERPRINT exists, otherwise None.
    RFC: CRC32 over the message up to (but excluding) the FINGERPRINT attribute,
    XORed with 0x5354554e.
    """
    if not meta:   # guard for None or empty
        return None

    for m in meta:
        if m.get("name") == "FINGERPRINT" and m.get("len") == 4:
            attr_start = 20 + m["start"]        # attributes start after 20-byte header
            reported = int.from_bytes(full_msg[attr_start+4:attr_start+8], "big")
            crc = binascii.crc32(full_msg[:attr_start]) & 0xFFFFFFFF
            return (crc ^ 0x5354554E) == reported
    return None

def classify_stun_transaction(packets):
    """
    Returns (mode, auth) where:
    - mode ∈ {"ICE connectivity checks", "NAT behavior discovery (RFC 5780)", "STUN discovery (public IP)"}
    - auth ∈ {"None", "Short‑term (ICE)", "Long‑term (STUN)"}
    """
    saw = set()
    uses_short = uses_long = False
    for p in packets:
        attrs = p["attributes"]
        saw |= set(attrs.keys())
        if any(k in attrs for k in ("MESSAGE-INTEGRITY", "MESSAGE-INTEGRITY-SHA256")):
            if "REALM" in attrs and "NONCE" in attrs:
                uses_long = True
            elif "USERNAME" in attrs:
                uses_short = True

    if uses_long:
        auth = "Long-term (STUN)"
    elif uses_short:
        auth = "Short-term (ICE)"
    else:
        auth = "None"

    if {"PRIORITY", "ICE-CONTROLLING", "ICE-CONTROLLED", "USE-CANDIDATE"} & saw or uses_short:
        mode = "ICE connectivity checks"
    elif {"CHANGE-REQUEST", "RESPONSE-ORIGIN", "OTHER-ADDRESS", "RESPONSE-PORT"} & saw:
        mode = "NAT behavior discovery (RFC 5780)"
    else:
        mode = "STUN discovery (public IP)"

    return mode, auth


def extract_ice_metadata(packets):
    """
    Returns a dict with optional ICE bits (ufrags, roles, priorities seen).
    """
    meta = {}
    # Pick first USERNAME; in ICE it's "remoteUfrag:localUfrag"
    for p in packets:
        uname = p["attributes"].get("USERNAME")
        if uname and ":" in uname:
            remote, local = uname.split(":", 1)
            meta["ufrag_remote"] = remote
            meta["ufrag_local"] = local
            break

    roles = set()
    prios = []
    for p in packets:
        attrs = p["attributes"]
        if "ICE-CONTROLLING" in attrs:
            roles.add("controlling")
            meta["tie_breaker"] = attrs["ICE-CONTROLLING"]
        if "ICE-CONTROLLED" in attrs:
            roles.add("controlled")
            meta["tie_breaker"] = attrs["ICE-CONTROLLED"]
        if "PRIORITY" in attrs:
            prios.append(attrs["PRIORITY"])
    if roles:
        meta["roles_seen"] = sorted(roles)
    if prios:
        meta["priority_min"] = min(prios)
        meta["priority_max"] = max(prios)
    return meta

def analyze_stun_transaction(packets):
    """
    Analyze a STUN transaction keyed by Transaction ID.
    Roles are derived from message types (requests vs responses).
    """
    summary = {
        "is_stun_used": True,
        "stun_standard": "RFC 5389/8489 (magic cookie present)",
        "mode": "Unknown",
        "authentication_type": "None",
        "client_lan_ip": "Unknown",
        "responder_ip": "Unknown",
        "exposed_reflexive_address": "Not detected",
        "public_ip_disclosed": False,       # expected behavior for discovery/ICE (not a 'leak')
        "library_info": "Not detected",
        "asn_info": "Unknown",
        "packets": packets
    }

    if not packets:
        return summary

    # Identify the requester from a Binding Request
    req = next((p for p in packets if p["message_type"] == "Binding Request"), None)
    if req:
        summary["client_lan_ip"] = req["src_ip"]
        summary["responder_ip"] = req["dst_ip"]
    else:
        # Fallback: just use the first packet direction
        summary["client_lan_ip"] = packets[0]["src_ip"]
        summary["responder_ip"] = packets[0]["dst_ip"]
        summary["note"] = "No Binding Request observed; roles inferred from first packet."

    # Enrich from attributes
    for p in packets:
        attrs = p["attributes"]
        if attrs.get("XOR-MAPPED-ADDRESS"):
            summary["exposed_reflexive_address"] = attrs["XOR-MAPPED-ADDRESS"]
            try:
                ip_part = attrs["XOR-MAPPED-ADDRESS"].rsplit(":", 1)[0]
                summary["public_ip_disclosed"] = not is_private_ip(ip_part)
            except Exception:
                pass
        if attrs.get("SOFTWARE"):
            summary["library_info"] = attrs["SOFTWARE"]

    # Classify mode & auth
    mode, auth = classify_stun_transaction(packets)
    summary["mode"] = mode
    summary["authentication_type"] = auth

    # ICE-specific metadata (if any)
    if mode == "ICE connectivity checks":
        summary["ice"] = extract_ice_metadata(packets)

    return summary

def derive_ice_output_path(output_path: str) -> str:
    """
    Try to produce a sibling ICE JSON path next to the main output.
    - If the filename contains 'stun' (case-insensitive), swap it for 'ice'.
    - Else, write 'ice_analysis.json' in the same directory.
    """
    p = Path(output_path)
    stem_lower = p.stem.lower()
    if "stun" in stem_lower:
        # Replace only the first 'stun' occurrence in the stem to keep other parts intact
        new_stem = p.stem.replace("stun", "ice", 1).replace("STUN", "ICE", 1)
        return str(p.with_name(new_stem + p.suffix))
    else:
        return str(p.with_name("ice_analysis.json"))
    
def main(pcap_path, output_path):

    packets = rdpcap(pcap_path)
    transactions = {}
    responder_ips = set()  # endpoints that sent a Success Response (server/peer)

    for pkt in packets:
        if not (pkt.haslayer(UDP) and len(pkt[UDP].payload) >= 20):
            continue

        payload = bytes(pkt[UDP].payload)
        if payload[4:8] != STUN_MAGIC_COOKIE:
            continue

        msg_type = int.from_bytes(payload[0:2], "big")
        if msg_type not in VALID_STUN_TYPES:
            continue

        msg_len = int.from_bytes(payload[2:4], "big")
        if len(payload) < 20 + msg_len:
            continue  # truncated

        transaction_id = payload[8:20]
        attrs, meta = parse_attributes_manually(payload[20:20+msg_len], transaction_id)
        fp_ok = verify_fingerprint(payload[:20+msg_len], meta)

        # Determine IP layer (IPv4 or IPv6)
        ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)

        pkt_info = {
            "timestamp": float(pkt.time),
            "src_ip": ip_layer.src,
            "src_port": pkt[UDP].sport,
            "dst_ip": ip_layer.dst,
            "dst_port": pkt[UDP].dport,
            "message_type": MESSAGE_TYPES.get(msg_type, f"Unknown(0x{msg_type:04x})"),
            "attributes": attrs,
        }
        if fp_ok is not None:
            pkt_info["fingerprint_valid"] = fp_ok

        transactions.setdefault(transaction_id.hex(), []).append(pkt_info)

        # Track 'server-like' responders for GeoIP (senders of Success Response)
        if (msg_type == 0x0101) and ip_layer.src:
            responder_ips.add(ip_layer.src)
    
 # --- Geolocation Phase ---
    geoip_summary = {}
    if safe_get_ip_details and ipinfo:
        load_dotenv(dotenv_path=Path('.') / '.env', override=True)
        ipinfo_token = os.getenv('IPINFO_TOKEN')
        if ipinfo_token:
            handler = ipinfo.getHandler(ipinfo_token, request_options={"timeout": 5})
            print(f"\n[+] Performing GeoIP lookup for {len(responder_ips)} unique responder IP(s)...")
            for ip in tqdm(responder_ips, desc="Looking up IPs"):
                geoip_summary[ip] = safe_get_ip_details(handler, ip)
        else:
            print("\n[WARN] IPINFO_TOKEN environment variable not set. Skipping GeoIP lookup.")
            geoip_summary["error"] = "IPINFO_TOKEN not configured."


    # Analyze and enrich transactions
    analyzed_transactions = {txid: analyze_stun_transaction(pkts) for txid, pkts in transactions.items()}

    ice_transactions = derive_ice_transactions_from_stun({
        txid: v["packets"] for txid, v in analyzed_transactions.items()
    })


    final_report = {
        "geoip_summary": geoip_summary,
        "stun_transactions": analyzed_transactions,
        "ice_transactions": ice_transactions,
    }


    with open(output_path, "w") as f:
        json.dump(final_report, f, indent=2)

    ice_output_path = derive_ice_output_path(output_path)
    #ice_only = ice_transactions  # the ICE template expects the tx map at the root
    with open(ice_output_path, "w") as f:
        json.dump(final_report, f, indent=2)


    print(f"[+] Detection complete. Found {len(analyzed_transactions)} STUN transactions.")
    print(f"[+] Wrote STUN+ICE combined report to '{output_path}'")
    print(f"[+] Wrote ICE-only report to '{ice_output_path}'")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python stun_analyzer.py <input.pcap> [output.json]")
        sys.exit(1)
        
    pcap_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "stun_analysis.json"
    
    main(pcap_file, output_file)
