import json
import sys
import argparse
from flask import sessions
import pyshark
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.backends import default_backend
from tqdm import tqdm
from ciphers import CIPHER_SUITES_IANA, WEAK_CIPHER_PREFIXES, WEAK_SUBSTRINGS

# --- Helper Functions (No changes needed here) ---
def get_session_key(pkt):
    try:
        # Choose the correct IP layer
        src_ip = pkt.ip.src if hasattr(pkt, 'ip') else pkt.ipv6.src
        dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else pkt.ipv6.dst

        # Get transport layer ports
        transport_layer = pkt[pkt.transport_layer]
        src_port = transport_layer.srcport
        dst_port = transport_layer.dstport

        key_parts = sorted([(src_ip, src_port), (dst_ip, dst_port)])
        return f"{key_parts[0][0]}:{key_parts[0][1]}-{key_parts[1][0]}:{key_parts[1][1]}"
    except AttributeError:
        return None

def is_cipher_strong(cipher_name):
    if not cipher_name: return False
    if any(cipher_name.upper().startswith(prefix) for prefix in WEAK_CIPHER_PREFIXES): return False
    if any(weak_part in cipher_name.upper() for weak_part in WEAK_SUBSTRINGS): return False
    return True

def analyze_certificate(cert_hex_string, date):
    try:
        #print("[DEBUG] Analyzing certificate data...")
        cert_data = bytes.fromhex(cert_hex_string)
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
        is_self_signed = cert.issuer == cert.subject
        #print(f"[DEBUG] Certificate validity check: {cert.not_valid_before_utc} <= {date} <= {cert.not_valid_after_utc}")

        is_valid_period = cert.not_valid_before_utc <= date <= cert.not_valid_after_utc
        try: san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName); sans = [str(name) for name in san_ext.value]
        except x509.ExtensionNotFound: sans = []
        issuer_cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value if cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME) else "Not Found"
        subject_cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value if cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME) else "Not Found"
        fingerprint = cert.fingerprint(hashes.SHA256())
        formatted_fp = ":".join(f"{b:02X}" for b in fingerprint)

        return {
            "self_signed": is_self_signed,
            "validity_period_ok": is_valid_period,
            "valid_from": cert.not_valid_before_utc.isoformat(),
            "valid_until": cert.not_valid_after_utc.isoformat(),
            "issuer_cn": issuer_cn,
            "subject_cn": subject_cn,
            "subject_alternative_names": sans,
            "key_exchange_algorithm": cert.signature_algorithm_oid._name,
            "fingerprint": formatted_fp

        }
    except Exception as e:
        return {"error": f"Failed to parse certificate: {e}"}

def analyze_tls_sessions(pcap_file, output_file, verbose=False):
    sessions = {}
    print("[+] Analyzing all TLS and DTLS packets...")

    try:
        # Capture both TLS and DTLS packets
        cap = pyshark.FileCapture(pcap_file, display_filter="tls or dtls")
        cap.load_packets()
        total_packets = len(cap)
    except Exception as e:
        print(f"[ERROR] Error opening pcap file: {e}")
        return

    for pkt in tqdm(cap, total=total_packets, desc="Processing packets"):
        # --- Session key extraction (IPv4/IPv6 aware) ---
        key = get_session_key(pkt)
        src_ip = pkt.ip.src if hasattr(pkt, 'ip') else pkt.ipv6.src
        dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else pkt.ipv6.dst
        transport_layer = pkt[pkt.transport_layer]
        src_port = transport_layer.srcport
        dst_port = transport_layer.dstport

        # Determine TLS/DTLS layer
        protocol_layer = None
        protocol_name = None
        if hasattr(pkt, 'tls'):
            protocol_layer = pkt.tls
            protocol_name = "TLS"
        elif hasattr(pkt, 'dtls'):
            protocol_layer = pkt.dtls
            protocol_name = "DTLS"

        if not protocol_layer:
            continue

        # Initialize session if new
        if key not in sessions:
            if verbose:
                print(f"\n[INFO] Packet {pkt.number}: Discovered new {protocol_name} session: {key}")
            sessions[key] = {
                "protocol": protocol_name,
                "client_endpoint": f"{src_ip}:{src_port}",
                "server_endpoint": f"{dst_ip}:{dst_port}",
                "total_bytes": 0,
                "client_hello": {},
                "server_hello": {},
                "certificate_details": {}
            }

        session = sessions[key]

        # Add packet size
        try:
            session["total_bytes"] += int(pkt.length)
        except AttributeError:
            pass

        # --- Handshake parsing ---
        try:
            if hasattr(protocol_layer, 'handshake_type'):
                pkt_num = pkt.number

                # ClientHello
                if protocol_layer.handshake_type == '1' and not session["client_hello"].get("offered_cipher_suites"):
                    if verbose:
                        print(f"  [DEBUG] Packet {pkt_num}: Found ClientHello")

                    # TLS version
                    try:
                        session["client_hello"]["version"] = protocol_layer.handshake_version.showname_value
                    except AttributeError:
                        pass

                    # Offered ciphers
                    try:
                        raw_values = [f.raw_value for f in protocol_layer.handshake_ciphersuite.all_fields]
                        cipher_names = [CIPHER_SUITES_IANA.get(c.lower(), {}).get('name', f"Unknown (0x{c})") for c in raw_values]
                        session["client_hello"]["offered_cipher_suites"] = cipher_names
                        if verbose:
                            print(f"    [SUCCESS] Extracted {len(cipher_names)} cipher suites")
                    except (AttributeError, KeyError):
                        if verbose:
                            print(f"    [FAIL] Could not extract offered cipher suites")

                # ServerHello
                if protocol_layer.handshake_type == '2' and not session["server_hello"].get("chosen_crypto_suite"):
                    if verbose:
                        print(f"  [DEBUG] Packet {pkt_num}: Found ServerHello")
                    try:
                        chosen_hex = protocol_layer.handshake_ciphersuite.raw_value
                        chosen_name = CIPHER_SUITES_IANA.get(chosen_hex, {}).get('name', f"Unknown (0x{chosen_hex})")
                        session["server_hello"]["chosen_crypto_suite"] = chosen_name
                        session["server_hello"]["is_encryption_strong"] = is_cipher_strong(chosen_name)
                    except AttributeError:
                        if verbose:
                            print(f"    [WARN] Could not extract chosen cipher suite")

                # Certificate
                if not session["certificate_details"] or "error" in session["certificate_details"]:
                    cert_hex = None
                    # TLS 1.3 style
                    if hasattr(protocol_layer, 'handshake_certificate') and protocol_layer.handshake_certificate:
                        cert_hex = protocol_layer.handshake_certificate.replace(':', '')
                    # TLS 1.2 style (multiple certs)
                    elif hasattr(protocol_layer, 'handshake_certificate_item'):
                        for c in protocol_layer.handshake_certificate_item.all_fields:
                            cert_hex = c.show.replace(':', '')
                            if cert_hex:
                                break  # Take the first cert

                    if cert_hex:
                        if verbose:
                            print(f"  [DEBUG] Packet {pkt_num}: Found certificate data")
                        date = pkt.sniff_time.astimezone(timezone.utc) if hasattr(pkt, 'sniff_time') else datetime.now(timezone.utc)
                        session["certificate_details"] = analyze_certificate(cert_hex, date)

        except Exception as e:
            if verbose:
                print(f"  [ERROR] Packet {pkt.number} parsing failed: {e}")

    cap.close()

    # Post-processing: weak cipher summary
    for session in sessions.values():
        if session.get("client_hello") and session["client_hello"].get("offered_cipher_suites"):
            offered = session["client_hello"]["offered_cipher_suites"]
            weak_found = [c for c in offered if not is_cipher_strong(c)]
            session["client_hello"]["security_summary"] = {"offers_weak_ciphers": len(weak_found) > 0, "weak_ciphers_list": weak_found}

    # Prepare final report
    report = list(sessions.values())
    final_report = [s for s in report if s.get("client_hello") or s.get("server_hello") or s.get("certificate_details")]

    print("[+] Sorting report to prioritize DTLS sessions...")
    final_report.sort(key=lambda s: s.get('protocol') != 'DTLS')

    print("\n" + "="*50 + "\nANALYSIS SUMMARY\n" + "="*50)
    if not final_report:
        print(f"[!] Found {len(sessions)} potential TLS/DTLS session(s), but could not extract handshake details.")
    else:
        print(f"[+] Successfully analyzed {len(final_report)} of {len(sessions)} detected TLS/DTLS session(s).")

    with open(output_file, "w") as f:
        json.dump(final_report, f, indent=2)
    print(f"[+] Full report saved to '{output_file}'")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python webrtc.py <input.pcap> [output.json]")
        sys.exit(1)
        
    pcap_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "webrtc_analysis.json"
    verbose = True if len(sys.argv) > 3 else False

    analyze_tls_sessions(pcap_file, output_file, verbose)