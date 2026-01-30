import json
import sys
import argparse
from datetime import datetime, timezone
import pyshark
from tqdm import tqdm
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import ipaddress
import socket


# --- Helper Function (The same robust one from our WebRTC script) ---

def analyze_certificate(cert_hex_string, date):
    """
    Parses a certificate (provided as a hex string) and extracts its security properties.
    """
    try:
        cert_data = bytes.fromhex(cert_hex_string)
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
        is_self_signed = cert.issuer == cert.subject
        is_valid_period = cert.not_valid_before_utc <= date <= cert.not_valid_after_utc
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [str(name) for name in san_ext.value]
        except x509.ExtensionNotFound:
            sans = []
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
            "signature_algorithm": cert.signature_algorithm_oid._name, 
            "public_key_algorithm": cert.public_key().__class__.__name__,
            "fingerprint": formatted_fp
            }
    except Exception as e:
        return {"error": f"Failed to parse certificate: {e}"}


def get_ip_details(ip_address):
    """Analyzes an IP address to determine its type and resolves its hostname if public."""
    details = {"ip": ip_address}
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.is_private:
            details["type"] = "Private"
            details["hostname"] = "N/A (Private IP)"
        else:
            details["type"] = "Public"
            try:
                hostname, _, _ = socket.gethostbyaddr(ip_address)
                details["hostname"] = hostname
            except socket.herror:
                details["hostname"] = "Resolution Failed"
    except ValueError:
        details["type"] = "Invalid"; details["hostname"] = "N/A"
    return details


# --- Main Logic ---

def extract_and_analyze_certs(pcap_file, output_file):
    """
    Finds and analyzes all unique TLS/DTLS certificates in a PCAP using pyshark.
    """
    print("[+] Using pyshark to search for certificates in TLS/DTLS handshakes...")
    
    unique_certs_hex = set()
    analyzed_certs = []

    try:
        # Use a display filter to find any packet that might contain a certificate
        cap = pyshark.FileCapture(pcap_file, display_filter="tls.handshake or dtls.handshake")
        cap.load_packets()
        total_packets = len(cap)
    except Exception as e:
        print(f"[ERROR] Could not read PCAP file with pyshark: {e}")
        return

    for pkt in tqdm(cap, total=total_packets, desc="Processing packets"):
        try:
            cert_hex = None
            protocol_layer = None

            # The field name is the same for both TLS and DTLS in tshark
            if hasattr(pkt, 'tls') and hasattr(pkt.tls, 'handshake_type'):
                protocol_layer = pkt.tls
            elif hasattr(pkt, 'dtls') and hasattr(pkt.dtls, 'handshake_type'):
                protocol_layer = pkt.dtls


            if hasattr(protocol_layer, 'handshake_certificate') and protocol_layer.handshake_certificate:
                cert_hex = protocol_layer.handshake_certificate.replace(':', '')
                if cert_hex and cert_hex not in unique_certs_hex:
                    unique_certs_hex.add(cert_hex)
                    date = pkt.sniff_time.astimezone(timezone.utc)
                    analysis = analyze_certificate(cert_hex, date)
                    analysis["found_in_packet_number"] = pkt.number
                    analysis["found_in_packet_summary"] = pkt.highest_layer + " Packet"
                    analyzed_certs.append(analysis)

            elif hasattr(protocol_layer, 'handshake_certificate_item'):
                for c in protocol_layer.handshake_certificate_item.all_fields:
                    cert_hex = c.show.replace(':', '')
                    if cert_hex and cert_hex not in unique_certs_hex:
                        unique_certs_hex.add(cert_hex)
                        date = pkt.sniff_time.astimezone(timezone.utc)
                        analysis = analyze_certificate(cert_hex, date)
                        analysis["found_in_packet_number"] = pkt.number
                        analysis["found_in_packet_summary"] = pkt.highest_layer + " Packet"
                        analyzed_certs.append(analysis)

                            
        except (AttributeError, KeyError):
            # This packet matched the filter but was likely a fragment
            # that pyshark couldn't fully reassemble. We safely ignore it.
            continue
    
    cap.close()

    with open(output_file, "w") as f:
        json.dump(analyzed_certs, f, indent=2)

    print("\n" + "="*50 + "\nANALYSIS COMPLETE\n" + "="*50)
    print(f"[+] Found and analyzed {len(analyzed_certs)} unique certificate(s).")
    print(f"[+] Full report saved to '{output_file}'")

# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extracts and analyzes all unique TLS/DTLS certificates from a PCAP file.")
    parser.add_argument("pcap_file", help="Input PCAP or PCAPNG file")
    parser.add_argument("output_file", nargs='?', default="certificate_analysis.json", help="Output JSON file")
    args = parser.parse_args()
    
    extract_and_analyze_certs(args.pcap_file, args.output_file)