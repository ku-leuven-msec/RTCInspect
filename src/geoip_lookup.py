# Save this file as geoip_lookup.py
import sys
import os
import json
import argparse
import re
import time
import ipaddress
import ipinfo
from typing import Dict, Any
from dotenv import load_dotenv
from pathlib import Path


def get_ip_details(handler, ip_address):
    """
    Looks up geolocation and ASN details for a single IP address.
    
    Args:
        handler: The ipinfo.Handler object.
        ip_address: The IP address string to look up.
        
    Returns:
        A dictionary with the IP's details, or an error message.
    """
    try:
        # The getDetails method does the API call
        details = handler.getDetails(ip_address)
        
        # Return a clean dictionary with the most important fields
        return {
            "ip": details.ip,
            "hostname": details.hostname,
            "city": details.city,
            "region": details.region,
            "country": details.country,
            "location": details.loc, # "latitude,longitude"
            "organization": details.org, # ASN information
            "timezone": details.timezone,
        }
    except Exception as e:
        # Handle cases like private IPs, invalid IPs, or API errors
        return {
            "ip": ip_address,
            "error": str(e)
        }


_STATUS_RE = re.compile(r"APIError:\s*(\d+)")

def is_public_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_global
    except ValueError:
        return False

def safe_get_ip_details(handler, ip_address: str, retries: int = 2, backoff_base: float = 0.5) -> Dict[str, Any]:
    """Robust wrapper around ipinfo lookups with error categorization and backoff."""
    if not is_public_ip(ip_address):
        return {"ip": ip_address, "error": {"type": "non_public_or_invalid", "message": "Non-public or invalid IP"}}

    attempt = 0
    while True and attempt < 10:
        try:
            d = handler.getDetails(ip_address)
            return {
                "ip": d.ip,
                "hostname": d.hostname,
                "city": d.city,
                "region": d.region,
                "country": d.country,
                "location": d.loc,
                "organization": d.org,
                "timezone": d.timezone,
            }
        except Exception as e:
            msg = str(e)
            m = _STATUS_RE.search(msg)
            status = int(m.group(1)) if m else None

            if status in (401, 403):
                return {"ip": ip_address, "error": {"type": "auth", "status": status, "message": "Invalid or unknown token"}}

            retriable = status in (429, 500, 502, 503, 504) or status is None
            if not retriable or attempt >= retries:
                return {"ip": ip_address, "error": {"type": "lookup_failed", "status": status, "message": msg}}

            time.sleep(backoff_base * (2 ** attempt))
            attempt += 1

def main():
    """Main function to run the script from the command line."""
    parser = argparse.ArgumentParser(description="Get Geolocation and ASN information for one or more IP addresses.")
    parser.add_argument("ips", nargs='+', help="The IP address(es) to look up.")
    args = parser.parse_args()
    # Ensure .env takes precedence over any pre-set environment variable
    load_dotenv(dotenv_path=Path('.') / '.env', override=True)

    ipinfo_token = os.getenv('IPINFO_TOKEN')

    if not ipinfo_token:
        print("[FATAL ERROR] IPINFO_TOKEN environment variable not set.", file=sys.stderr)
        print("Please get a free token from https://ipinfo.io/signup and set the variable.", file=sys.stderr)
        sys.exit(1)
        
    # Create the handler object once (with timeout)
    ipinfo_handler = ipinfo.getHandler(ipinfo_token, request_options={"timeout": 5})
    
    results = []
    print(f"[+] Looking up {len(args.ips)} IP address(es)...")
    for ip in args.ips:
        details = safe_get_ip_details(ipinfo_handler, ip)
        results.append(details)
        
    # Print the final results as a nicely formatted JSON array
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
