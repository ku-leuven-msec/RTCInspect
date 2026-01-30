# ciphers.py
# A centralized configuration file for TLS/DTLS cipher suite information and security analysis.
# Data is sourced from the official IANA TLS Parameters registry.

# A comprehensive mapping of IANA-registered cipher suite hex codes.
# Format: 'hex_code': {'name': 'FULL_NAME', 'recommended': True/False, 'dtls_ok': True/False}
CIPHER_SUITES_IANA = {
    # TLS 1.3 Cipher Suites
    '1301': {'name': 'TLS_AES_128_GCM_SHA256', 'recommended': True, 'dtls_ok': True},
    '1302': {'name': 'TLS_AES_256_GCM_SHA384', 'recommended': True, 'dtls_ok': True},
    '1303': {'name': 'TLS_CHACHA20_POLY1305_SHA256', 'recommended': True, 'dtls_ok': True},
    '1304': {'name': 'TLS_AES_128_CCM_SHA256', 'recommended': True, 'dtls_ok': True},
    '1305': {'name': 'TLS_AES_128_CCM_8_SHA256', 'recommended': False, 'dtls_ok': True},

    # Modern & Strong TLS 1.2 Cipher Suites (Perfect Forward Secrecy)
    'c02b': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'recommended': True, 'dtls_ok': True},
    'c02c': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'recommended': True, 'dtls_ok': True},
    'cca9': {'name': 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'recommended': True, 'dtls_ok': True},
    'c02f': {'name': 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'recommended': True, 'dtls_ok': True},
    'c030': {'name': 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'recommended': True, 'dtls_ok': True},
    'cca8': {'name': 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'recommended': True, 'dtls_ok': True},
    '009e': {'name': 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'recommended': True, 'dtls_ok': True},
    '009f': {'name': 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384', 'recommended': True, 'dtls_ok': True},

    # Other common suites found in your capture
    'c009': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    'c00a': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    'c013': {'name': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    'c014': {'name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    'c023': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'recommended': False, 'dtls_ok': True},
    'c024': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384', 'recommended': False, 'dtls_ok': True},
    'c027': {'name': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 'recommended': False, 'dtls_ok': True},
    'c028': {'name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'recommended': False, 'dtls_ok': True},
    '0067': {'name': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256', 'recommended': False, 'dtls_ok': True},
    '006b': {'name': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', 'recommended': False, 'dtls_ok': True},
    
    # Older/Weaker TLS 1.2 Cipher Suites (No Perfect Forward Secrecy)
    '009c': {'name': 'TLS_RSA_WITH_AES_128_GCM_SHA256', 'recommended': False, 'dtls_ok': True},
    '009d': {'name': 'TLS_RSA_WITH_AES_256_GCM_SHA384', 'recommended': False, 'dtls_ok': True},
    '002f': {'name': 'TLS_RSA_WITH_AES_128_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    '0035': {'name': 'TLS_RSA_WITH_AES_256_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    '003c': {'name': 'TLS_RSA_WITH_AES_128_CBC_SHA256', 'recommended': False, 'dtls_ok': True},
    '003d': {'name': 'TLS_RSA_WITH_AES_256_CBC_SHA256', 'recommended': False, 'dtls_ok': True},

    # Legacy and Insecure Ciphers
    '000a': {'name': 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    'c008': {'name': 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    'c012': {'name': 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    '0016': {'name': 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    'c004': {'name': 'TLS_ECDH_anon_WITH_RC4_128_MD5', 'recommended': False, 'dtls_ok': True},
    '0005': {'name': 'TLS_RSA_WITH_RC4_128_SHA', 'recommended': False, 'dtls_ok': False},
    
    # Special Purpose / Unassigned from your previous list
    '00ff': {'name': 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV', 'recommended': False, 'dtls_ok': True},
    
    # Adding the rest of the found 'unknowns' from IANA list
    '00a3': {'name': 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384', 'recommended': False, 'dtls_ok': True},
    '006a': {'name': 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256', 'recommended': False, 'dtls_ok': True},
    '0038': {'name': 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    '0088': {'name': 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    '0087': {'name': 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    'c032': {'name': 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384', 'recommended': False, 'dtls_ok': True},
    'c02e': {'name': 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384', 'recommended': False, 'dtls_ok': True},
    'c02a': {'name': 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384', 'recommended': False, 'dtls_ok': True},
    'c026': {'name': 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384', 'recommended': False, 'dtls_ok': True},
    'c00f': {'name': 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    'c005': {'name': 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    '0084': {'name': 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    '00a2': {'name': 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256', 'recommended': False, 'dtls_ok': True},
    '0040': {'name': 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256', 'recommended': False, 'dtls_ok': True},
    '0032': {'name': 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    '0045': {'name': 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    '0044': {'name': 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    'c031': {'name': 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256', 'recommended': False, 'dtls_ok': True},
    'c02d': {'name': 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256', 'recommended': False, 'dtls_ok': True},
    'c029': {'name': 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256', 'recommended': False, 'dtls_ok': True},
    'c025': {'name': 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256', 'recommended': False, 'dtls_ok': True},
    'c00e': {'name': 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    '0041': {'name': 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    'c017': {'name': 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    'c00d': {'name': 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA', 'recommended': False, 'dtls_ok': True},
    'c003': {'name': 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA', 'recommended': False, 'dtls_ok': True},
}

# A set of IANA-recommended cipher suites for easy checking.
RECOMMENDED_CIPHERS = {
    suite['name'] for suite in CIPHER_SUITES_IANA.values() if suite.get('recommended', False)
}

# --- Security Analysis Configuration ---

# Ciphers starting with these prefixes are fundamentally flawed for modern use.
WEAK_CIPHER_PREFIXES = [
    'TLS_RSA_WITH_',         # No Perfect Forward Secrecy (PFS)
    'TLS_DH_DSS_WITH_',      # No PFS and uses outdated DSS
    'TLS_DH_RSA_WITH_',      # No PFS
    'TLS_DH_anon_WITH_',     # No authentication (Anonymous)
    'TLS_ECDH_anon_WITH_',   # No authentication (Anonymous)
    'TLS_KRB5_WITH_',        # Kerberos-based, complex and often unnecessary
]

# Any cipher containing these substrings is considered weak or outdated.
WEAK_SUBSTRINGS = [
    '_NULL_',                # No encryption
    '_RC4_',                 # Broken stream cipher
    '_DES_',                 # Broken block cipher (use 3DES for Triple DES)
    '_3DES_',                # Slow and weak by modern standards
    '_MD5',                  # Broken hash function
    '_CBC_',                 # Vulnerable to padding oracle attacks (use GCM/CHACHA20 instead)
    '_EXPORT_',              # Intentionally weakened for export
    'SEED',                  # Less common, Korean-developed cipher
    'IDEA',                  # Old and rarely used
    'CAMELLIA',              # Not inherently weak, but less vetted and common than AES
]