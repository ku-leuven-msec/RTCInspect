# RTCInspect
## WebRTC Security Analysis

**RTCInspect** is a comprehensive framework for analyzing the security of WebRTC communications from network captures (**PCAP files**) and presenting the findings in an interactive, web-based dashboard.  

It is designed for **security researchers, pentesters, and developers** to quickly assess the security posture of IoT devices and web applications that rely on Real-Time Communication protocols.

![Dashboard](./docs/Dashboard.png)

---

## 🚀 Setup & Installation

### Prerequisites
- Python **3.8+**
- Pip package manager
- tshark
```bash
sudo apt install tshark
```
- GeoIP lookups (optional, set ipinfo token in .env)


### Installation
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

### Step 1: Capture Traffic
- **Normal operation: Unencrypted or (D)TLS-encrypted  traffic:**  
  Capture a standard PCAP containing RTC traffic.

- **Encrypted traffic: QUIC / HTTP/2 / HTTP/3 / WebSocket traffic:**  
  1. **Generate SSLKEYLOGFILE**  
     Set an environment variable before launching your browser to save TLS keys.  
  2. **Extract Keys in wireshark**
    File > Export TLS Sessions Keys
  3. **Run with Tshark**
```bash
tshark -r capture.pcapng -o tls.keylog_file:key.txt -w decrypted.pcapng
```


### Step 2: Run the Application
```bash
python app.py
```

## Features

- **Web-Based Dashboard**  
  Flask-powered UI to browse, view, and manage analysis results.

- **Upload & Scan Pipeline**  
  Upload `.pcap` or `.pcapng` files directly through the web interface.

- **Hierarchical Report Browser**  
  Results grouped by device/application with collapsible navigation.

- **Aggregated Folder Summaries**  
  High-level overview across multiple captures to detect systemic issues.

- **Comprehensive Protocol Analysis**  
  Supports STUN, TURN, ICE, TLS, and DTLS traffic.

- **Intelligent Signaling Detection**  
  - **Keyword/Pattern-based:** Detects SIP, XMPP, SDP, and common WebRTC markers.  
  - **Heuristic fallback:** Identifies obfuscated/proprietary signaling via behavioral patterns.

- **Decrypted Traffic Analysis**  
  Specialized module for HTTP/2, HTTP/3, and WebSocket after SSLKEYLOGFILE-based decryption.

- **Cryptographic Assessment**  
  - Certificate trust (self-signed, expired, issuer).  
  - Cipher suite negotiation & strength.  
  - Presence of critical extensions.  

- **Media Stream Identification**  
  Detects major data streams and evaluates encryption via entropy analysis.

- **Universal Certificate Audit**  
  Extracts and analyzes all unique TLS/DTLS certificates.

- **Interactive Network Graph** *(vis.js powered)*  
  - Filter by protocol, data volume, or LAN abstraction.  
  - Aggregated edges with bandwidth-weighted visualization.  
  - Hover tooltips for IPs, protocols, and security notes.  

---

## 📖 License
*MIT*
