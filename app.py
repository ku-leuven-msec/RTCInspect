import ipaddress
import os
import json
from flask import Flask, render_template, abort, url_for, request, redirect, flash
from datetime import datetime
from werkzeug.utils import secure_filename # For secure file handling
import subprocess # To run your scripts
from datetime import datetime
from pathlib import Path
import sys
from collections import defaultdict
from dotenv import load_dotenv
import re


# --- CONFIGURATION ---
# Load environment variables (including Flask secret) from .env
load_dotenv(Path('.') / '.env', override=True)
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results')
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), 'templates')
PCAPS_DIR = os.path.join(APP_ROOT, 'pcaps') 
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

# Define a preferred order for reports on the page
REPORT_ORDER = [
    'signaling_analysis', 'new_signal_analysis','stun_analysis', 'turn_analysis', 
    'ice_analysis', 'webrtc_analysis', 'stream_analysis', 'certs_analysis', 'communication_map'
]

def format_report_name(value):
    acronyms = {"stun": "STUN", "turn": "TURN", "ice": "ICE", "webrtc": "Secure Channel Setup and Media Exchange","stream": "Media Stream", "certs":"Certificate", "new":"Decrypted Web " }
    words = value.replace("_", " ").split()
    formatted = []
    for w in words:
        lw = w.lower()
        if lw in acronyms:
            formatted.append(acronyms[lw])
        else:
            formatted.append(w.capitalize())
    return " ".join(formatted)



app = Flask(__name__)
# Prefer FLASK_SECRET_KEY from environment; fall back to a dev-only default
app.secret_key = os.getenv('FLASK_SECRET_KEY') or 'development-insecure-key'
app.jinja_env.add_extension('jinja2.ext.do')
app.jinja_env.filters["format_report_name"] = format_report_name

# --- HELPERS ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_severity_class(severity):
    """Returns a bootstrap class based on severity string."""
    severity = str(severity).lower()
    if severity in ['high', 'critical']: return 'danger'
    if severity == 'medium': return 'warning'
    if severity == 'low': return 'info'
    return 'secondary'

def format_timestamp(ts):
    """Formats a Unix timestamp into a readable string."""
    if not ts: return "N/A"
    try:
        return datetime.fromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return str(ts)

def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
        
def generate_summary_data(results_data, device_path, filename):
    """
    Processes all report data to create a high-level summary object.
    """
    print('arguments: ', results_data.keys(), device_path, filename)
    summary = {
        'stun_used': 'Not Found',
        'turn_used': 'Not Found',
        'ice_used': 'Not Found',
        'dtls_used': 'Not Found', 
        'tls_used': 'Not Found',  
        'signaling_method': 'Not Found',
        'TURN_credentials_found': False,
        'ICE_credentials_found': False,
        'ice_candidates': False,
        'IPs_in_candidates': False,
        'weak_ciphers': False,
        'self_signed_certs': False,
        'outdated_certs': False,
        'DTLS_certificate_reuse': False,
    }
    print("Generating summary data for capture" + device_path)
    # Check for Protocol Usage
    if stun_data := results_data.get('stun_analysis'):
        summary['stun_used'] = 'Yes' if stun_data.get('stun_transactions') else 'No'
    else:
        summary['stun_used'] = 'No'

    if turn_data := results_data.get('turn_analysis'):
        summary['turn_used'] = 'Yes' if turn_data.get('turn_transactions') else 'No'
    else:
        summary['turn_used'] = 'No'

    if ice_data := results_data.get('stun_analysis'):
        # ICE analysis has dynamic keys, so we just check if the dict is not empty
        summary['ice_used'] = 'Yes' if ice_data.get('ice_transactions') else 'No'
    else:
        summary['ice_used'] = 'No'

    print('CHECKING DTLS/TLS USAGE...')
    if webrtc_data := results_data.get('webrtc_analysis'):
        if isinstance(webrtc_data, list):
            # Check if any item in the list has the protocol "DTLS"
            summary['dtls_used'] = 'Yes' if any(c.get('protocol') == 'DTLS' for c in webrtc_data) else 'No'
            # Check if any item in the list has the protocol "TLS"
            summary['tls_used'] = 'Yes' if any(c.get('protocol') == 'TLS' for c in webrtc_data) else 'No'

          
                
        else:
            # Handle case where it might not be a list
            summary['dtls_used'] = 'No'
            summary['tls_used'] = 'No'

        
        # Check for weak ciphers in DTLS/TLS connections
        for conn in webrtc_data:
            sh = conn.get('server_hello') or {}
            if sh.get('is_encryption_strong') is False:
                summary['weak_ciphers'] = True
                break

    # DTLS certificate reuse (within current capture)
    print('CHECKING DTLS CERTIFICATE REUSE...')
    fingerprints_current = set()
    
    # Make sure we don't crash if webrtc_data is None or not a list
    if webrtc_data is None:
        webrtc_data = []
    elif not isinstance(webrtc_data, list):
        webrtc_data = [webrtc_data]

    for conn in webrtc_data:
        if conn.get('protocol') == 'DTLS':
            cd = conn.get('certificate_details') or {}
            fp = cd.get('fingerprint')
            if fp:
                if fp in fingerprints_current:
                    summary['DTLS_certificate_reuse'] = True
                fingerprints_current.add(fp)
    print(fingerprints_current)
    
    # ---------- DTLS reuse across other captures under device_path ----------
    print('CHECKING DTLS CERTIFICATE REUSE ACROSS OTHER CAPTURES...')

    curr = device_path
    results_root = None
    while curr != os.path.dirname(curr):
        if os.path.basename(curr).lower() == "results":
            results_root = curr
            break
        curr = os.path.dirname(curr)

    if results_root is None:
        raise RuntimeError(f"'results' folder not found in path: {device_path}")

    # --- Identify app-level base path ---
    rel_path = os.path.relpath(device_path, results_root)
    parts = rel_path.split(os.sep)

    # Always walk from the app-level folder, e.g. results/Zoom
    app_folder = os.path.join(results_root, parts[0])
    base_path = os.path.abspath(app_folder)
    device_path = os.path.join(device_path, filename)
    device_path = os.path.abspath(device_path)

    current_part = os.path.abspath(os.path.join(device_path, filename))

    #print("all paths", current_part, device_path, base_path, results_root)
    #print(f"Base path for other captures: {base_path} for capture {os.path.basename(device_path)}")

    capture_paths = []
    for root, dirs, files in os.walk(base_path):
        if any(f.endswith('.json') for f in files):
            root_norm = os.path.abspath(root)
            #print("testing root", root_norm, device_path)
            # skip current capture folder and descendants
            if not os.path.normcase(root_norm).startswith(os.path.normcase(device_path)):
                capture_paths.append(root_norm)
               #print("Found capture folder:", root_norm)

    summary['total_captures'] = len(capture_paths)
    #print(f"Found {len(capture_paths)} captures under {base_path}")
    #print(capture_paths)



    fingerprints_other = set()


    for capture_path in capture_paths:
        fp = os.path.join(capture_path, 'webrtc_analysis.json')
        print(fp)
        try:
            with open(fp, 'r', encoding='utf-8') as f:
                conns = json.load(f)
            if isinstance(conns, dict):
                conns = [conns]
            if not isinstance(conns, list):
                continue
            for conn in conns:
                if conn.get('protocol') == 'DTLS':
                    cd = conn.get('certificate_details') or {}
                    fpo = cd.get('fingerprint')
                    if fpo:
                        fingerprints_other.add(fpo)
        except (FileNotFoundError, json.JSONDecodeError):
            continue

    print("Fingerprints in other captures:", fingerprints_other)
    print("Fingerprints in current capture:", fingerprints_current)
    if fingerprints_current & fingerprints_other:
        print("FOUND DTLS CERTIFICATE REUSE ACROSS CAPTURES")
        print(fingerprints_current & fingerprints_other)
        summary['DTLS_certificate_reuse'] = True

    

    


    # Check Signaling and Credentials
    ip_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    if signaling_data := results_data.get('signaling_analysis'):
        if method := signaling_data.get('detection_method'):
            summary['signaling_method'] = method + " \n | No clear pattern found, fallback on heuristic"
        else: 
            summary['signaling_method'] = 'Keyword/Pattern-Based'
            for session_id, session_data in signaling_data.items():
                if isinstance(session_data, dict):
                    info = session_data.get('important_info', {})
                    if info.get('turn_password'):
                        summary['TURN_credentials_found'] = True

                    if info.get('ice-pwd'):
                        summary['ICE_credentials_found'] = True

                    if info.get('candidate'):
                        summary['ice_candidates'] = True
                        if ip_regex.search(info.get('candidate')):
                            summary['IPs_in_candidates'] = True 
                            
    # Check Certificate Issues
    if cert_data := results_data.get('certs_analysis'):
        if not isinstance(cert_data, list): cert_data = [] # Ensure it's a list
        for cert in cert_data:
            if cert.get('self_signed'):
                summary['self_signed_certs'] = True
            if not cert.get('validity_period_ok', True): # Default to OK if key is missing
                summary['outdated_certs'] = True
        if summary['self_signed_certs'] and summary['outdated_certs']:
            # No need to check further if both are already found
            pass

    print(summary)
    return summary

def get_rtc_related_ips(results_data):
    """
    Scans all report data to find IPs involved in STUN, TURN, ICE, DTLS, and Signaling.
    """
    rtc_ips = set()

    # 1. Get IPs from STUN analysis
    if stun_data := results_data.get('stun_analysis'):
        for tx_id, tx_data in stun_data.get('stun_transactions', {}).items():
            if ip := tx_data.get('client_lan_ip'): rtc_ips.add(ip)
            if ip := tx_data.get('stun_server_ip'): rtc_ips.add(ip)

    # 2. Get IPs from TURN analysis
    if turn_data := results_data.get('turn_analysis'):
        for tx_id, messages in turn_data.get('turn_transactions', {}).items():
            for msg in messages:
                if src_ip := msg.get('src', '').split(':')[0]: rtc_ips.add(src_ip)
                if dst_ip := msg.get('dst', '').split(':')[0]: rtc_ips.add(dst_ip)
    
    # 3. Get IPs from ICE analysis
    if ice_data := results_data.get('ice_analysis'):
        for _txid, val in ice_data.items():
            if isinstance(val, list):  # OLD
                for msg in val.get('messages', []):
                    if src_ip := msg.get('src', '').split(':')[0]: rtc_ips.add(src_ip)
                    if dst_ip := msg.get('dst', '').split(':')[0]: rtc_ips.add(dst_ip)
            elif isinstance(val, dict):  # NEW
                for msg in val.get('messages', []):
                    if src_ip := msg.get('src', '').split(':')[0]: rtc_ips.add(src_ip)
                    if dst_ip := msg.get('dst', '').split(':')[0]: rtc_ips.add(dst_ip)  


    # 4. Get IPs from DTLS/TLS analysis
    if webrtc_data := results_data.get('webrtc_analysis'):
        for c in webrtc_data:
            if c.get('protocol') == 'DTLS':
                rtc_ips.add(c.get('client_endpoint').split(':')[0])  # Only add IP part
                rtc_ips.add(c.get('server_endpoint').split(':')[0])  # Only add IP part
        
    # 5. Get IPs from Signaling analysis
    if signaling_data := results_data.get('signaling_analysis'):
        for session_id, session_data in signaling_data.items():
            if isinstance(session_data, dict):
                print(f"Processing session {session_id} for RTC IPs...")
                rtc_ips.add(session_data['summary'].get('servers_contacted'))
                rtc_ips.add(session_data['important_info'].get('turn_addr'))

                rtc_ips.add(session_id.split('-')[0].split(':')[1])  # Add client IP
                rtc_ips.add(session_id.split('-')[1].split(':')[0])  # Add server IP

    print(f"Found {len(rtc_ips)} RTC-related IPs: {rtc_ips}")

    return rtc_ips

# Register helpers for use in templates
app.jinja_env.globals.update(
    get_severity_class=get_severity_class,
    format_timestamp=format_timestamp
)

def generate_folder_summary(device_path):
    """
    Analyzes all captures within a device folder to generate an aggregated summary.
    """
    summary = {
        'total_captures': 0,
        'signaling_creds': [],
        'turn_usernames': set(), 
        'self_signed_cert_count': 0,
        'outdated_cert_count': 0,
        'reused_certs': []
    }
    all_fingerprints = defaultdict(list) # key: fingerprint, value: [capture_id1, capture_id2]

    # Find all the individual capture directories inside the device folder
    capture_paths = []
    for root, dirs, files in os.walk(device_path):
        if any(f.endswith('.json') for f in files):
            # This is a capture directory, store its full path
            capture_paths.append(root)
    
    summary['total_captures'] = len(capture_paths)
    if not capture_paths:
        return summary

    #print(capture_paths)
    for capture_path in capture_paths:
        # Get a user-friendly name for the capture (relative to the device folder)
        capture_id = os.path.relpath(capture_path, device_path).replace('\\', '/')
        #print(capture_id)
        # --- Analyze Signaling Credentials ---        
        try:
            signaling_file_path = os.path.join(capture_path, 'signaling_analysis.json')
            if os.path.isfile(signaling_file_path):
                with open(signaling_file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if data.get('detection_method') != 'Heuristic-Based':
                        for session_id, session_data in data.items():
                            if isinstance(session_data, dict):
                                info = session_data.get('important_info', {})
                                if cred := info.get('turn_password'):
                                    summary['signaling_creds'].append({'source': capture_id, 'type': 'TURN Password', 'value': cred})
                                if cred := info.get('ice-pwd'):
                                    summary['signaling_creds'].append({'source': capture_id, 'type': 'ICE Password', 'value': cred})
        except (FileNotFoundError, json.JSONDecodeError):
            continue


        # --- Analyze TURN Usernames ---
        print(f"Analyzing TURN usernames in {capture_id}...")
        try:
            print(f"  [DEBUG] Checking TURN usernames in {capture_id}...")
            with open(os.path.join(capture_path, 'turn_analysis.json'), 'r', encoding='utf-8') as f:
                data = json.load(f)
                transactions = data.get('turn_transactions', {})
                for tx_id, messages in transactions.items():
                    for msg in messages:
                        if username := msg.get('credentials', {}).get('username'):
                            summary['turn_usernames'].add(username)
        except (FileNotFoundError, json.JSONDecodeError):
            continue

        # --- Analyze Certificate Information ---
        certs_to_process = []
        # Source 1: cert_analysis.json (Context is 'TLS' as a safe default)
        try:
            with open(os.path.join(capture_path, 'cert_analysis.json'), 'r', encoding='utf-8') as f:
                certs = json.load(f)
                if isinstance(certs, list):
                    for cert in certs:
                        certs_to_process.append({'cert': cert, 'context': 'TLS (Generic)'})
        except (FileNotFoundError, json.JSONDecodeError):
            pass

        # Source 2: webrtc_analysis.json (Context is the connection protocol)
        try:
            with open(os.path.join(capture_path, 'webrtc_analysis.json'), 'r', encoding='utf-8') as f:
                conns = json.load(f)
                if isinstance(conns, list):
                    for conn in conns:
                        if cert_details := conn.get('certificate_details'):
                            # Here we capture the context!
                            context = conn.get('protocol', 'Unknown Protocol')
                            certs_to_process.append({'cert': cert_details, 'context': context})
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        
        for item in certs_to_process:
            cert = item.get('cert', {})
            context = item.get('context', 'N/A')
            if not isinstance(cert, dict): continue
            
            if fingerprint := cert.get('fingerprint'):
                # Store the context along with the capture ID
                all_fingerprints[fingerprint].append({'capture': capture_id, 'context': context})

            if cert.get('self_signed'):
                summary['self_signed_cert_count'] += 1
            if not cert.get('validity_period_ok', True):
                summary['outdated_cert_count'] += 1

    # Post-process fingerprints for reuse
    summary['reused_certs'] = []
    for fp, captures_with_context in all_fingerprints.items():
        # Determine if this fingerprint appears in more than one distinct capture
        unique_capture_ids = {item['capture'] for item in captures_with_context}
        if len(unique_capture_ids) > 1:
            # Deduplicate to one entry per capture (keep the first context seen)
            seen_captures = set()
            dedup_locations = []
            for item in captures_with_context:
                cap = item.get('capture')
                if cap in seen_captures:
                    continue
                seen_captures.add(cap)
                dedup_locations.append({'capture': cap, 'context': item.get('context')})

            summary['reused_certs'].append({
                'fingerprint': fp,
                'locations': dedup_locations
            })
    summary['turn_usernames'] = sorted(list(summary['turn_usernames']))


    return summary


# Recursive scanner
def find_capture_dirs(start_path):
    """Recursively finds all directories that contain at least one .json file."""
    capture_paths = []
    for root, dirs, files in os.walk(start_path):
        if any(f.endswith('.json') for f in files):
            # This is a valid capture directory.
            # We get its path relative to the starting directory.
            relative_path = os.path.relpath(root, start_path)
            if relative_path != '.':
                # The replace() is for Windows/Linux path compatibility in URLs
                capture_paths.append(relative_path.replace('\\', '/'))
    return sorted(capture_paths, reverse=True)


# --- ROUTES ---
@app.route('/', methods=['GET', 'POST'])
def index():
    """Homepage: Finds ALL captures and groups them by their top-level device folder."""
    """Upload logic"""
    if request.method == 'POST':
        if 'pcap_file' not in request.files:
            flash('No file part in the request!', 'danger')
            return redirect(request.url)
        
        file = request.files['pcap_file']
        folder_name = request.form.get('folder_name')
        analysis_type = request.form.get('analysis_type')

        if not folder_name:
            flash('Folder name is required!', 'danger')
            return redirect(request.url)
        
        if file.filename == '':
            flash('No selected file!', 'danger')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            # Sanitize inputs for security
            sane_folder_name = secure_filename(folder_name)
            file_name_input = request.form.get("file_name")
            sane_filename = secure_filename(file_name_input) if file_name_input else secure_filename(file.filename)

            print("[DEBUG] Using filename:", sane_filename + " in folder:", sane_folder_name)
            # Derive an output directory under results/<folder>/<file_stem>
            from pathlib import Path as _Path
            target_results_dir = os.path.join(RESULTS_DIR, sane_folder_name, _Path(sane_filename).stem)
            print("[DEBUG] Results will go to:", target_results_dir)
            # Create target directories for uploaded pcap; results dir is created by analysis script
            target_pcap_dir = os.path.join(PCAPS_DIR, sane_folder_name)
            os.makedirs(target_pcap_dir, exist_ok=True)
            
            file_path = os.path.join(target_pcap_dir, sane_filename)
            file.save(file_path)

            # Determine which script to run
            script_to_run = "main.py" if analysis_type == 'device' else "main_webapp.py"
            script_to_run_path = os.path.join(APP_ROOT, script_to_run)

            flash(f"File uploaded successfully. Starting analysis with '{script_to_run_path}'...", 'info')

            # Run the analysis script as a subprocess
            try:
                python_executable = sys.executable
                # Example command: python analyze_device.py /path/to/pcap /path/to/results
                command = [python_executable, script_to_run_path, file_path, "-o", target_results_dir]
                print(f"Executing command: {' '.join(command)}") # For debugging
                
                # Using subprocess.run. For very long tasks, consider Celery or RQ.
                result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=300) # 5-minute timeout
                
                print("Script STDOUT:", result.stdout)
                print("Script STDERR:", result.stderr)

                flash(f"Analysis for '{sane_folder_name}' completed successfully!", 'success')

            except FileNotFoundError:
                 flash(f"Error: The script '{script_to_run}' was not found.", 'danger')
            except subprocess.CalledProcessError as e:
                flash(f"Analysis script failed for '{sane_folder_name}'. Error: {e.stderr}", 'danger')
            except subprocess.TimeoutExpired:
                flash(f"Analysis for '{sane_folder_name}' timed out after 5 minutes.", 'danger')

            return redirect(url_for('index'))
        else:
            flash('Invalid file type. Allowed types are: .pcap, .pcapng', 'danger')
            return redirect(request.url)

    """Get request logic"""
    grouped_captures = {}
    try:
        # 1. Get a single, flat list of ALL valid capture paths.
        # e.g., ['eufy/outdoor/cap1', 'digitus']
        all_capture_paths = find_capture_dirs(RESULTS_DIR)

        # 2. Group these paths by their top-level directory.
        for path in all_capture_paths:
            # The group key is the first part of the path (e.g., 'eufy' or 'digitus')
            group_key = path.split('/')[0]
            
            # Initialize the list for this group if it doesn't exist
            if group_key not in grouped_captures:
                grouped_captures[group_key] = []
            
            # Add the full path to the group's list
            grouped_captures[group_key].append(path)

    except FileNotFoundError:
        print(f"ERROR: The results directory was not found at {os.path.abspath(RESULTS_DIR)}")

    # Pass the dictionary to the template, sorted by device name.
    return render_template('index.html', grouped_captures=dict(sorted(grouped_captures.items())))


# This new route replaces BOTH device_captures and capture_details
@app.route('/report/<path:capture_path>')
def view_report(capture_path):
    """Displays the detailed results for any given capture path."""
    full_path = os.path.join(RESULTS_DIR, capture_path)
    
    if not os.path.isdir(full_path):
        abort(404, description="Capture directory not found at the specified path.")

    results_data = {}
    for filename in os.listdir(full_path):
        if filename.endswith('.json'):
            file_path = os.path.join(full_path, filename)
            print(f"Loading report file: {file_path}")
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    report_name = os.path.splitext(filename)[0]
                    results_data[report_name] = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                results_data[report_name] = {"error": f"Could not load file: {e}"}

    # Sort the reports according to our preferred order
    def sort_key(item):
        try:
            return REPORT_ORDER.index(item[0])
        except ValueError:
            return len(REPORT_ORDER)
    sorted_results = dict(sorted(results_data.items(), key=sort_key))
    print(f"Sorted results: {sorted_results.keys()}")
    print(f"Results data: {results_data.keys()}")

    print('full_path', full_path)
    # change \ to / in fullpath for Windows compatibility
    filename = os.path.basename(full_path)
    summary_data = generate_summary_data(results_data, os.path.dirname(full_path), filename)
    map_data = results_data.get('connection_analysis') or results_data.get('communication_map')

    rtc_ips = get_rtc_related_ips(results_data)
    rtc_flow_data = []
    if map_data and rtc_ips:
        for conv in map_data:
            if conv.get('src_ip') in rtc_ips and conv.get('dst_ip') in rtc_ips:
                rtc_flow_data.append(conv)


    # Create breadcrumbs for navigation
    path_parts = capture_path.split('/')
    breadcrumbs = []
    for i, part in enumerate(path_parts):
        # This isn't a real link, just text, as intermediate folders have no page
        breadcrumbs.append({'name': part})
    print(f"Breadcrumbs: {breadcrumbs}" + f" for path: {capture_path}" + f" with parts: {path_parts}") 
    return render_template('capture.html', 
                           capture_path=capture_path, 
                           data=sorted_results,
                           breadcrumbs=breadcrumbs,
                           summary=summary_data,
                           rtc_flow_data=rtc_flow_data
                           )

@app.route('/summary/<device_name>')
def folder_summary(device_name):
    device_path = os.path.join(RESULTS_DIR, device_name)
    if not os.path.isdir(device_path):
        abort(404, description="Device folder not found.")
    
    summary_data = generate_folder_summary(device_path)
    
    return render_template('folder_summary.html', device_name=device_name, summary=summary_data)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
