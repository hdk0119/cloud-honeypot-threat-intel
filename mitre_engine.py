import json
import requests
import pandas as pd
import time
import os

# --- CONFIGURATION ---
API_KEY = 'b91c911091f53574a1c1f74353ef11c28f4c338ce7374b5fae2a603c2f0109e3c70ccf32029f056e'  # <--- PASTE YOUR KEY HERE
OUTPUT_FILE = 'unified_threat_feed.csv'

# Log Paths for T-Pot Honeypots
LOG_SOURCES = {
    "Cowrie": "/home/kali/Desktop/data/cowrie/log/cowrie.json",
    "Dionaea": "/home/kali/Desktop/data/dionaea/log/dionaea.json",
    "Suricata": "/home/kali/Desktop/data/suricata/log/eve.json"
}

# --- UNIFIED MITRE ATT&CK MAPPING ---
# Expanded dictionary to cover SSH, SMB, HTTP, and Network Exploits
MITRE_MAPPING = {
    # Cowrie (SSH/Telnet)
    "cowrie.login.failed": {"ID": "T1110", "Technique": "Brute Force"},
    "cowrie.session.connect": {"ID": "T1046", "Technique": "Network Service Discovery"},
    "wget": {"ID": "T1105", "Technique": "Ingress Tool Transfer"},
    "curl": {"ID": "T1105", "Technique": "Ingress Tool Transfer"},
    
    # Dionaea (SMB/FTP/HTTP)
    "smbd": {"ID": "T1210", "Technique": "Exploitation of Remote Services"},
    "httpd": {"ID": "T1190", "Technique": "Exploit Public-Facing Application"},
    "ftpd": {"ID": "T1021", "Technique": "Remote Services"},
    "mqtt": {"ID": "T1046", "Technique": "Network Service Discovery"},
    
    # Suricata (Network Alerts)
    "alert": {"ID": "T1595", "Technique": "Active Scanning"},
    "Exploit": {"ID": "T1210", "Technique": "Exploitation of Remote Services"},
    "Malware": {"ID": "T1204", "Technique": "User Execution"}
}

# --- FUNCTIONS ---

def get_mitre_tag(event_type, detailed_info=""):
    """Maps varied event types to MITRE Tags."""
    # 1. Check detailed info (Command or Alert Signature)
    if detailed_info:
        for keyword, mapping in MITRE_MAPPING.items():
            if keyword.lower() in str(detailed_info).lower():
                return mapping['ID'], mapping['Technique']
    
    # 2. Check Event Type
    for keyword, mapping in MITRE_MAPPING.items():
        if keyword in event_type:
            return mapping['ID'], mapping['Technique']
            
    return "T1071", "Standard Application Layer Protocol" # Fallback

def parse_line(line, honeypot_name):
    """Normalizes logs from different honeypots into a standard format."""
    try:
        log = json.loads(line)
        data = {
            'timestamp': log.get('timestamp', 'N/A'),
            'src_ip': None,
            'event': 'unknown',
            'details': None
        }

        # --- COWRIE PARSING ---
        if honeypot_name == "Cowrie":
            data['src_ip'] = log.get('src_ip')
            data['event'] = log.get('eventid')
            data['details'] = log.get('input') # Commands

        # --- DIONAEA PARSING ---
        elif honeypot_name == "Dionaea":
            # Dionaea often uses 'remote_host' or 'src_ip'
            data['src_ip'] = log.get('src_ip') or log.get('remote_host')
            data['event'] = log.get('connection_type') or log.get('protocol')
            data['details'] = log.get('connection_transport')

        # --- SURICATA PARSING ---
        elif honeypot_name == "Suricata":
            data['src_ip'] = log.get('src_ip')
            data['event'] = log.get('event_type')
            if data['event'] == 'alert':
                # Extract the specific alert signature
                data['details'] = log.get('alert', {}).get('signature')

        return data
    except:
        return None

def load_all_logs(max_lines=300):
    """Iterates through all configured log sources."""
    unified_data = []
    
    for name, path in LOG_SOURCES.items():
        print(f"[*] Reading {name} logs from {path}...")
        
        if not os.path.exists(path):
            print(f"    [!] File not found. Skipping {name}.")
            continue
            
        try:
            with open(path, 'r') as f:
                lines = f.readlines()[-max_lines:] # Read last N lines
                for line in lines:
                    parsed = parse_line(line, name)
                    
                    if parsed and parsed['src_ip']:
                        # Filter out internal IPs/Noise
                        if parsed['src_ip'] == "127.0.0.1": continue 
                        
                        # Apply MITRE Mapping
                        t_id, tech = get_mitre_tag(str(parsed['event']), parsed['details'])
                        
                        unified_data.append({
                            'Timestamp': parsed['timestamp'],
                            'Honeypot': name,
                            'Src_IP': parsed['src_ip'],
                            'Event': parsed['event'],
                            'Details': parsed['details'],
                            'MITRE_ID': t_id,
                            'MITRE_Technique': tech
                        })
        except Exception as e:
            print(f"    [!] Error reading {name}: {e}")

    print(f"[*] Total events captured across all honeypots: {len(unified_data)}")
    return unified_data

def check_ip_reputation(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Accept': 'application/json', 'Key': API_KEY}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    try:
        r = requests.get(url, headers=headers, params=params)
        if r.status_code == 200: return r.json()['data']
        elif r.status_code == 429: time.sleep(5); return None
    except: return None

# --- MAIN EXECUTION ---
def main():
    print("--- UNIFIED THREAT INTELLIGENCE ENGINE (v2.0) ---")
    
    # 1. Load & Normalize Data
    events = load_all_logs()
    if not events: return

    # 2. Enrich Data (Limit API calls for demo)
    df = pd.DataFrame(events)
    unique_ips = df['Src_IP'].unique()[:10] # Process top 10 unique IPs
    
    ip_intel = {}
    print(f"[*] Enriching {len(unique_ips)} unique IPs via AbuseIPDB...")
    
    for ip in unique_ips:
        print(f"    checking: {ip}")
        intel = check_ip_reputation(ip)
        if intel:
            ip_intel[ip] = intel
        time.sleep(1) 

    # 3. Merge Intelligence
    final_results = []
    for event in events:
        if event['Src_IP'] in ip_intel:
            intel = ip_intel[event['Src_IP']]
            event['Country'] = intel.get('countryCode')
            event['Confidence'] = intel.get('abuseConfidenceScore')
            final_results.append(event)
    
    # 4. Save
    if final_results:
        final_df = pd.DataFrame(final_results)
        # Reorder columns for readability
        cols = ['Timestamp', 'Honeypot', 'Src_IP', 'Country', 'Confidence', 'Event', 'Details', 'MITRE_ID', 'MITRE_Technique']
        final_df = final_df[cols]
        final_df.to_csv(OUTPUT_FILE, index=False)
        print(f"\n[SUCCESS] Master Feed generated: {OUTPUT_FILE}")
        print(final_df.head())
    else:
        print("[!] No enriched data to save.")

if __name__ == "__main__":
    main()
