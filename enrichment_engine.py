import json
import requests
import pandas as pd
import time
import os
from datetime import datetime

# --- CONFIGURATION ---
# Replace with YOUR actual API Key from AbuseIPDB
API_KEY = 'b91c911091f53574a1c1f74353ef11c28f4c338ce7374b5fae2a603c2f0109e3c70ccf32029f056e' 

# Path to T-Pot Cowrie logs (Standard T-Pot location)
LOG_FILE_PATH = '/home/kali/Desktop/data/cowrie/log/cowrie.json' 
OUTPUT_FILE = 'enriched_threat_intel.csv'

# --- FUNCTIONS ---

def load_logs(filepath, max_lines=500):
    """Reads the last N lines of the log file to get recent attacks."""
    data = []
    print(f"[*] Reading logs from {filepath}...")
    
    if not os.path.exists(filepath):
        print(f"[!] Error: Log file not found at {filepath}")
        return []

    try:
        with open(filepath, 'r') as f:
            # Read line by line
            lines = f.readlines()
            # Take the last 'max_lines' to analyze recent activity
            for line in lines[-max_lines:]:
                try:
                    log_entry = json.loads(line)
                    # We only care about login attempts or command execution
                    if log_entry.get('eventid') == 'cowrie.login.failed':
                        data.append({
                            'timestamp': log_entry.get('timestamp'),
                            'src_ip': log_entry.get('src_ip'),
                            'username': log_entry.get('username'),
                            'password': log_entry.get('password')
                        })
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        
    print(f"[*] Found {len(data)} potential attack events.")
    return data

def check_ip_reputation(ip):
    """Queries AbuseIPDB for IP reputation."""
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }

    try:
        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
        if response.status_code == 200:
            decoded = response.json()
            return decoded['data']
        elif response.status_code == 429:
            print("[!] API Rate Limit Exceeded. Waiting...")
            time.sleep(60) # Wait if we hit a limit
            return None
        else:
            print(f"[!] API Error: {response.status_code}")
            return None
    except Exception as e:
        print(f"[!] Connection Error: {e}")
        return None

# --- MAIN EXECUTION ---

def main():
    print("--- STARTING THREAT ENRICHMENT ENGINE ---")
    
    # 1. Load Raw Data
    raw_attacks = load_logs(LOG_FILE_PATH)
    if not raw_attacks:
        print("[!] No logs found. Exiting.")
        return

    # Convert to DataFrame for easier handling
    df = pd.DataFrame(raw_attacks)
    
    # Get unique IPs to avoid querying the same IP twice (saves API credits)
    unique_ips = df['src_ip'].unique()
    print(f"[*] Identified {len(unique_ips)} unique attacker IPs.")

    enriched_data = []

    # 2. Enrich Data (Loop through IPs)
    print("[*] Querying AbuseIPDB (This may take a moment)...")
    
    for i, ip in enumerate(unique_ips[:15]): # Limit to 15 IPs for testing
        print(f"    [{i+1}/{min(len(unique_ips), 15)}] Checking IP: {ip}")
        
        reputation = check_ip_reputation(ip)
        
        if reputation:
            enriched_data.append({
                'IP': ip,
                'Country': reputation.get('countryCode'),
                'ISP': reputation.get('isp'),
                'Confidence_Score': reputation.get('abuseConfidenceScore'),
                'Total_Reports': reputation.get('totalReports'),
                'Last_Reported': reputation.get('lastReportedAt')
            })
        
        # Sleep briefly to be nice to the API
        time.sleep(1)

    # 3. Save Results
    if enriched_data:
        enrich_df = pd.DataFrame(enriched_data)
        enrich_df.to_csv(OUTPUT_FILE, index=False)
        print(f"\n[SUCCESS] Enriched Intelligence saved to: {OUTPUT_FILE}")
        print(enrich_df.head()) # Show preview
    else:
        print("\n[!] No data was enriched.")

if __name__ == "__main__":
    main()
