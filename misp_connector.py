import pandas as pd
import json
import uuid
from datetime import datetime

# --- CONFIGURATION ---
INPUT_FILE = 'unified_threat_feed.csv'
OUTPUT_FILE = 'misp_import_data.json'

# --- FUNCTIONS ---

def generate_misp_event(row):
    """Converts a single CSV row into a MISP Event structure."""
    
    # 1. Create unique Event ID
    event_uuid = str(uuid.uuid4())
    
    # 2. Map Honeypot Data to MISP Attributes
    attributes = []
    
    # Attribute: Source IP
    attributes.append({
        "type": "ip-src",
        "value": row['Src_IP'],
        "comment": f"Detected by {row['Honeypot']}",
        "to_ids": True # This means "Yes, this is an Indicator of Compromise"
    })
    
    # Attribute: MITRE Technique (Tagging)
    if row.get('MITRE_ID'):
        attributes.append({
            "type": "text",
            "value": f"MITRE ATT&CK: {row['MITRE_ID']} - {row['MITRE_Technique']}",
            "comment": "Automated Classification"
        })

    # Attribute: Country of Origin
    if row.get('Country'):
        attributes.append({
            "type": "text",
            "value": f"Origin: {row['Country']}",
            "comment": "GeoIP Enrichment"
        })

    # 3. Construct the Full Event Object
    misp_event = {
        "Event": {
            "uuid": event_uuid,
            "info": f"T-Pot Alert: {row['Event']} detected from {row['Src_IP']}",
            "date": datetime.now().strftime("%Y-%m-%d"),
            "threat_level_id": "2", # Medium
            "analysis": "1", # Initial Analysis
            "Attribute": attributes
        }
    }
    
    return misp_event

# --- MAIN EXECUTION ---

def main():
    print("--- STARTING MISP CONNECTOR (INTEGRATION MODULE) ---")
    print(f"[*] Loading intelligence from {INPUT_FILE}...")
    
    try:
        df = pd.read_csv(INPUT_FILE)
        print(f"[*] Loaded {len(df)} enriched threat events.")
    except FileNotFoundError:
        print("[!] Error: CSV file not found. Run the enrichment engine first.")
        return

    misp_export_list = []

    print("[*] Transforming data to MISP JSON format...")
    
    # Process the first 10 rows as a sample for the report
    for index, row in df.head(10).iterrows():
        event = generate_misp_event(row)
        misp_export_list.append(event)
        
    # Save the output
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(misp_export_list, f, indent=4)
        
    print(f"[*] Transformation Complete.")
    print(f"[SUCCESS] {len(misp_export_list)} events formatted for MISP ingestion.")
    print(f"[SUCCESS] Output saved to: {OUTPUT_FILE}")
    
    # Preview for the user
    print("\n--- PREVIEW OF MISP EVENT (Row 1) ---")
    print(json.dumps(misp_export_list[0], indent=4))

if __name__ == "__main__":
    main()
