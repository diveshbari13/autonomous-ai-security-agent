import requests
import google.generativeai as genai
import json
import urllib3
import subprocess  
import time
import re         
import sys        
import os         
from config import GEMINI_API_KEY

WAZUH_INDEXER_URL = "https://localhost:9200"
WAZUH_USER = "admin"
WAZUH_PASSWORD = "admin"

ADMIN_IP= "192.168.1.6"

SEEN_ALERTS_FILE = "seen_alerts.txt"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GEMINI_PROMPT = """
You are a senior cybersecurity analyst for a production server.
Your only job is to analyze this Wazuh alert and decide if it represents a
hostile threat that requires an immediate IP block.

**Policy:**
1.  All failed SSH login attempts ('authentication failed', 'failed password', 'non-existent user') are considered high-priority hostile actions (brute-force attempts).
2.  Your default bias should be to protect the server.
3.  Respond with only the single word 'YES' or the single word 'NO'.

Here is the alert:
{alert_json}
"""

processed_alert_ids = set()

def load_seen_alerts():    
    if not os.path.exists(SEEN_ALERTS_FILE):
        return set()     
    print(f"Loading memory from {SEEN_ALERTS_FILE}...", file=sys.stderr)
    try:
        with open(SEEN_ALERTS_FILE, 'r') as f:          
            return set(line.strip() for line in f)
    except Exception as e:
        print(f"Error loading seen alerts: {e}. Starting fresh.", file=sys.stderr)
        return set()

def save_seen_alert(alert_id):    
    try:
        with open(SEEN_ALERTS_FILE, 'a') as f:
            f.write(f"{alert_id}\n")
    except Exception as e:
        print(f"Error saving seen alert: {e}", file=sys.stderr)

def get_wazuh_alerts():     
    print("Fetching latest alerts...", file=sys.stderr)    
    url = f"{WAZUH_INDEXER_URL}/wazuh-alerts-*/_search"    
    query = {
        "size": 20,
        "sort": [
            { "timestamp": { "order": "desc" } }
        ],
        "query": {
            "match_all": {}
        }
    }
    try:
        response = requests.post(
            url,
            auth=(WAZUH_USER, WAZUH_PASSWORD),
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=False
        )
        response.raise_for_status()
        
        hits = response.json().get("hits", {}).get("hits", [])
        alerts = [hit.get("_source") for hit in hits]
        return alerts
        
    except Exception as e:
        print(f"Error in get_wazuh_alerts: {e}!", file=sys.stderr)
        return None

def get_gemini_analysis(alert_entry):    
    print(f"\n Analyzing Alert: {alert_entry.get('rule', {}).get('description', 'No description')}", file=sys.stderr)    
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-flash-latest')        
        alert_text = json.dumps(alert_entry, indent=2)
        prompt_to_send = GEMINI_PROMPT.format(alert_json=alert_text)        
        response = model.generate_content(prompt_to_send)
        analysis = response.text.strip().upper()
        print(f"AI Agent's Decision: {analysis}", file=sys.stderr)
        return analysis
        
    except Exception as e:
        print(f"An error occurred during AI analysis: {e}", file=sys.stderr)
        return "ERROR"

def block_ip(ip_address):    
    if not ip_address:
        print("No IP address found in alert, cannot block.", file=sys.stderr)
        return

    if ip_address == ADMIN_IP:
        print(f"Agent saw a failed login from Admin PC ({ip_address}). Ignoring block action.", file=sys.stderr)
        return

    print(f"Taking Action: Attempting to block IP: {ip_address}", file=sys.stderr)
    try:
        command = ['iptables', '-I', 'INPUT', '1', '-s', ip_address, '-j', 'DROP']        
        subprocess.run(command, check=True)
        print(f"SUCCESS: Successfully blocked {ip_address} using iptables", file=sys.stderr)
        
    except FileNotFoundError:
        print("ERROR: 'iptables' command not found", file=sys.stderr)
    except subprocess.CalledProcessError:
        print("ERROR: Failed to run iptables.", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred during IP block: {e}", file=sys.stderr)


def main_loop():
    global processed_alert_ids     
    if not GEMINI_API_KEY or GEMINI_API_KEY == "YOUR_GEMINI_API_KEY_HERE":
        print(" Set or edit your GEMINI_API_KEY.", file=sys.stderr)
        return
    
    processed_alert_ids = load_seen_alerts()
    print(f"Loaded {len(processed_alert_ids)} seen alerts from memory.", file=sys.stderr)

    print("Agent is running", file=sys.stderr)
    while True:
        try:
            alerts = get_wazuh_alerts() 
            
            if alerts:
                for alert in alerts:
                    alert_id = alert.get('id')
                                        
                    if alert_id and (alert_id not in processed_alert_ids):
                        
                        ip_address = alert.get('data', {}).get('srcip')
                        alert_description = alert.get('rule', {}).get('description', '').lower()
                        
                        print(f"[NEW ALERT]: {alert_description}", file=sys.stderr)
                        
                        if ip_address and ("authentication fail" in alert_description or \
                                           "failed password" in alert_description or \
                                           "non-existent user" in alert_description):
                            
                            gemini_decision = get_gemini_analysis(alert)
                            
                            if gemini_decision == "YES":
                                block_ip(ip_address)
                                               
                        processed_alert_ids.add(alert_id)
                        save_seen_alert(alert_id)
            
            time.sleep(10)
            
        except KeyboardInterrupt:
            print("\nShutting down agent.", file=sys.stderr)
            break
        except Exception as e:
            print(f"Main loop error: {e}", file=sys.stderr)
            time.sleep(30) 

if __name__ == "__main__":
    main_loop()
