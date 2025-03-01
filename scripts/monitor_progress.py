import logging
import json
import time
from datetime import datetime

def monitor_progress():
    while True:
        try:
            with open("processing_state.json", 'r') as f:
                state = json.load(f)
            
            last_processed = state.get("last_processed")
            timestamp = state.get("timestamp")
            
            if timestamp:
                last_update = datetime.fromisoformat(timestamp)
                time_since_update = datetime.now() - last_update
                
                print(f"Last processed commit: {last_processed}")
                print(f"Time since last update: {time_since_update}")
                
                # Alert if no updates for more than 30 minutes
                if time_since_update.total_seconds() > 1800:
                    print("WARNING: No updates in the last 30 minutes!")
            
        except Exception as e:
            print(f"Error reading progress: {e}")
            
        time.sleep(60)  # Check every minute

if __name__ == "__main__":
    monitor_progress() 