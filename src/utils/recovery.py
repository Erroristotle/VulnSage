import logging
import json
import os
from datetime import datetime

class ProcessingStateManager:
    def __init__(self, checkpoint_file="processing_state.json"):
        self.checkpoint_file = checkpoint_file
        self.state = self.load_state()
        
    def load_state(self):
        """Load the last known processing state"""
        if os.path.exists(self.checkpoint_file):
            try:
                with open(self.checkpoint_file, 'r') as f:
                    return json.load(f)
            except:
                return {"last_processed": None, "timestamp": None}
        return {"last_processed": None, "timestamp": None}
    
    def save_state(self, commit_hash):
        """Save the current processing state"""
        self.state = {
            "last_processed": commit_hash,
            "timestamp": datetime.now().isoformat()
        }
        with open(self.checkpoint_file, 'w') as f:
            json.dump(self.state, f)
    
    def get_last_processed(self):
        """Get the last successfully processed commit"""
        return self.state.get("last_processed") 