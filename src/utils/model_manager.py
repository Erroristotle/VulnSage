import subprocess
import time
import logging
from typing import Optional, Tuple
from ..config import Config

logger = logging.getLogger(__name__)

class ModelManager:
    """Manages model installation and cleanup."""
    
    def __init__(self):
        self.current_model: Optional[str] = None
        self.model_parameter: Optional[str] = None

    def install_model(self, model_name: str) -> Tuple[bool, str]:
        command = Config.get_model_command(model_name)
        try:
            print(f"Installing {model_name}...")
            process = subprocess.Popen(
                command.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            time.sleep(10)  # Wait for initialization
            
            # Don't terminate the process - keep it running
            self.current_model = model_name
            self.model_parameter = command.split(" ")[2]
            
            return True, "Success"
                
        except subprocess.CalledProcessError as e:
            return False, str(e)

    def cleanup_model(self):
        if self.current_model:
            try:
                subprocess.run(['ollama', 'stop'], check=True)
                logger.info(f"Model {self.current_model} stopped")
            except Exception as e:
                logger.error(f"Error stopping model: {e}")

    def get_model_parameter(self) -> Optional[str]:
        """Get the current model parameter for API calls."""
        return self.model_parameter