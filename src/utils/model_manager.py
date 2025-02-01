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
        """Install a specific model."""
        command = Config.get_model_command(model_name)
        if not command:
            return False, f"Model {model_name} not found in configuration"
        
        try:
            logger.info(f"Installing model: {model_name}")
            process = subprocess.Popen(
                command.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for initialization
            time.sleep(10)
            process.terminate()
            
            self.current_model = model_name
            self.model_parameter = command.split(" ")[2]
            
            logger.info(f"Model {model_name} installed successfully")
            return True, "Success"
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install model {model_name}: {e}")
            return False, str(e)

    def cleanup_model(self) -> None:
        """Remove the currently installed model."""
        if self.model_parameter:
            try:
                subprocess.run(['ollama', 'rm', self.model_parameter])
                logger.info(f"Model {self.current_model} removed successfully")
            except Exception as e:
                logger.error(f"Error removing model: {e}")
            finally:
                self.current_model = None
                self.model_parameter = None

    def get_model_parameter(self) -> Optional[str]:
        """Get the current model parameter for API calls."""
        return self.model_parameter