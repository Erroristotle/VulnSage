import subprocess
import time
import logging
from typing import Optional, Tuple
from ..config import Config

logger = logging.getLogger(__name__)

class ModelManager:
    """Manages model installation and cleanup."""
    
    def __init__(self):
        self.current_model = None
        self.model_parameter = None

    def install_model(self, model_name: str) -> Tuple[bool, str]:
        """
        Create a custom model by writing a Modelfile and executing the 'ollama create'
        command, then install (run) the custom model.
        """
        # Parse the model identifier and context length from configuration.
        model_identifier, context_length = Config.get_model_command(model_name)
        if not model_identifier or not context_length:
            return False, "Model configuration not found or invalid"
        
        # Normalize the model identifier for creation:
        # Replace any colon (":") with a dash ("-") so the custom model name is valid.
        safe_model_identifier = model_identifier.replace(":", "-")
        
        # Create the Modelfile content.
        modelfile_content = f"FROM {model_identifier}\nPARAMETER num_ctx {context_length}\n"
        try:
            with open("Modelfile", "w") as f:
                f.write(modelfile_content)
            logger.info(f"Modelfile created with content:\n{modelfile_content}")
        except Exception as e:
            logger.error(f"Failed to write Modelfile: {e}")
            return False, f"Failed to write Modelfile: {e}"
        
        # Run the 'ollama create' command using the normalized model name.
        create_command = f"ollama create -f Modelfile {safe_model_identifier}:custom"
        logger.info(f"Running command: {create_command}")
        try:
            subprocess.run(create_command.split(), check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Error creating custom model: {e}")
            return False, f"Error creating custom model: {e}"
        
        # Now install (run) the custom model using the safe (normalized) identifier.
        run_command = f"ollama run {safe_model_identifier}:custom"
        logger.info(f"Installing model {model_name} using command: {run_command}")
        try:
            # Optionally, you might launch the process (if needed):
            # process = subprocess.Popen(run_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(10)  # Wait for model to initialize
            self.current_model = model_name
            # For API calls, use the safe custom model identifier.
            self.model_parameter = f"{safe_model_identifier}:custom"
            return True, "Success"
        except subprocess.CalledProcessError as e:
            logger.error(f"Error installing model: {e}")
            return False, str(e)

    def get_model_parameter(self) -> Optional[str]:
        """Get the current model parameter for API calls."""
        return self.model_parameter
