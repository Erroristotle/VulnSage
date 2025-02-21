import os
from typing import Dict, Tuple

class Config:
    """Configuration settings for the vulnerability detection system."""
    
    # API and Database settings
    API_URL: str = "http://localhost:11434/api/generate"
    DATABASE_PATH: str = "vulnerability_dataset/database/database.sqlite"
    # OUTPUT_DIR: str = os.path.join("..", "output")

    # Configurable constant for ambiguous decisions
    AMBIGUOUS_DECISION_VALUE: float = 2.0
    
    # Model configurations
    MODELS: Dict[str, str] = {
        "deepseek-v2-16b": "deepseek-v2 num_ctx 163840",
        "llama3_1_8b": "llama3.1 num_ctx 131072",
        "llama3_1_70b": "llama3.1:70b num_ctx 131072",
        "gemma2-9b": "gemma2 num_ctx 8192",
        "gemma2-27b": "gemma2:27b num_ctx 8192",
        "deepseek-coder-16b": "deepseek-coder-v2 num_ctx 163840",
        "qwen2.5-coder-7b": "qwen2.5-coder num_ctx 32768",
        "qwen2.5-coder-32b": "qwen2.5-coder:32b num_ctx 32768",
        "codellama-7b": "codellama num_ctx 16384",
        "codellama-34b": "codellama:34b num_ctx 16384",
        "deepseek-r1-7b": "deepseek-r1:7b num_ctx 131072",
        "deepseek-r1-32b": "deepseek-r1:32b num_ctx 131072"
    }

    # Processing settings
    MAX_RETRIES: int = 3
    RETRY_DELAY: int = 2
    MAX_WORKERS: int = os.cpu_count()
    BATCH_SIZE: int = 4
    SUB_BATCH_SIZE: int = 2  # For breaking down large batches

    # State management
    STATE_FILE: str = "process_state.json"
    LOCK_FILE: str = "process.lock"

    @classmethod
    def get_model_command(cls, model_name: str) -> Tuple[str, str]:
        """
        Given a model name key, return a tuple (model_identifier, context_length)
        extracted from the MODELS dictionary.
        """
        command = cls.MODELS.get(model_name)
        if not command:
            return None, None
        parts = command.split()
        if len(parts) >= 3 and parts[1] == "num_ctx":
            model_identifier = parts[0].strip()
            context_length = parts[2].strip()
            return model_identifier, context_length
        return command.strip(), ""
    
    @classmethod
    def get_model_identifier(cls, model_name: str) -> str:
        """
        Returns the custom model identifier to be used for API calls.
        For example, if the MODELS entry is "codellama num_ctx 16384", this returns "codellama:custom".
        """
        model_identifier, _ = cls.get_model_command(model_name)
        if model_identifier is None:
            return None
        # Normalize by replacing any colon with a hyphen.
        safe_model_identifier = model_identifier.replace(":", "-")
        return f"{safe_model_identifier}:custom"