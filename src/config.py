import os
from typing import Dict

class Config:
    """Configuration settings for the vulnerability detection system."""
    
    # API and Database settings
    API_URL: str = "http://localhost:11434/api/generate"
    DATABASE_PATH: str = "database.sqlite"
    OUTPUT_DIR: str = os.path.join("..", "output")

    # Model configurations
    MODELS: Dict[str, str] = {
        "deepseek-v2-16b": "ollama run deepseek-v2",
        "llama3.1-8b": "ollama run llama3.1",
        "llama3.1-70b": "ollama run llama3.1:70b",
        "gemma2-9b": "ollama run gemma2:9b",
        "gemma2-27b": "ollama run gemma2:27b",
        "deepseek-coder-16b": "ollama run deepseek-coder-v2",
        "qwen2.5-coder-7b": "ollama run qwen2.5-coder",
        "qwen2.5-coder-32b": "ollama run qwen2.5-coder:32b",
        "codellama-7b": "ollama run codellama:7b",
        "codellama-34b": "ollama run codellama:34b",
        "deepseek-r1-7b": "ollama run deepseek-r1",
        "deepseek-r1-32b": "ollama run deepseek-r1:32b"
    }

    # Processing settings
    MAX_RETRIES: int = 3
    RETRY_DELAY: int = 2
    MAX_WORKERS: int = os.cpu_count()

    # State management
    STATE_FILE: str = "process_state.json"
    LOCK_FILE: str = "process.lock"

    @classmethod
    def get_model_command(cls, model_name: str) -> str:
        """Get the command to run a specific model."""
        return cls.MODELS.get(model_name)