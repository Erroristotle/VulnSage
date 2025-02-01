import os
import logging
import signal
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from src.config import Config
from src.database import Database
from src.utils.model_manager import ModelManager
from src.llm_interaction import LLMInteraction
from src.models import VulnerabilityData

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vulnerability_analysis.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class VulnerabilityAnalyzer:
    """Main class for running vulnerability analysis."""
    
    def __init__(self):
        self.model_manager = ModelManager()
        self.database = Database(Config.DATABASE_PATH)
        self.running = True
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info("Received shutdown signal. Cleaning up...")
        self.running = False
        self.cleanup()
        sys.exit(0)

    def cleanup(self):
        """