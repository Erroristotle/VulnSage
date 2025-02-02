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
        """Cleanup resources."""
        logger.info("Performing cleanup...")
        self.model_manager.cleanup_model()
        logger.info("Cleanup completed")

    def process_vulnerability(self, data: VulnerabilityData, llm: LLMInteraction) -> None:
        """Process a single vulnerability."""
        try:
            # Process vulnerable code
            if data.vulnerable_code and self.running:
                logger.info(f"Processing vulnerable code for commit {data.commit_hash}")
                llm.detection(
                    commit_hash=data.commit_hash,
                    code_block=data.vulnerable_code,
                    cwe_id=data.cwe_id,
                    is_vulnerable=True
                )

            # Process patched code
            if data.patched_code and self.running:
                logger.info(f"Processing patched code for commit {data.commit_hash}")
                llm.detection(
                    commit_hash=data.commit_hash,
                    code_block=data.patched_code,
                    cwe_id=data.cwe_id,
                    is_vulnerable=False
                )

        except Exception as e:
            logger.error(f"Error processing commit {data.commit_hash}: {e}")

    def run_analysis(self, model_name: str) -> None:
        """Run the vulnerability analysis for a specific model."""
        try:
            # Install model
            logger.info(f"Installing model: {model_name}")
            success, message = self.model_manager.install_model(model_name)
            if not success:
                logger.error(f"Failed to install model: {message}")
                return

            # Create output directory
            os.makedirs(Config.OUTPUT_DIR, exist_ok=True)

            # Initialize database
            db_path = os.path.join(Config.OUTPUT_DIR, f"database_{model_name}.sqlite")
            if not os.path.exists(db_path):
                import shutil
                shutil.copy(Config.DATABASE_PATH, db_path)

            # Get vulnerability data
            vulnerability_data = self.database.get_vulnerability_data()
            logger.info(f"Found {len(vulnerability_data)} vulnerabilities to process")

            # Initialize LLM interaction
            llm = LLMInteraction(db_path, model_name)

            # Process vulnerabilities using thread pool
            with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
                futures = []
                for data in vulnerability_data:
                    if not self.running:
                        break
                    futures.append(
                        executor.submit(self.process_vulnerability, data, llm)
                    )

                # Wait for completion
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Error in future: {e}")

        except Exception as e:
            logger.error(f"Error in analysis: {e}")
        finally:
            self.cleanup()

# Initialize analyzer
analyzer = VulnerabilityAnalyzer()

# Display available models
print("\nAvailable models:")
for idx, model in enumerate(Config.MODELS.keys(), 1):
    print(f"{idx}. {model}")

# Get user input
while True:
    try:
        selection = input("\nEnter model number to use: ")
        model_name = list(Config.MODELS.keys())[int(selection) - 1]
        break
    except (ValueError, IndexError):
        print("Invalid selection. Please try again.")

# Run analysis
logger.info(f"Starting analysis with model: {model_name}")
analyzer.run_analysis(model_name)