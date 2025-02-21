import os
import logging
import signal
import sys
import time
import sqlite3
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
    """Main class for running vulnerability analysis using batched LLM calls."""
    
    def __init__(self):
        self.model_manager = ModelManager()
        self.database = Database(Config.DATABASE_PATH)
        self.running = True
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info("Received shutdown signal.")
        self.running = False
        sys.exit(0)

    def run_analysis(self, model_name: str) -> None:
        """Run the vulnerability analysis for a specific model using batching."""
        try:
            # Install model
            logger.info(f"Installing model: {model_name}")
            success, message = self.model_manager.install_model(model_name)
            if not success:
                logger.error(f"Failed to install model: {message}")
                return

            # Get vulnerability data
            vulnerability_data: List[VulnerabilityData] = self.database.get_vulnerability_data()
            logger.info(f"Found {len(vulnerability_data)} vulnerabilities to process")
            
            # Filter vulnerabilities: only process projects "linux" and "xen"
            vulnerability_data = [v for v in vulnerability_data if v.project.lower() in ["linux", "xen"]]
            logger.info(f"After filtering, {len(vulnerability_data)} vulnerabilities remain for projects linux and xen")

            # Initialize LLM interaction
            llm = LLMInteraction(Config.DATABASE_PATH, model_name)
            strategies = ["baseline", "cot", "think", "think_verify"]

            for strategy in strategies:
                logger.info(f"Processing strategy: {strategy}")
                
                # Retrieve unprocessed commits
                unprocessed_commits = self.database.get_unprocessed_commits(model_name, strategy)
                
                if not unprocessed_commits:
                    logger.info(f"All commits already processed for strategy {strategy}. Skipping.")
                    continue

                # Filter vulnerabilities for only unprocessed commits
                vulnerabilities_for_strategy = [
                    v for v in vulnerability_data if v.commit_hash in unprocessed_commits
                ]
                logger.info(f"Found {len(vulnerabilities_for_strategy)} unprocessed vulnerabilities for {strategy}")

                logger.info(f"Starting {strategy} strategy")
                batch_size = getattr(Config, 'BATCH_SIZE', 8)
                for i in range(0, len(vulnerabilities_for_strategy), batch_size):
                    batch = vulnerabilities_for_strategy[i:i+batch_size]
                    vulnerable_inputs = []
                    patched_inputs = []

                    for data in batch:
                        if not self.running:
                            break
                        if data.vulnerable_code:
                            vulnerable_inputs.append({
                                'commit_hash': data.commit_hash,
                                'code_block': data.vulnerable_code,
                                'cwe_id': data.cwe_id,
                                'is_vulnerable': True
                            })
                        if data.patched_code:
                            patched_inputs.append({
                                'commit_hash': data.commit_hash,
                                'code_block': data.patched_code,
                                'cwe_id': data.cwe_id,
                                'is_vulnerable': False
                            })

                    if vulnerable_inputs:
                        logger.info(f"Processing vulnerable batch for {strategy} with {len(vulnerable_inputs)} commits")
                        llm.batch_detection(vulnerable_inputs, strategy)

                    if patched_inputs:
                        logger.info(f"Processing patched batch for {strategy} with {len(patched_inputs)} commits")
                        llm.batch_detection(patched_inputs, strategy)

                logger.info(f"Completed {strategy} strategy")

        except Exception as e:
            logger.error(f"Error in analysis: {e}")
        finally:
            logger.info("All strategies completed.")

def main():
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

if __name__ == "__main__":
    main()