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
from src.utils.recovery import ProcessingStateManager
import argparse

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

class GracefulShutdown:
    shutdown_flag = False

    @classmethod
    def initiate_shutdown(cls, signum, frame):
        logging.info("Shutdown signal received. Completing current task...")
        cls.shutdown_flag = True

class VulnerabilityAnalyzer:
    """Main class for running vulnerability analysis using batched LLM calls."""
    
    def __init__(self):
        self.model_manager = ModelManager()
        self.database = Database(Config.DATABASE_PATH)
        self.running = True
        self.state_manager = ProcessingStateManager()
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        # Ensure ollama is running at start
        self.model_manager.ensure_ollama_running()

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
            
            # Initialize LLM interaction with model manager
            llm = LLMInteraction(Config.DATABASE_PATH, model_name, self.model_manager)
            strategies = ["baseline", "cot", "think", "think_verify"]
            batch_size = getattr(Config, 'BATCH_SIZE', 4)

            for strategy in strategies:
                logger.info(f"Processing strategy: {strategy}")
                
                # Check for unprocessed VULN columns
                vuln_commits = self.database.get_unprocessed_commits(model_name, strategy, "VULN")
                
                if vuln_commits:
                    logger.info(f"Found {len(vuln_commits)} commits with empty VULN columns for {strategy}")
                    
                    # Filter vulnerabilities for unprocessed VULN commits
                    vuln_vulnerabilities = [
                        v for v in vulnerability_data 
                        if v.commit_hash in vuln_commits
                    ]
                    
                    logger.info(f"Processing {len(vuln_vulnerabilities)} vulnerabilities for {strategy} VULN")
                    
                    # Process VULN in batches
                    for i in range(0, len(vuln_vulnerabilities), batch_size):
                        if not self.running:
                            logger.info("Shutdown requested. Saving state and exiting...")
                            return
                            
                        batch = vuln_vulnerabilities[i:i+batch_size]
                        
                        try:
                            # Prepare vulnerable inputs
                            vulnerable_inputs = []

                            for data in batch:
                                if data.vulnerable_code:
                                    vulnerable_inputs.append({
                                        'commit_hash': data.commit_hash,
                                        'code_block': data.vulnerable_code,
                                        'cwe_id': data.cwe_id,
                                        'is_vulnerable': True
                                    })

                            # Process vulnerable code
                            if vulnerable_inputs:
                                logger.info(f"Processing VULN batch {i//batch_size + 1} of {(len(vuln_vulnerabilities)-1)//batch_size + 1}")
                                llm.batch_detection(vulnerable_inputs, strategy)
                                
                        except Exception as e:
                            logger.error(f"Error processing VULN batch: {str(e)}")
                            continue
                            
                        # Add delay between batches
                        time.sleep(2)
                
                # Check for unprocessed PATCH columns
                patch_commits = self.database.get_unprocessed_commits(model_name, strategy, "PATCH")
                
                if patch_commits:
                    logger.info(f"Found {len(patch_commits)} commits with empty PATCH columns for {strategy}")
                    
                    # Filter vulnerabilities for unprocessed PATCH commits
                    patch_vulnerabilities = [
                        v for v in vulnerability_data 
                        if v.commit_hash in patch_commits
                    ]
                    
                    logger.info(f"Processing {len(patch_vulnerabilities)} vulnerabilities for {strategy} PATCH")
                    
                    # Process PATCH in batches
                    for i in range(0, len(patch_vulnerabilities), batch_size):
                        if not self.running:
                            logger.info("Shutdown requested. Saving state and exiting...")
                            return
                            
                        batch = patch_vulnerabilities[i:i+batch_size]
                        
                        try:
                            # Prepare patched inputs
                            patched_inputs = []

                            for data in batch:
                                if data.patched_code:
                                    patched_inputs.append({
                                        'commit_hash': data.commit_hash,
                                        'code_block': data.patched_code,
                                        'cwe_id': data.cwe_id,
                                        'is_vulnerable': False
                                    })

                            # Process patched code
                            if patched_inputs:
                                logger.info(f"Processing PATCH batch {i//batch_size + 1} of {(len(patch_vulnerabilities)-1)//batch_size + 1}")
                                llm.batch_detection(patched_inputs, strategy)
                                
                        except Exception as e:
                            logger.error(f"Error processing PATCH batch: {str(e)}")
                            continue
                            
                        # Add delay between batches
                        time.sleep(2)
                
                if not vuln_commits and not patch_commits:
                    logger.info(f"All commits already processed for strategy {strategy}. Skipping.")
                    continue
                    
                logger.info(f"Completed {strategy} strategy")

        except Exception as e:
            logger.error(f"Critical error in analysis: {str(e)}")
        finally:
            logger.info("Analysis completed or interrupted. Final state saved.")
            
    def complete_database(self, model_name: str, batch_size: int = 10, delay: float = 1.0, limit: int = None) -> None:
        """Complete empty columns in the database for a specific model."""
        logger.info(f"Starting database completion for model: {model_name}")
        
        # Initialize database
        db = Database(Config.DATABASE_PATH)
        
        # Complete empty columns
        db.complete_empty_columns(
            model_name=model_name,
            batch_size=batch_size,
            delay=delay,
            limit=limit
        )
        
        logger.info(f"Database completion finished for model: {model_name}")

    def verify_database_results(self, model_name, commit_hashes, strategy=None):
        """Verify that results are saved in the database."""
        logger.info(f"Verifying database results for model: {model_name}")
        
        # Initialize database
        db = Database(Config.DATABASE_PATH)
        
        # Check each commit hash
        for commit_hash in commit_hashes:
            result = db.verify_saved_results(model_name, commit_hash, strategy)
            if result:
                logger.info(f"✓ Data found for commit {commit_hash}")
            else:
                logger.error(f"✗ No data found for commit {commit_hash}")
        
        logger.info("Database verification completed")

def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description='Run vulnerability analysis')
    parser.add_argument('--complete-db', action='store_true',
                        help='Complete empty columns in the database')
    parser.add_argument('--batch-size', type=int, default=10, 
                        help='Number of entries to process in a batch')
    parser.add_argument('--delay', type=float, default=1.0,
                        help='Delay between API calls in seconds')
    parser.add_argument('--limit', type=int, default=None,
                        help='Limit the number of entries to process')
    args = parser.parse_args()

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

    # Check if we should complete the database or run analysis
    if args.complete_db:
        logger.info(f"Starting database completion with model: {model_name}")
        analyzer.complete_database(
            model_name=model_name,
            batch_size=args.batch_size,
            delay=args.delay,
            limit=args.limit
        )
    else:
        # Run analysis
        logger.info(f"Starting analysis with model: {model_name}")
        analyzer.run_analysis(model_name)

if __name__ == "__main__":
    main()