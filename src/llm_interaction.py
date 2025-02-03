import requests
import time
from typing import Optional, List, Dict
from .prompts import BaselinePrompt, ChainOfThoughtPrompt, ThinkPrompt, ThinkVerifyPrompt
from .config import Config
import json
import sqlite3
import logging

# Configure logger
logger = logging.getLogger(__name__)
class LLMInteraction:
    def __init__(self, db_file: str, model_name: str):
        self.db_file = Config.DATABASE_PATH
        self.model_name = model_name
        self.model_parameter = Config.get_model_command(model_name).split(" ")[2]  # Extract the model name from command
        self.table_name = f"vulnerabilities_{model_name.replace('-', '_')}"
        
        # Initialize database connection
        self.conn = sqlite3.connect(self.db_file, timeout=60.0)
        self.conn.isolation_level = None  # autocommit mode
        
        # Set database pragmas for performance and reliability
        self.conn.execute("PRAGMA journal_mode=DELETE")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA busy_timeout=60000")
        
        self.strategies = {
            "baseline": BaselinePrompt(),
            "cot": ChainOfThoughtPrompt(),
            "think": ThinkPrompt(),
            "think_verify": ThinkVerifyPrompt()
        }
        
        # Create the table
        self.create_table()
        logger.info(f"Initialized LLM interaction with model: {model_name}, parameter: {self.model_parameter}")
    
    def __del__(self):
        """Cleanup database connection."""
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()
        
    def create_table(self):
        """Create the model-specific table if it doesn't exist."""
        try:
            cursor = self.conn.cursor()
            create_table_sql = f"""
            CREATE TABLE IF NOT EXISTS {self.table_name} (
                COMMIT_HASH TEXT PRIMARY KEY,
                BASELINE_VULN INT,
                BASELINE_PATCH INT,
                COT_VULN INT,
                COT_PATCH INT,
                THINK_VULN INT,
                THINK_PATCH INT,
                THINK_VERIFY_VULN INT,
                THINK_VERIFY_PATCH INT,
                FOREIGN KEY (COMMIT_HASH) REFERENCES vulnerabilities(COMMIT_HASH)
            )
            """
            cursor.execute(create_table_sql)
            cursor.execute("PRAGMA wal_checkpoint")  # Force a WAL checkpoint
            logger.info(f"Created or verified table: {self.table_name}")
        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
            raise
        
    def query_model(self, prompt: str, max_retries: int = 3, retry_delay: int = 2) -> Optional[str]:
        """Send a single prompt to the model and get a response."""
        payload = {
            "model": Config.get_model_command(self.model_name),
            "prompt": prompt
        }

        for attempt in range(max_retries):
            try:
                response = requests.post(Config.API_URL, json=payload)
                if response.status_code == 200:
                    lines = response.content.decode('utf-8').splitlines()
                    return ''.join([
                        json.loads(line)["response"] 
                        for line in lines if line
                    ])
                elif response.status_code == 503:
                    print(f"Model loading, retry in {retry_delay}s...")
                time.sleep(retry_delay)
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(retry_delay)
        return None

    def query_model_batch(self, prompts: List[str]) -> Optional[List[str]]:
        """Process prompts sequentially since Ollama doesn't support true batching."""
        responses = []
        
        for i, prompt in enumerate(prompts):
            payload = {
                "model": self.model_parameter,  # Use the extracted model parameter
                "prompt": prompt
            }
            
            logger.info(f"Processing prompt {i+1}/{len(prompts)}")
            
            for attempt in range(Config.MAX_RETRIES):
                try:
                    response = requests.post(Config.API_URL, json=payload)
                    if response.status_code == 200:
                        response_lines = response.content.decode('utf-8').splitlines()
                        full_response = ''.join([
                            json.loads(line)["response"] 
                            for line in response_lines if line
                        ])
                        responses.append(full_response)
                        logger.info(f"Successfully processed prompt {i+1}")
                        break
                    elif response.status_code == 503:
                        logger.warning(f"Model loading, retry in {Config.RETRY_DELAY}s...")
                        time.sleep(Config.RETRY_DELAY)
                    else:
                        logger.error(f"Request failed with status {response.status_code}")
                        time.sleep(Config.RETRY_DELAY)
                except Exception as e:
                    logger.error(f"Error in query {i+1}: {e}")
                    time.sleep(Config.RETRY_DELAY)
            else:
                # If all retries failed for this prompt
                logger.error(f"Failed to get response for prompt {i+1} after all retries")
                responses.append(None)
        
        successful_responses = len([r for r in responses if r is not None])
        logger.info(f"Completed batch processing. {successful_responses}/{len(prompts)} successful responses")
        return responses if any(r is not None for r in responses) else None

    def detection(self, commit_hash: str, code_block: str, cwe_id: str, 
                  is_vulnerable: bool, strategy: str = "baseline") -> None:
        """Run vulnerability detection for a single case."""
        prompt = self.strategies[strategy].create_prompt(code_block, cwe_id)
        result = self.query_model(prompt)
        
        table_name = f"vulnerabilities_{self.model_name}"
        logger.info(f"Storing result in table: {table_name}")
        
        if result:
            status = self.strategies[strategy].parse_response(result)
            if status is not None:
                column = f"{strategy.upper()}_{'VULN' if is_vulnerable else 'PATCH'}"
                logger.info(f"Storing result {status} for commit {commit_hash} in column {column}")
                
                with sqlite3.connect(self.db_file) as conn:
                    cursor = conn.cursor()
                    cursor.execute(f"""
                        INSERT OR REPLACE INTO {table_name}
                        (COMMIT_HASH, {column})
                        VALUES (?, ?)
                    """, (commit_hash, status))
                    conn.commit()

    def batch_detection(self, inputs: List[Dict], strategy: str = "baseline") -> None:
        """Process a batch of vulnerability detection requests."""
        logger.info(f"Processing batch of {len(inputs)} inputs with strategy: {strategy}")
        
        # Build prompts
        prompts = []
        metadata_list = []
        
        for item in inputs:
            prompt = self.strategies[strategy].create_prompt(
                item["code_block"], 
                item["cwe_id"]
            )
            prompts.append(prompt)
            metadata_list.append({
                "commit_hash": item["commit_hash"],
                "is_vulnerable": item["is_vulnerable"]
            })
        
        responses = self.query_model_batch(prompts)
        if not responses:
            logger.error("Batch query failed completely")
            return

        # Process responses
        for metadata, response in zip(metadata_list, responses):
            if not response:
                continue
                
            commit_hash = metadata["commit_hash"]
            is_vulnerable = metadata["is_vulnerable"]
            status = self.strategies[strategy].parse_response(response)
            
            if status is not None:
                column = f"{strategy.upper()}_{'VULN' if is_vulnerable else 'PATCH'}"
                logger.info(f"Storing result {status} for commit {commit_hash} in column {column}")
                
                try:
                    cursor = self.conn.cursor()
                    cursor.execute(f"""
                        INSERT OR REPLACE INTO {self.table_name} 
                        (COMMIT_HASH, {column})
                        VALUES (?, ?)
                    """, (commit_hash, status))
                    logger.info(f"Successfully stored result in database")
                except sqlite3.Error as e:
                    logger.error(f"Database error: {e}")
                    cursor.execute(f"SELECT sql FROM sqlite_master WHERE type='table' AND name='{self.table_name}'")
                    logger.error(f"Table schema: {cursor.fetchone()}")
                        
    def check_results(self):
        """Check the results stored in the database."""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {self.table_name} LIMIT 5")
            rows = cursor.fetchall()
            for row in rows:
                logger.info(f"Result: {row}")
            
            # Get count of results by type
            for strategy in ['BASELINE', 'COT', 'THINK', 'THINK_VERIFY']:
                for type_ in ['VULN', 'PATCH']:
                    column = f"{strategy}_{type_}"
                    cursor.execute(f"SELECT COUNT(*) FROM {self.table_name} WHERE {column} IS NOT NULL")
                    count = cursor.fetchone()[0]
                    logger.info(f"{column} results: {count}")