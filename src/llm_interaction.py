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
        # Use the full command exactly as defined in the configuration.
        self.model_parameter = Config.get_model_identifier(model_name)
        self.table_name = f"vulnerabilities_{model_name.replace('-', '_').replace('.', '_')}"
        
        # Initialize database connection
        self.conn = sqlite3.connect(self.db_file, timeout=60.0)
        self.conn.isolation_level = None  # autocommit mode
        
        # Set database pragmas for performance and reliability
        self.conn.execute("PRAGMA journal_mode=DELETE")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA busy_timeout=60000")
        
        # Pass the chosen model command to each prompt strategy.
        # This ensures that if the user selects "gemma2" for example, the BasePrompt receives the command for gemma2.
        self.strategies = {
            "baseline": BaselinePrompt(self.model_parameter),
            "cot": ChainOfThoughtPrompt(self.model_parameter),
            "think": ThinkPrompt(self.model_parameter),
            "think_verify": ThinkVerifyPrompt(self.model_parameter)
        }
        
        # Create the table
        self.create_table()
        logger.info(f"Table {self.table_name} is ready with all required columns")
        logger.info(f"Initialized LLM interaction with model: {model_name}, parameter: {self.model_parameter}")
    
    def __del__(self):
        """Cleanup database connection."""
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()
        
    def create_table(self):
        """Create or update the model-specific table."""
        try:
            cursor = self.conn.cursor()
            
            # Check if table exists
            cursor.execute(f"""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name=?
            """, (self.table_name,))
            
            if cursor.fetchone():
                # Table exists, add new columns if they don't exist
                new_columns = [
                    'COT_REASONING_VULN TEXT',
                    'COT_REASONING_PATCH TEXT',
                    'THINK_REASONING_VULN TEXT',
                    'THINK_REASONING_PATCH TEXT',
                    'THINK_VERIFY_REASONING_VULN TEXT',
                    'THINK_VERIFY_REASONING_PATCH TEXT'
                ]
                
                for column in new_columns:
                    try:
                        alter_sql = f"ALTER TABLE {self.table_name} ADD COLUMN {column}"
                        cursor.execute(alter_sql)
                        logger.info(f"Added column {column} to {self.table_name}")
                    except sqlite3.OperationalError as e:
                        if "duplicate column name" not in str(e).lower():
                            logger.error(f"Error adding column {column}: {e}")
            else:
                # Create new table with all columns
                create_table_sql = f"""
                CREATE TABLE {self.table_name} (
                    COMMIT_HASH TEXT PRIMARY KEY,
                    BASELINE_VULN INT,
                    BASELINE_PATCH INT,
                    COT_VULN INT,
                    COT_PATCH INT,
                    COT_REASONING_VULN TEXT,
                    COT_REASONING_PATCH TEXT,
                    THINK_VULN INT,
                    THINK_PATCH INT,
                    THINK_REASONING_VULN TEXT,
                    THINK_REASONING_PATCH TEXT,
                    THINK_VERIFY_VULN INT,
                    THINK_VERIFY_PATCH INT,
                    THINK_VERIFY_REASONING_VULN TEXT,
                    THINK_VERIFY_REASONING_PATCH TEXT,
                    FOREIGN KEY (COMMIT_HASH) REFERENCES vulnerabilities(COMMIT_HASH)
                )
                """
                cursor.execute(create_table_sql)
                
            self.conn.commit()
            logger.info(f"Table {self.table_name} is ready with all required columns")
            
        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
            raise
        
    def verify_results(self, commit_hash: str, strategy: str):
        """Verify results and reasoning for a specific commit and strategy."""
        cursor = self.conn.cursor()
        
        if strategy == "baseline":
            cursor.execute(f"""
                SELECT BASELINE_VULN, BASELINE_PATCH
                FROM {self.table_name} 
                WHERE COMMIT_HASH = ?
            """, (commit_hash,))
            result = cursor.fetchone()
            if result:
                logger.info(f"Baseline results for {commit_hash}:")
                logger.info(f"VULN: {result[0]}, PATCH: {result[1]}")
        else:
            cursor.execute(f"""
                SELECT 
                    {strategy.upper()}_VULN,
                    {strategy.upper()}_PATCH
                FROM {self.table_name} 
                WHERE COMMIT_HASH = ?
            """, (commit_hash,))
            result = cursor.fetchone()
            if result:
                logger.info(f"{strategy} results for {commit_hash}:")
                logger.info(f"VULN: {result[0]}, PATCH: {result[1]}")
        
    def query_model(self, prompt: str, max_retries: int = 3, retry_delay: int = 2) -> Optional[str]:
        """Send a single prompt to the model and get a response."""
        payload = {
            "model": Config.get_model_command(self.model_name),
            "prompt": prompt,
            "temperature": 0.7,
            "stream": False
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
                "model": self.model_parameter,
                "prompt": prompt,
                "temperature": 0.7,
                "stream": False
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
        """Run vulnerability detection and store both result and reasoning."""
        prompt = self.strategies[strategy].create_prompt(code_block, cwe_id)
        result = self.query_model(prompt)
        
        if result:
            status = self.strategies[strategy].parse_response(result)
            if status is not None:
                try:
                    cursor = self.conn.cursor()
                    
                    # Determine column names based on strategy and type
                    result_column = f"{strategy.upper()}_{'VULN' if is_vulnerable else 'PATCH'}"
                    if strategy != "baseline":  # Baseline doesn't have reasoning
                        reasoning_column = f"{strategy.upper()}_REASONING_{'VULN' if is_vulnerable else 'PATCH'}"
                        
                        # Check if row exists
                        cursor.execute(f"""
                            SELECT {result_column}, {reasoning_column}
                            FROM {self.table_name} 
                            WHERE COMMIT_HASH = ?
                        """, (commit_hash,))
                        existing_row = cursor.fetchone()
                        
                        if existing_row:
                            # Update existing row
                            cursor.execute(f"""
                                UPDATE {self.table_name}
                                SET {result_column} = ?,
                                    {reasoning_column} = ?
                                WHERE COMMIT_HASH = ?
                            """, (status, result, commit_hash))
                        else:
                            # Insert new row
                            cursor.execute(f"""
                                INSERT INTO {self.table_name}
                                (COMMIT_HASH, {result_column}, {reasoning_column})
                                VALUES (?, ?, ?)
                            """, (commit_hash, status, result))
                    else:
                        # Handle baseline case (no reasoning)
                        cursor.execute(f"""
                            INSERT OR REPLACE INTO {self.table_name}
                            (COMMIT_HASH, {result_column})
                            VALUES (?, ?)
                        """, (commit_hash, status))
                    
                    self.conn.commit()
                    logger.info(f"Stored result {status} and reasoning for commit {commit_hash}")
                    
                    # Log stored information
                    if strategy != "baseline":
                        logger.info(f"Reasoning stored: {result[:200]}...")  # Log first 200 chars
                    
                except sqlite3.Error as e:
                    logger.error(f"Database error: {e}")

    def batch_detection(self, inputs: List[Dict], strategy: str = "baseline") -> None:
        """Process a batch of vulnerability detection requests."""
        logger.info(f"Processing batch of {len(inputs)} inputs with strategy: {strategy}")
        
        # Build prompts and metadata list
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
        for metadata, full_response in zip(metadata_list, responses):
            if not full_response:
                continue
                
            commit_hash = metadata["commit_hash"]
            is_vulnerable = metadata["is_vulnerable"]
            status = self.strategies[strategy].parse_response(full_response)
            
            if status is not None:
                try:
                    cursor = self.conn.cursor()
                    
                    # Determine column names
                    result_column = f"{strategy.upper()}_{'VULN' if is_vulnerable else 'PATCH'}"
                    reasoning_column = f"{strategy.upper()}_REASONING_{'VULN' if is_vulnerable else 'PATCH'}"
                    
                    if strategy == "baseline":
                        # For baseline, only store the decision
                        cursor.execute(f"""
                            INSERT INTO {self.table_name} (COMMIT_HASH, {result_column})
                            VALUES (?, ?)
                            ON CONFLICT(COMMIT_HASH) DO UPDATE SET {result_column} = excluded.{result_column}
                        """, (commit_hash, status))
                    else:
                        # For other strategies, store both decision and reasoning
                        cursor.execute(f"""
                            INSERT INTO {self.table_name} (COMMIT_HASH, {result_column}, {reasoning_column})
                            VALUES (?, ?, ?)
                            ON CONFLICT(COMMIT_HASH) DO UPDATE SET 
                            {result_column} = excluded.{result_column},
                            {reasoning_column} = excluded.{reasoning_column}
                        """, (commit_hash, status, full_response))
                    
                    self.conn.commit()
                    logger.info(f"Storing result {status} for commit {commit_hash} in column {result_column}")
                    if strategy != "baseline":
                        logger.info(f"Full reasoning stored in {reasoning_column}")
                    logger.info("Successfully stored result in database")
                    
                    # Verify results after storing
                    self.verify_results(commit_hash, strategy)
                    
                except sqlite3.Error as e:
                    logger.error(f"Database error: {e}")
                    cursor.execute(f"SELECT sql FROM sqlite_master WHERE type='table' AND name='{self.table_name}'")
                    logger.error(f"Table schema: {cursor.fetchone()}")
                        
    def get_unprocessed_strategies(self) -> List[str]:
        """Return a list of strategies that have empty columns."""
        cursor = self.conn.cursor()
        unprocessed = []
        
        # Check baseline
        cursor.execute(f"""
            SELECT COUNT(*) 
            FROM {self.table_name} 
            WHERE BASELINE_VULN IS NOT NULL 
            AND BASELINE_PATCH IS NOT NULL
        """)
        if cursor.fetchone()[0] == 0:
            unprocessed.append("baseline")
        
        # Check COT
        cursor.execute(f"""
            SELECT COUNT(*) 
            FROM {self.table_name} 
            WHERE COT_VULN IS NOT NULL 
            AND COT_PATCH IS NOT NULL 
            AND COT_REASONING_VULN IS NOT NULL 
            AND COT_REASONING_PATCH IS NOT NULL
        """)
        if cursor.fetchone()[0] == 0:
            unprocessed.append("cot")
        
        # Check think
        cursor.execute(f"""
            SELECT COUNT(*) 
            FROM {self.table_name} 
            WHERE THINK_VULN IS NOT NULL 
            AND THINK_PATCH IS NOT NULL 
            AND THINK_REASONING_VULN IS NOT NULL 
            AND THINK_REASONING_PATCH IS NOT NULL
        """)
        if cursor.fetchone()[0] == 0:
            unprocessed.append("think")
        
        # Check think_verify
        cursor.execute(f"""
            SELECT COUNT(*) 
            FROM {self.table_name} 
            WHERE THINK_VERIFY_VULN IS NOT NULL 
            AND THINK_VERIFY_PATCH IS NOT NULL 
            AND THINK_VERIFY_REASONING_VULN IS NOT NULL 
            AND THINK_VERIFY_REASONING_PATCH IS NOT NULL
        """)
        if cursor.fetchone()[0] == 0:
            unprocessed.append("think_verify")
        
        logger.info(f"Found unprocessed strategies: {unprocessed}")
        return unprocessed