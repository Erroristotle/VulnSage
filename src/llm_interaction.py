import requests
import time
from typing import Optional, List, Dict
from .prompts import BaselinePrompt, ChainOfThoughtPrompt, ThinkPrompt, ThinkVerifyPrompt
from .config import Config
import json
import sqlite3
import logging
from tenacity import retry, stop_after_attempt, wait_exponential
from .utils.model_manager import ModelManager

# Configure logger
logger = logging.getLogger(__name__)
class LLMInteraction:
    def __init__(self, db_file: str, model_name: str, model_manager: ModelManager):
        self.db_file = Config.DATABASE_PATH
        self.model_name = model_name
        self.model_parameter = Config.get_model_identifier(model_name)
        self.table_name = f"vulnerabilities_{model_name.replace('-', '_').replace('.', '_')}"
        self.model_manager = model_manager  # Store the model manager instance
        
        # Initialize database connection
        self.conn = sqlite3.connect(self.db_file, timeout=60.0)
        self.conn.isolation_level = None  # autocommit mode
        
        # Set database pragmas for performance and reliability
        self.conn.execute("PRAGMA journal_mode=DELETE")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA busy_timeout=60000")
        
        # Initialize strategies
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
        self._save_result = self._save_result_to_db
    
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
        
        try:
            if strategy == "baseline":
                cursor.execute(f"""
                    SELECT BASELINE_VULN, BASELINE_PATCH
                    FROM {self.table_name} 
                    WHERE COMMIT_HASH = ?
                """, (commit_hash,))
                result = cursor.fetchone()
                if result:
                    logger.info(f"Verified baseline results for {commit_hash}: VULN={result[0]}, PATCH={result[1]}")
                    return True
                else:
                    logger.warning(f"No baseline results found for {commit_hash}")
                    return False
            else:
                # For strategies with reasoning, first check just the result columns
                result_cols = f"{strategy.upper()}_VULN, {strategy.upper()}_PATCH"
                
                cursor.execute(f"""
                    SELECT {result_cols}
                    FROM {self.table_name} 
                    WHERE COMMIT_HASH = ?
                """, (commit_hash,))
                result = cursor.fetchone()
                
                if result:
                    logger.info(f"Verified {strategy} results for {commit_hash}: VULN={result[0]}, PATCH={result[1]}")
                    
                    # Now check for reasoning columns separately
                    reasoning_cols = f"{strategy.upper()}_REASONING_VULN, {strategy.upper()}_REASONING_PATCH"
                    cursor.execute(f"""
                        SELECT {reasoning_cols}
                        FROM {self.table_name} 
                        WHERE COMMIT_HASH = ?
                    """, (commit_hash,))
                    reasoning = cursor.fetchone()
                    
                    if reasoning and reasoning[0] is not None and reasoning[1] is not None:
                        vuln_reasoning = reasoning[0][:50] + "..." if reasoning[0] else "None"
                        patch_reasoning = reasoning[1][:50] + "..." if reasoning[1] else "None"
                        logger.info(f"Reasoning VULN: {vuln_reasoning} PATCH: {patch_reasoning}")
                    else:
                        logger.info(f"Reasoning columns not yet populated for {commit_hash}")
                    
                    return True
                else:
                    logger.warning(f"No {strategy} results found for {commit_hash}")
                    return False
        except sqlite3.Error as e:
            logger.error(f"Database error during verification: {e}")
            return False

    def _save_result_to_db(self, commit_hash: str, response: str, strategy: str, is_vulnerable: bool = None) -> None:
        """Save result and reasoning to database"""
        try:
            # Get the is_vulnerable flag from the input data if not provided
            if is_vulnerable is None:
                # Try to determine from the context
                for input_data in self.current_batch:
                    if input_data['commit_hash'] == commit_hash:
                        is_vulnerable = input_data.get('is_vulnerable', True)
                        break
            
            # Log what we're saving for debugging
            logger.info(f"Saving result for commit {commit_hash}, strategy {strategy}, is_vulnerable={is_vulnerable}")
            
            status = self.strategies[strategy].parse_response(response)
            if status is not None:
                cursor = self.conn.cursor()
                
                # Determine column names
                result_column = f"{strategy.upper()}_{'VULN' if is_vulnerable else 'PATCH'}"
                
                if strategy == "baseline":
                    # For baseline, only save the result (no reasoning)
                    cursor.execute(f"""
                        INSERT INTO {self.table_name} (COMMIT_HASH, {result_column})
                        VALUES (?, ?)
                        ON CONFLICT(COMMIT_HASH) DO UPDATE SET 
                            {result_column} = excluded.{result_column}
                    """, (commit_hash, status))
                else:
                    # For other strategies, save both result and reasoning
                    reasoning_column = f"{strategy.upper()}_REASONING_{'VULN' if is_vulnerable else 'PATCH'}"
                    
                    # First check if the row exists
                    cursor.execute(f"""
                        SELECT COMMIT_HASH FROM {self.table_name} WHERE COMMIT_HASH = ?
                    """, (commit_hash,))
                    
                    if cursor.fetchone():
                        # Row exists, update specific columns
                        cursor.execute(f"""
                            UPDATE {self.table_name}
                            SET {result_column} = ?, {reasoning_column} = ?
                            WHERE COMMIT_HASH = ?
                        """, (status, response, commit_hash))
                    else:
                        # Row doesn't exist, insert with specific columns
                        cursor.execute(f"""
                            INSERT INTO {self.table_name} (COMMIT_HASH, {result_column}, {reasoning_column})
                            VALUES (?, ?, ?)
                        """, (commit_hash, status, response))
                
                self.conn.commit()
                logger.info(f"Saved result {status} for commit {commit_hash} in column {result_column}")
                return True
                
        except sqlite3.Error as e:
            logger.error(f"Database error while saving result: {str(e)}")
        except Exception as e:
            logger.error(f"Error saving result: {str(e)}")
        
        return False

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=2, min=4, max=20))
    def _make_request(self, prompt: str) -> str:
        """Make a request to the LLM with retry logic and timeout"""
        try:
            # Check if ollama is running and responding
            if not self.model_manager.check_ollama_running():
                if not self.model_manager.wait_for_ollama(timeout=30):
                    logger.error("Ollama not running or not responding")
                    logger.info("Please ensure Ollama is running using: nohup ~/ollama/bin/ollama serve &>/dev/null & disown")
                    raise Exception("Ollama not available")
            
            # Make request with timeout
            response = requests.post(
                Config.API_URL,
                json={"model": self.model_parameter, "prompt": prompt},
                timeout=Config.TIMEOUT,
                stream=True
            )
            
            if response.status_code != 200:
                raise requests.exceptions.RequestException(f"Request failed with status {response.status_code}")
            
            # Accumulate the response with timeout
            full_response = ""
            response_timeout = time.time() + Config.TIMEOUT
            
            for line in response.iter_lines():
                if time.time() > response_timeout:
                    logger.error("Response accumulation timed out")
                    raise TimeoutError("Response accumulation timed out")
                    
                if line:
                    try:
                        json_response = json.loads(line.decode('utf-8'))
                        if 'response' in json_response:
                            full_response += json_response['response']
                        if json_response.get('done', False):
                            break
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to decode JSON line: {line}")
                        continue
            
            if not full_response:
                raise ValueError("Empty response from model")
                
            return full_response
            
        except Exception as e:
            logger.error(f"Request failed: {str(e)}")
            raise

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

    def batch_detection(self, inputs: List[Dict], strategy: str) -> None:
        """Process a batch of inputs with error handling and progress tracking"""
        logger.info(f"Processing batch of {len(inputs)} inputs with strategy: {strategy}")
        
        # Store the current batch for reference
        self.current_batch = inputs
        
        # Log the batch type for debugging
        batch_type = "vulnerable" if inputs and inputs[0].get('is_vulnerable', True) else "patched"
        logger.info(f"Processing {batch_type} batch with {len(inputs)} inputs")
        
        for idx, input_data in enumerate(inputs, 1):
            logger.info(f"Processing prompt {idx}/{len(inputs)}")
            
            try:
                # Generate prompt based on strategy
                prompt = self.strategies[strategy].create_prompt(
                    input_data["code_block"], 
                    input_data["cwe_id"]
                )
                
                # Make request with retry logic
                try:
                    response = self._make_request(prompt)
                    if response:
                        # Save result to database
                        success = self._save_result(
                            commit_hash=input_data['commit_hash'],
                            response=response,
                            strategy=strategy,
                            is_vulnerable=input_data.get('is_vulnerable', True)
                        )
                        
                        if success:
                            # Verify the result was saved
                            self.verify_results(input_data['commit_hash'], strategy)
                except Exception as e:
                    logger.error(f"Failed to process or save response: {str(e)}")
                    continue
                
                # Add small delay between requests
                time.sleep(2)  # Increased delay to prevent rate limiting
                
            except Exception as e:
                logger.error(f"Error processing input {idx}: {str(e)}")
                continue
        
        # Clear the current batch
        self.current_batch = None

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