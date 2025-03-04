import sqlite3
from typing import List, Optional, Tuple
from contextlib import contextmanager
from .models import VulnerabilityData
import logging

logger = logging.getLogger(__name__)

class Database:
    """Database management class."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path

    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()

    def create_model_table(self, model_name: str) -> None:
        """Create a new table for specific model results with enhanced fields."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            table_name = f"vulnerabilities_{model_name}"
            
            strategies = ['BASELINE', 'COT', 'THINK', 'THINK_VERIFY']
            columns = []
            
            for strategy in strategies:
                for type_ in ['VULN', 'PATCH']:
                    base_name = f"{strategy}_{type_}"
                    columns.extend([
                        f"{base_name} INT",
                        f"{base_name}_CONFIDENCE REAL",
                        f"{base_name}_SEVERITY TEXT",
                        f"{base_name}_CVE_MATCHES TEXT",
                        f"{base_name}_CWE_MATCHES TEXT"
                    ])
            
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {table_name} (
                    COMMIT_HASH TEXT PRIMARY KEY,
                    {','.join(columns)},
                    FOREIGN KEY (COMMIT_HASH) REFERENCES vulnerabilities(COMMIT_HASH)
                )
            """)
            conn.commit()

    def get_vulnerability_data(self) -> List[VulnerabilityData]:
        """Fetch all vulnerability data from the database."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COMMIT_HASH, vulnerable_code_block, patched_code_block,
                       VULNERABILITY_CWE, VULNERABILITY_YEAR, description_in_patch, PROJECT
                FROM vulnerabilities
            """)
            return [
                VulnerabilityData(
                    commit_hash=row[0],
                    vulnerable_code=row[1],
                    patched_code=row[2],
                    cwe_id=row[3],
                    year=row[4],
                    description=row[5],
                    project=row[6]
                )
                for row in cursor.fetchall()
            ]

    def update_result(self, model_name: str, commit_hash: str,
                     strategy: str, is_vulnerable: bool, status: int) -> None:
        """Update result in the database."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            table_name = f"vulnerabilities_{model_name}"
            column = f"{strategy.upper()}_{'VULN' if is_vulnerable else 'PATCH'}"
            
            cursor.execute(f"""
                INSERT OR REPLACE INTO {table_name} 
                (COMMIT_HASH, {column})
                VALUES (?, ?)
            """, (commit_hash, status))
            conn.commit()

    def get_unprocessed_commits(self, model_name: str, strategy: str, column_type: str = None) -> List[str]:
        """
        Get commits that haven't been processed for a specific model, strategy, and column type.
        
        Args:
            model_name (str): The model name
            strategy (str): The strategy (baseline, cot, think, think_verify)
            column_type (str, optional): Specific column type to check (VULN or PATCH)
                                        If None, checks both VULN and PATCH
        
        Returns:
            List[str]: List of commit hashes that need processing
        """
        table_name = f"vulnerabilities_{model_name.replace('-', '_').replace('.', '_')}"
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Build the query based on what we need to check
                if column_type:
                    # Check only the specified column type (VULN or PATCH)
                    column_name = f"{strategy.upper()}_{column_type}"
                    reasoning_column = f"{strategy.upper()}_REASONING_{column_type}" if strategy != "baseline" else None
                    
                    if reasoning_column:
                        query = f"""
                            SELECT DISTINCT v.COMMIT_HASH 
                            FROM vulnerabilities v
                            LEFT JOIN {table_name} m ON v.COMMIT_HASH = m.COMMIT_HASH
                            WHERE m.COMMIT_HASH IS NULL
                            OR m.{column_name} IS NULL
                            OR m.{reasoning_column} IS NULL
                        """
                    else:
                        query = f"""
                            SELECT DISTINCT v.COMMIT_HASH 
                            FROM vulnerabilities v
                            LEFT JOIN {table_name} m ON v.COMMIT_HASH = m.COMMIT_HASH
                            WHERE m.COMMIT_HASH IS NULL
                            OR m.{column_name} IS NULL
                        """
                else:
                    # Check both VULN and PATCH columns
                    query = f"""
                        SELECT DISTINCT v.COMMIT_HASH 
                        FROM vulnerabilities v
                        LEFT JOIN {table_name} m ON v.COMMIT_HASH = m.COMMIT_HASH
                        WHERE m.COMMIT_HASH IS NULL
                        OR (
                            m.{strategy.upper()}_VULN IS NULL 
                            OR m.{strategy.upper()}_PATCH IS NULL
                            {'' if strategy == 'baseline' else f'''
                            OR m.{strategy.upper()}_REASONING_VULN IS NULL 
                            OR m.{strategy.upper()}_REASONING_PATCH IS NULL
                            '''}
                        )
                    """
                
                cursor.execute(query)
                unprocessed = [row[0] for row in cursor.fetchall()]
                
                logger.info(f"Found {len(unprocessed)} unprocessed commits for {strategy}" + 
                           (f" {column_type}" if column_type else ""))
                return unprocessed
                
        except sqlite3.Error as e:
            logger.error(f"Database error in get_unprocessed_commits: {e}")
            return []

    def complete_empty_columns(self, model_name, batch_size=10, delay=1.0, limit=None):
        """
        Find and complete empty columns in the database table for the specified model.
        
        Args:
            model_name (str): The name of the model to use for completion
            batch_size (int): Number of entries to process in a batch
            delay (float): Delay between API calls in seconds
            limit (int, optional): Limit the number of entries to process
        """
        import time
        from tqdm import tqdm
        from src.llm_interaction import LLMInteraction
        from src.config import Config
        
        logger = logging.getLogger('database_completion')
        
        # Get the table name for this model
        table_name = self.get_table_for_model(model_name)
        if not table_name:
            logger.error(f"No table found for model {model_name}")
            return
        
        logger.info(f"Using table: {table_name}")
        
        # Get incomplete rows
        incomplete_rows, strategy_columns = self.get_incomplete_rows(table_name, limit)
        logger.info(f"Found {len(incomplete_rows)} rows with incomplete data")
        
        if not incomplete_rows:
            logger.info("No incomplete rows found. Database is already complete.")
            return
        
        # Initialize LLM and Config
        llm = LLMInteraction(model_name)
        config = Config()
        
        # Process incomplete rows
        logger.info("Starting to process incomplete rows...")
        updates = []
        
        for row in tqdm(incomplete_rows, desc="Processing rows"):
            row_updates = {'COMMIT_HASH': row['COMMIT_HASH']}
            
            # Get vulnerable and patched code
            vuln_code = row.get('VULNERABLE_CODE', '')
            patch_code = row.get('PATCHED_CODE', '')
            
            if not vuln_code or not patch_code:
                logger.warning(f"Missing code for commit {row['COMMIT_HASH']}, skipping")
                continue
            
            # Process each empty column
            for col in strategy_columns:
                if row[col] is None:  # Only process NULL columns
                    # Determine code type (VULN or PATCH)
                    code_type = 'VULN' if 'VULN' in col else 'PATCH'
                    code = vuln_code if code_type == 'VULN' else patch_code
                    
                    # Get strategy name
                    if 'BASELINE' in col:
                        strategy = 'BASELINE'
                    elif 'COT' in col:
                        strategy = 'COT'
                    elif 'THINK_VERIFY' in col:
                        strategy = 'THINK_VERIFY'
                    elif 'THINK' in col:
                        strategy = 'THINK'
                    else:
                        continue
                    
                    # Check for reasoning column
                    reasoning_col = f"COT_REASONING_{code_type}" if strategy == 'COT' else None
                    
                    # Generate prompt
                    prompt = self.get_prompt_for_strategy(config, strategy, code, code_type)
                    
                    # Get response from LLM
                    try:
                        response = llm.generate(prompt)
                        
                        # Parse response to get answer and reasoning
                        answer, reasoning = self.parse_response(response, strategy)
                        
                        # Add answer to updates
                        row_updates[col] = answer
                        
                        # Add reasoning to updates if applicable
                        if reasoning_col and reasoning and row.get(reasoning_col) is None:
                            row_updates[reasoning_col] = reasoning
                        
                        # Add delay to avoid rate limiting
                        time.sleep(delay)
                    except Exception as e:
                        logger.error(f"Error processing {col} for commit {row['COMMIT_HASH']}: {e}")
            
            # Add row updates to batch
            if len(row_updates) > 1:  # More than just COMMIT_HASH
                updates.append(row_updates)
            
            # Commit batch if batch size reached
            if len(updates) >= batch_size:
                self.update_table_batch(table_name, updates)
                updates = []
        
        # Commit any remaining updates
        if updates:
            self.update_table_batch(table_name, updates)
        
        logger.info("Database completion finished successfully")

    def get_table_for_model(self, model_name):
        """Find the table associated with the selected model."""
        # Convert model name to a format used in table names
        model_identifier = model_name.replace('.', '_').replace('-', '_')
        
        cursor = self.conn.cursor()
        
        # Get all tables in the database
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        tables = [table[0] for table in tables]
        
        # Look for tables that match the model name
        matching_tables = [table for table in tables if model_identifier.lower() in table.lower()]
        
        if not matching_tables:
            return None
        
        return matching_tables[0]

    def get_incomplete_rows(self, table_name, limit=None):
        """Get rows with incomplete data."""
        cursor = self.conn.cursor()
        
        # Get all column names
        cursor.execute(f"PRAGMA table_info({table_name});")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Filter for strategy columns
        strategy_columns = [col for col in columns if any(strat in col for strat in 
                           ['BASELINE', 'COT', 'THINK', 'THINK_VERIFY'])]
        
        # Build query to find rows with at least one NULL strategy column
        conditions = " OR ".join([f"{col} IS NULL" for col in strategy_columns])
        query = f"SELECT * FROM {table_name} WHERE {conditions}"
        
        if limit:
            query += f" LIMIT {limit}"
        
        cursor.execute(query)
        rows = cursor.fetchall()
        
        # Convert to list of dictionaries
        result = []
        for row in rows:
            row_dict = {}
            for i, col in enumerate(columns):
                row_dict[col] = row[i]
            result.append(row_dict)
        
        return result, strategy_columns

    def get_prompt_for_strategy(self, config, strategy, code, code_type):
        """Get the appropriate prompt for a given strategy."""
        strategy = strategy.upper()
        
        if 'BASELINE' in strategy:
            return config.get_baseline_prompt(code, code_type)
        elif 'COT' in strategy:
            return config.get_cot_prompt(code, code_type)
        elif 'THINK_VERIFY' in strategy:
            return config.get_think_verify_prompt(code, code_type)
        elif 'THINK' in strategy:
            return config.get_think_prompt(code, code_type)
        else:
            raise ValueError(f"Unknown strategy: {strategy}")

    def parse_response(self, response, strategy):
        """Parse the response from the LLM to extract the answer and reasoning."""
        strategy = strategy.upper()
        
        # Default values
        answer = None
        reasoning = None
        
        if 'BASELINE' in strategy:
            # For baseline, just look for YES/NO
            if 'YES' in response.upper():
                answer = 1
            elif 'NO' in response.upper():
                answer = 0
        elif 'COT' in strategy:
            # For COT, extract both reasoning and answer
            reasoning = response
            if 'YES' in response.upper():
                answer = 1
            elif 'NO' in response.upper():
                answer = 0
        elif 'THINK' in strategy or 'THINK_VERIFY' in strategy:
            # For THINK strategies, extract the answer
            if 'YES' in response.upper():
                answer = 1
            elif 'NO' in response.upper():
                answer = 0
        
        return answer, reasoning

    def update_table_batch(self, table_name, updates):
        """Update a table with a batch of updates."""
        if not updates:
            return
        
        cursor = self.conn.cursor()
        
        for update in updates:
            commit_hash = update.pop('COMMIT_HASH')
            
            if not update:  # Skip if there are no columns to update
                continue
            
            # Build the SET clause
            set_clause = ", ".join([f"{col} = ?" for col in update.keys()])
            values = list(update.values())
            values.append(commit_hash)  # Add commit_hash for the WHERE clause
            
            query = f"UPDATE {table_name} SET {set_clause} WHERE COMMIT_HASH = ?"
            
            try:
                cursor.execute(query, values)
            except sqlite3.Error as e:
                logging.error(f"Error updating table {table_name}: {e}")
                raise
        
        self.conn.commit()
        logging.info(f"Updated {len(updates)} rows in {table_name}")

    def verify_saved_results(self, model_name, commit_hash, strategy=None):
        """
        Verify that results for a specific commit hash are saved in the database.
        
        Args:
            model_name (str): The name of the model
            commit_hash (str): The commit hash to check
            strategy (str, optional): The specific strategy to check
            
        Returns:
            dict: The saved data for the commit hash
        """
        # Get the table name for this model
        table_name = self.get_table_for_model(model_name)
        if not table_name:
            logger.error(f"No table found for model {model_name}")
            return None
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Get all column names
            cursor.execute(f"PRAGMA table_info({table_name});")
            columns = [column[1] for column in cursor.fetchall()]
            
            # Build query to get the row for this commit hash
            query = f"SELECT * FROM {table_name} WHERE COMMIT_HASH = ?"
            
            cursor.execute(query, (commit_hash,))
            row = cursor.fetchone()
            
            if not row:
                logger.error(f"No data found for commit {commit_hash} in table {table_name}")
                return None
            
            # Convert to dictionary
            result = {}
            for i, col in enumerate(columns):
                result[col] = row[i]
            
            # Filter for specific strategy if provided
            if strategy:
                strategy = strategy.upper()
                strategy_cols = {col: result[col] for col in result if strategy in col}
                logger.info(f"Data for commit {commit_hash}, strategy {strategy}: {strategy_cols}")
                return strategy_cols
            
            logger.info(f"All data for commit {commit_hash}: {result}")
            return result
