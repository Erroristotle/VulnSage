#!/usr/bin/env python3
"""
Database Completion Script

This script identifies and fills empty columns in the vulnerability database tables.
It processes missing entries by running the appropriate prompts for each strategy.
"""

import os
import sys
import argparse
import logging
import time
import sqlite3
from tqdm import tqdm

# Add the project root to the path so we can import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import necessary modules from the project
from src.llm_interaction import LLMInteraction
from src.database import Database
from src.config import Config
from src.utils.model_manager import ModelManager

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('database_completion.log')
    ]
)
logger = logging.getLogger('database_completion')

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Complete missing entries in the vulnerability database.')
    parser.add_argument('--model', type=str, help='Model to use for completion (e.g., llama3.1-8b)')
    parser.add_argument('--db-path', type=str, default='vulnerability_dataset/database/database.sqlite',
                        help='Path to the SQLite database')
    parser.add_argument('--batch-size', type=int, default=10, 
                        help='Number of entries to process in a batch before committing')
    parser.add_argument('--delay', type=float, default=1.0,
                        help='Delay between API calls in seconds')
    parser.add_argument('--limit', type=int, default=None,
                        help='Limit the number of entries to process (for testing)')
    return parser.parse_args()

def get_table_for_model(db_path, model_name):
    """Find the table associated with the selected model."""
    # Convert model name to a format used in table names
    model_identifier = model_name.replace('.', '_').replace('-', '_')
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get all tables in the database
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    tables = [table[0] for table in tables]
    
    # Look for tables that match the model name
    matching_tables = [table for table in tables if model_identifier.lower() in table.lower()]
    
    conn.close()
    
    if not matching_tables:
        logger.error(f"No table found for model {model_name}")
        return None
    
    if len(matching_tables) > 1:
        print(f"Multiple tables found for model {model_name}:")
        for i, table in enumerate(matching_tables, 1):
            print(f"{i}. {table}")
        
        while True:
            try:
                selection = int(input("\nSelect a table (enter number): "))
                if 1 <= selection <= len(matching_tables):
                    return matching_tables[selection-1]
                else:
                    print(f"Please enter a number between 1 and {len(matching_tables)}")
            except ValueError:
                print("Please enter a valid number")
    
    return matching_tables[0]

def get_incomplete_rows(db_path, table_name, limit=None):
    """Get rows with incomplete data."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
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
    
    conn.close()
    return result, strategy_columns

def get_prompt_for_strategy(config, strategy, code, code_type):
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

def parse_response(response, strategy):
    """Parse the LLM response to extract the answer."""
    response = response.strip()
    
    # For baseline, look for YES/NO
    if 'BASELINE' in strategy:
        if 'YES' in response.upper():
            return 1
        elif 'NO' in response.upper():
            return 0
        else:
            # Try to find the answer in the last few lines
            lines = response.split('\n')
            for line in reversed(lines):
                if 'YES' in line.upper():
                    return 1
                elif 'NO' in line.upper():
                    return 0
    
    # For other strategies, look for YES/NO in the conclusion
    else:
        if 'CONCLUSION' in response.upper():
            conclusion_part = response.upper().split('CONCLUSION')[-1]
            if 'YES' in conclusion_part:
                return 1
            elif 'NO' in conclusion_part:
                return 0
        
        # If no conclusion found, check the entire response
        if 'YES' in response.upper():
            return 1
        elif 'NO' in response.upper():
            return 0
    
    # Default fallback
    logger.warning(f"Could not parse response for strategy {strategy}. Defaulting to 1.")
    return 1

def process_incomplete_rows(db_path, table_name, model_name, incomplete_rows, strategy_columns, batch_size, delay):
    """Process rows with incomplete data."""
    # Initialize LLM interaction
    config = Config()
    llm = LLMInteraction(model_name)
    
    updates = []
    
    # Process each row
    for i, row in enumerate(tqdm(incomplete_rows, desc="Processing rows")):
        row_updates = {'COMMIT_HASH': row['COMMIT_HASH']}
        
        # Get vulnerable and patched code
        vuln_code = row.get('VULNERABLE_CODE', '')
        patch_code = row.get('PATCHED_CODE', '')
        
        if not vuln_code or not patch_code:
            logger.warning(f"Missing code for commit {row['COMMIT_HASH']}. Skipping.")
            continue
        
        # Process each missing strategy
        for col in strategy_columns:
            if row.get(col) is None:
                # Determine code type (vuln or patch)
                code_type = 'vuln' if 'VULN' in col else 'patch'
                code = vuln_code if code_type == 'vuln' else patch_code
                
                # Get strategy name
                if 'BASELINE' in col:
                    strategy = 'BASELINE'
                elif 'COT' in col:
                    strategy = 'COT'
                elif 'THINK_VERIFY' in col:
                    strategy = 'THINK_VERIFY'
                elif 'THINK' in col:
                    strategy = 'THINK'
                
                # Generate prompt
                prompt = get_prompt_for_strategy(config, strategy, code, code_type)
                
                # Get response from LLM
                try:
                    response = llm.generate(prompt)
                    
                    # Parse response to get answer
                    answer = parse_response(response, strategy)
                    
                    # Add to updates
                    row_updates[col] = answer
                    
                    # Add delay to avoid rate limiting
                    time.sleep(delay)
                except Exception as e:
                    logger.error(f"Error processing {col} for commit {row['COMMIT_HASH']}: {e}")
        
        # Add row updates to batch
        if row_updates:
            updates.append(row_updates)
        
        # Commit batch if batch size reached
        if len(updates) >= batch_size:
            update_table_batch(db_path, table_name, updates)
            updates = []
    
    # Commit any remaining updates
    if updates:
        update_table_batch(db_path, table_name, updates)

def update_table_batch(db_path, table_name, updates):
    """Update a table with a batch of updates."""
    if not updates:
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
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
            logger.error(f"Error updating table {table_name}: {e}")
            raise
    
    conn.commit()
    conn.close()
    logger.info(f"Updated {len(updates)} rows in {table_name}")

def main():
    """Main function to run the database completion script."""
    args = parse_arguments()
    
    # Select model
    model_name = args.model
    if not model_name:
        # Use ModelManager to list available models
        model_manager = ModelManager()
        available_models = model_manager.get_available_models()
        
        if not available_models:
            logger.error("No models available. Please ensure Ollama is running.")
            sys.exit(1)
        
        # Display available models
        print("Available models:")
        for i, model in enumerate(available_models, 1):
            print(f"{i}. {model}")
        
        # Get user selection
        while True:
            try:
                selection = int(input("\nSelect a model (enter number): "))
                if 1 <= selection <= len(available_models):
                    model_name = available_models[selection-1]
                    break
                else:
                    print(f"Please enter a number between 1 and {len(available_models)}")
            except ValueError:
                print("Please enter a valid number")
    
    logger.info(f"Selected model: {model_name}")
    
    # Get table for model
    table_name = get_table_for_model(args.db_path, model_name)
    if not table_name:
        sys.exit(1)
    logger.info(f"Using table: {table_name}")
    
    # Get incomplete rows
    incomplete_rows, strategy_columns = get_incomplete_rows(args.db_path, table_name, args.limit)
    logger.info(f"Found {len(incomplete_rows)} rows with incomplete data")
    
    if not incomplete_rows:
        logger.info("No incomplete rows found. Database is already complete.")
        sys.exit(0)
    
    # Process incomplete rows
    logger.info("Starting to process incomplete rows...")
    process_incomplete_rows(
        args.db_path, 
        table_name, 
        model_name, 
        incomplete_rows, 
        strategy_columns,
        args.batch_size,
        args.delay
    )
    
    logger.info("Database completion finished successfully")

if __name__ == "__main__":
    main() 