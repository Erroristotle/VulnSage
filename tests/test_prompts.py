import sqlite3
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def clear_strategies(
    db_path: str = "/home/azibaeir/Research/Benchmarking/project/vulnerability_dataset/database/database.sqlite",
    table_name: str = "vulnerabilities_codellama_7b"
):
    """Clear all COT, think, and think_verify related columns in the specified table."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # First verify the table exists
        cursor.execute(f"""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='{table_name}'
        """)
        
        if not cursor.fetchone():
            logger.error(f"Table {table_name} not found in database")
            return
            
        # Update query to set all relevant columns to NULL
        cursor.execute(f"""
            UPDATE {table_name}
            SET 
                -- COT columns
                COT_VULN = NULL,
                COT_PATCH = NULL,
                COT_REASONING_VULN = NULL,
                COT_REASONING_PATCH = NULL,
                
                -- Think columns
                THINK_VULN = NULL,
                THINK_PATCH = NULL,
                THINK_REASONING_VULN = NULL,
                THINK_REASONING_PATCH = NULL,
                
                -- Think Verify columns
                THINK_VERIFY_VULN = NULL,
                THINK_VERIFY_PATCH = NULL,
                THINK_VERIFY_REASONING_VULN = NULL,
                THINK_VERIFY_REASONING_PATCH = NULL
        """)
        
        # Commit the changes
        conn.commit()
        
        # Get count of affected rows
        affected_rows = cursor.rowcount
        logger.info(f"Successfully cleared {affected_rows} rows in {table_name}")
        
        # Verify the clearing worked
        cursor.execute(f"""
            SELECT COUNT(*) FROM {table_name}
            WHERE COT_VULN IS NOT NULL 
               OR THINK_VULN IS NOT NULL 
               OR THINK_VERIFY_VULN IS NOT NULL
        """)
        remaining = cursor.fetchone()[0]
        logger.info(f"Verification: {remaining} rows still have non-NULL values")
        
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
    except Exception as e:
        logger.error(f"Error: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    clear_strategies()