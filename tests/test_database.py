import sqlite3
import os

def check_database_results(model_name: str, db_path: str = "vulnerability_dataset/database/database.sqlite"):
    """Check the results for a specific model in the main database."""
    if not os.path.exists(db_path):
        print(f"Database not found at: {db_path}")
        return
        
    # Connect to database
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        
        # Get table name
        table_name = f"vulnerabilities_{model_name.replace('-', '_')}"
        
        # Check if table exists
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name=?
        """, (table_name,))
        
        if not cursor.fetchone():
            print(f"Table {table_name} not found in database")
            return
        
        # Print table schema
        cursor.execute(f"SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
        schema = cursor.fetchone()
        print(f"\nTable Schema:\n{schema[0]}")
        
        # Get total number of rows
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        total_rows = cursor.fetchone()[0]
        print(f"\nTotal rows in table: {total_rows}")
        
        # Get counts for each column
        columns = ['BASELINE_VULN', 'BASELINE_PATCH', 'COT_VULN', 'COT_PATCH', 
                  'THINK_VULN', 'THINK_PATCH', 'THINK_VERIFY_VULN', 'THINK_VERIFY_PATCH']
        
        print("\nResults by column:")
        for col in columns:
            cursor.execute(f"SELECT COUNT(*) FROM {table_name} WHERE {col} IS NOT NULL")
            count = cursor.fetchone()[0]
            cursor.execute(f"SELECT COUNT(*) FROM {table_name} WHERE {col} = 1")
            positive = cursor.fetchone()[0]
            cursor.execute(f"SELECT COUNT(*) FROM {table_name} WHERE {col} = 0")
            negative = cursor.fetchone()[0]
            print(f"\n{col}:")
            print(f"  Total results: {count}")
            print(f"  Positive (1): {positive}")
            print(f"  Negative (0): {negative}")
            
        # Show sample results
        print("\nSample results (first 5 rows):")
        cursor.execute(f"""
            SELECT v.COMMIT_HASH, v.VULNERABILITY_CWE, 
                   t.BASELINE_VULN, t.BASELINE_PATCH
            FROM vulnerabilities v
            LEFT JOIN {table_name} t ON v.COMMIT_HASH = t.COMMIT_HASH
            WHERE t.BASELINE_VULN IS NOT NULL
            LIMIT 5
        """)
        rows = cursor.fetchall()
        for row in rows:
            print(f"Commit: {row[0]}")
            print(f"CWE: {row[1]}")
            print(f"Baseline Vulnerable: {row[2]}")
            print(f"Baseline Patched: {row[3]}")
            print("-" * 50)

if __name__ == "__main__":
    model_name = "deepseek-r1-7b"  # Change this to check different models
    check_database_results(model_name)