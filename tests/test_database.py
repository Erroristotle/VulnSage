import sqlite3
import os

def check_database_results(model_name: str):
    """Check the results for a specific model."""
    # Construct database path
    db_path = os.path.join("vulnerability_dataset", "output", f"database_{model_name}.sqlite")
    
    if not os.path.exists(db_path):
        print(f"Database not found at: {db_path}")
        return
        
    # Connect to database
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        
        # Get table name
        table_name = f"vulnerabilities_{model_name.replace('-', '_')}"
        
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
        cursor.execute(f"SELECT * FROM {table_name} LIMIT 5")
        rows = cursor.fetchall()
        for row in rows:
            print(row)

if __name__ == "__main__":
    model_name = "deepseek-r1-7b"  # Change this to check different models
    check_database_results(model_name)