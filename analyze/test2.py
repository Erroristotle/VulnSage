import sqlite3

def add_columns_to_database(db_path, table_name):
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # List of new columns to add
        new_columns = [
            ("VULNERABILITY_YEAR", "INTEGER"),
            ("VULNERABILITY_CATEGORY", "TEXT"),
            ("DESCRIPTION_IN_PATCH", "TEXT")
        ]

        # Add each column if it does not already exist
        for column, data_type in new_columns:
            try:
                cursor.execute(f"""
                    ALTER TABLE {table_name} ADD COLUMN {column} {data_type}
                """)
            except sqlite3.OperationalError:
                print(f"Column {column} might already exist in {table_name}.")

        # Commit changes and close connection
        conn.commit()
        print("Columns added successfully.")
    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
    finally:
        conn.close()

# Usage example
if __name__ == "__main__":
    database_path = "/users/azibaeir/Research/Benchmarking/project/vulnerability_dataset/database/2025_database.sqlite"  # Path to your SQLite database
    table_name = "vulnerabilities"  # Replace with your actual table name
    add_columns_to_database(database_path, table_name)
