import sqlite3
from typing import List, Optional, Tuple
from contextlib import contextmanager
from .models import VulnerabilityData

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
                       VULNERABILITY_CWE, VULNERABILITY_YEAR, description_in_patch
                FROM vulnerabilities
            """)
            return [
                VulnerabilityData(
                    commit_hash=row[0],
                    vulnerable_code=row[1],
                    patched_code=row[2],
                    cwe_id=row[3],
                    year=row[4],
                    description=row[5]
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

    def get_unprocessed_commits(self, model_name: str, strategy: str) -> List[str]:
        """Get list of commits that haven't been processed for given strategy."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            table_name = f"vulnerabilities_{model_name}"
            cursor.execute(f"""
                SELECT v.COMMIT_HASH
                FROM vulnerabilities v
                LEFT JOIN {table_name} m ON v.COMMIT_HASH = m.COMMIT_HASH
                WHERE m.{strategy.upper()}_VULN IS NULL
                   OR m.{strategy.upper()}_PATCH IS NULL
            """)
            return [row[0] for row in cursor.fetchall()]