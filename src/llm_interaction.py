import requests
import time
from typing import Optional
from .prompts import BaselinePrompt, ChainOfThoughtPrompt, ThinkPrompt, ThinkVerifyPrompt
from .config import Config
import json
import sqlite3

class LLMInteraction:
    def __init__(self, db_file: str, model_name: str):
        self.db_file = db_file
        self.model_name = model_name
        self.strategies = {
            "baseline": BaselinePrompt(),
            "cot": ChainOfThoughtPrompt(),
            "think": ThinkPrompt(),
            "think_verify": ThinkVerifyPrompt()
        }

    def query_model(self, prompt: str, max_retries: int = 3, retry_delay: int = 2) -> Optional[str]:
        """Send prompt to the model and get response."""
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

    def detection(self, commit_hash: str, code_block: str, cwe_id: str, 
                 is_vulnerable: bool, strategy: str = "baseline") -> None:
        """Run vulnerability detection with specified strategy."""
        prompt = self.strategies[strategy].create_prompt(code_block, cwe_id)
        result = self.query_model(prompt)
        
        table_name = f"vulnerabilities_{self.model_name}"
        print(f"Storing result in table: {table_name}")
        if result:
            status = self.strategies[strategy].parse_response(result)
            if status is not None:
                print(f"Storing result {status} for commit {commit_hash} in column {column}")
                # Get full assessment
                assessment = self.strategies[strategy].get_full_assessment(result)
                
                if assessment['is_vulnerable'] is not None:
                    # Store comprehensive results
                    with sqlite3.connect(self.db_file) as conn:
                        cursor = conn.cursor()
                        table_name = f"vulnerabilities_{self.model_name}"
                        
                        # Update base column
                        column = f"{strategy.upper()}_{'VULN' if is_vulnerable else 'PATCH'}"
                        cursor.execute(f"""
                            INSERT OR REPLACE INTO {table_name}
                            (COMMIT_HASH, {column}, 
                            {column}_CONFIDENCE, 
                            {column}_SEVERITY,
                            {column}_CVE_MATCHES,
                            {column}_CWE_MATCHES)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (
                            commit_hash,
                            assessment['is_vulnerable'],
                            assessment['confidence'],
                            assessment['severity'],
                            ','.join(assessment['cve_ids']),
                            ','.join(assessment['cwe_ids'])
                        ))
                        conn.commit()