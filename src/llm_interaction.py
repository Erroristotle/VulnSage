import requests
import time
from typing import Optional, List, Dict
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
        """Send a single prompt to the model and get a response."""
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

    def query_model_batch(self, prompts: List[str], max_retries: int = 3, retry_delay: int = 2) -> Optional[List[str]]:
        """
        Send a batch of prompts to the model and return a list of responses.
        This implementation assumes that your API accepts a JSON payload with a key 'prompts'.
        """
        payload = {
            "model": Config.get_model_command(self.model_name),
            "prompts": prompts
        }

        for attempt in range(max_retries):
            try:
                response = requests.post(Config.API_URL, json=payload)
                if response.status_code == 200:
                    # Try to parse the response as a JSON list.
                    try:
                        responses = response.json()  # expecting a list of response objects
                        # Extract the "response" field from each item.
                        return [item["response"] for item in responses]
                    except Exception:
                        # Fallback: assume newline-separated JSON objects.
                        lines = response.content.decode('utf-8').splitlines()
                        return [
                            json.loads(line)["response"] 
                            for line in lines if line
                        ]
                elif response.status_code == 503:
                    print(f"Model loading, retry in {retry_delay}s...")
                time.sleep(retry_delay)
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(retry_delay)
        return None

    def detection(self, commit_hash: str, code_block: str, cwe_id: str, 
                  is_vulnerable: bool, strategy: str = "baseline") -> None:
        """Run vulnerability detection with specified strategy (single query)."""
        prompt = self.strategies[strategy].create_prompt(code_block, cwe_id)
        result = self.query_model(prompt)
        
        table_name = f"vulnerabilities_{self.model_name}"
        print(f"Storing result in table: {table_name}")
        if result:
            status = self.strategies[strategy].parse_response(result)
            if status is not None:
                column = f"{strategy.upper()}_{'VULN' if is_vulnerable else 'PATCH'}"
                print(f"Storing result {status} for commit {commit_hash} in column {column}")
                # Get full assessment
                assessment = self.strategies[strategy].get_full_assessment(result)
                
                if assessment['is_vulnerable'] is not None:
                    # Store comprehensive results
                    with sqlite3.connect(self.db_file) as conn:
                        cursor = conn.cursor()
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

    def batch_detection(self, inputs: List[Dict], strategy: str = "baseline",
                        max_retries: int = 3, retry_delay: int = 2) -> None:
        """
        Process a batch of vulnerability detection requests in one API call.
        
        Each item in `inputs` should be a dictionary with keys:
            - commit_hash
            - code_block
            - cwe_id
            - is_vulnerable
        
        The method creates prompts for each input using the specified strategy,
        sends them as a batch to the model, and processes each response.
        """
        # Build the list of prompts and record metadata for each input.
        prompts = []
        metadata_list = []  # Each element will be a dict with commit_hash and is_vulnerable.
        for item in inputs:
            prompt = self.strategies[strategy].create_prompt(item["code_block"], item["cwe_id"])
            prompts.append(prompt)
            metadata_list.append({
                "commit_hash": item["commit_hash"],
                "is_vulnerable": item["is_vulnerable"]
            })
        
        # Send all prompts in one batch.
        responses = self.query_model_batch(prompts, max_retries, retry_delay)
        if responses is None:
            print("Batch query failed")
            return

        table_name = f"vulnerabilities_{self.model_name}"
        # Process each response in order.
        for metadata, response in zip(metadata_list, responses):
            commit_hash = metadata["commit_hash"]
            is_vulnerable = metadata["is_vulnerable"]
            status = self.strategies[strategy].parse_response(response)
            if status is not None:
                # Get full assessment
                assessment = self.strategies[strategy].get_full_assessment(response)
                if assessment['is_vulnerable'] is not None:
                    column = f"{strategy.upper()}_{'VULN' if is_vulnerable else 'PATCH'}"
                    print(f"Storing result {assessment['is_vulnerable']} for commit {commit_hash} in column {column}")
                    with sqlite3.connect(self.db_file) as conn:
                        cursor = conn.cursor()
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
