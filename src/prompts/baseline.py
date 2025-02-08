from .base_prompt import BasePrompt
from typing import Optional
import re

class BaselinePrompt(BasePrompt):
    def create_prompt(self, code_block: str, cwe_id: str) -> str:
        """
        Create a prompt that instructs the LLM to only output "YES" or "NO" with no extra commentary.
        """
        return (
            f"You are a security expert specializing in identifying software vulnerabilities in C code.\n\n"
            f"Analyze the following code and determine **only** whether it contains a **{cwe_id}** vulnerability.\n\n"
            f"**Code to analyze:**\n{code_block}\n\n"
            f"Provide your response in **exactly** the following format:\n"
            f"YES or NO\n\n"
            f"**Do not provide any explanation or additional details.**"
        )
    
    def parse_response(self, result: str) -> Optional[int]:
        """
        Parse the LLM's response for the baseline prompt.

        This method strictly filters the response to detect either "YES" or "NO" (case-insensitive).
        - If the response is exactly "yes" or "no" (or contains a line that is exactly "yes" or "no"),
          it returns 1 for "yes" and 0 for "no".
        - If no clear decision can be made, the entire raw response is stored in an instance attribute
          (`self.last_raw_response`) for further inspection, and None is returned.
        """
        normalized = result.strip().lower()
        
        # Check for an exact match.
        if normalized == "yes":
            return 1
        if normalized == "no":
            return 0
        
        # Check each line in case the response spans multiple lines.
        lines = normalized.splitlines()
        for line in lines:
            line = line.strip()
            if line == "yes":
                return 1
            if line == "no":
                return 0
        
        # Alternatively, search for a whole-word match.
        yes_match = re.search(r'\byes\b', normalized)
        no_match = re.search(r'\bno\b', normalized)
        if yes_match and not no_match:
            return 1
        if no_match and not yes_match:
            return 0
        
        # If no clear YES/NO decision is found, save the raw response for review.
        self.last_raw_response = result
        return None
