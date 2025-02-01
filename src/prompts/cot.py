import re
from typing import Optional
from .base_prompt import BasePrompt

class ChainOfThoughtPrompt(BasePrompt):
    """Chain of Thought prompt for detailed vulnerability analysis."""

    def create_prompt(self, code_block: str, cwe_id: str) -> str:
        """Create a Chain of Thought prompt for structured analysis."""
        return f"""You are a security expert specializing in vulnerability detection, with a focus on **{cwe_id}**. Your task is to analyze the following C code using a structured approach to determine whether it contains this specific vulnerability.

Your analysis should **clearly explain whether {cwe_id} is present or not** by reasoning through the code step by step.

**Step-by-step analysis:**
1. **Code Structure Analysis:**
   * Identify key components (functions, loops, conditionals, memory operations).
   * Trace the data flow and control flow to locate relevant sections.
   * Determine areas where {cwe_id} might arise.

2. **{cwe_id} Pattern Matching & Risk Assessment:**
   * Identify coding patterns that match known causes of {cwe_id}.
   * Examine how data is processed, stored, and validated.
   * Determine whether unsafe functions or insecure coding practices contribute to this vulnerability.

3. **Exploitability & Security Impact:**
   * Assess whether an attacker could exploit {cwe_id} in this code.
   * Identify potential attack vectors and their impact.
   * Consider edge cases, user input handling, and memory management concerns.

4. **Final Decision ({cwe_id} Present or Not):**
   * **If {cwe_id} exists**, explain why and how it can be exploited. Provide an example scenario if possible.
   * **If the code is safe from {cwe_id}**, justify why no major security risks exist.

5. **Suggested Security Improvements:**
   * If applicable, suggest mitigations to eliminate {cwe_id}.
   * Provide best practices and alternative coding techniques.

**Code to analyze:**
{code_block}"""

    def parse_response(self, result: str) -> Optional[int]:
        """Parse response looking for final decision conclusion."""
        if re.search(r'Final Decision.*exists|present|found|detected|identified', result, re.IGNORECASE | re.DOTALL):
            return 1
        elif re.search(r'Final Decision.*safe|not present|no.*vulnerability', result, re.IGNORECASE | re.DOTALL):
            return 0
        return None