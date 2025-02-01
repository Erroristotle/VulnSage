import re
from typing import Optional
from .base_prompt import BasePrompt

class ThinkPrompt(BasePrompt):
    """Think prompt for analytical vulnerability detection."""

    def create_prompt(self, code_block: str, cwe_id: str) -> str:
        """Create a Think prompt for vulnerability analysis."""
        return f"""You are a security expert analyzing C code for vulnerabilities, with a focus on **{cwe_id}**. Use the following structured approach to determine whether this specific vulnerability is present in the code.

**<thinking>**
Explain your analysis process step by step:
* Identify potential instances of {cwe_id} as you read the code.
* Consider different attack scenarios relevant to {cwe_id}.
* Examine function interactions and data flows that may contribute to this vulnerability.
* Question assumptions about input validation, memory management, and user input handling.
* Verify initial findings and rule out false positives.
* Document confidence levels in each identified issue.

**<vulnerability_assessment>**
Summarize your conclusions, including:
* Presence of {cwe_id} (Yes/No)
* Explanation of how {cwe_id} manifests in this code (if applicable).
* Severity rating (Low, Medium, High, Critical).
* Relevant evidence from the code that supports the assessment.

**Code to analyze:**
{code_block}"""

    def parse_response(self, result: str) -> Optional[int]:
        """Parse response looking for vulnerability assessment conclusion."""
        assessment = re.search(r'<vulnerability_assessment>.*?Presence of.*?(\bYES\b|\bNO\b)', 
                             result, re.IGNORECASE | re.DOTALL)
        if assessment:
            if 'YES' in assessment.group(1).upper():
                return 1
            elif 'NO' in assessment.group(1).upper():
                return 0
        return None