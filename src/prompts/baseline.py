from .base_prompt import BasePrompt
from typing import Optional

class BaselinePrompt(BasePrompt):
    def create_prompt(self, code_block: str, cwe_id: str) -> str:
        return f"""You are a security expert specializing in identifying software vulnerabilities in C code.

Analyze the following code and determine **only** whether it contains a **{cwe_id}** vulnerability.

**Code to analyze:**
{code_block}

Provide your response in **exactly** the following format:
1. **Vulnerability Present?** (YES or NO)

**Do not provide any explanation or additional details.**"""

    def parse_response(self, result: str) -> Optional[int]:
        if 'YES' in result.upper():
            return 1
        elif 'NO' in result.upper():
            return 0
        return None