import re
from typing import Optional
from .base_prompt import BasePrompt

class ThinkVerifyPrompt(BasePrompt):
    """
    Think & Verify prompt for thorough vulnerability detection.
    
    In this prompt, the LLM is instructed to:
      1. Perform an initial analysis (the "thinking" phase) to identify potential instances of the vulnerability.
      2. List its findings along with a confidence score in a dedicated section.
      3. Validate high-confidence findings through a verification phase.
      4. Conclude with a final assessment (in an <assessment> section) that clearly states YES (vulnerable) or NO (not vulnerable).
    """
    
    def create_prompt(self, code_block: str, cwe_id: str) -> str:
        return (
            f"You are a security expert conducting an in-depth vulnerability assessment focused on **{cwe_id}**. "
            f"Follow these structured steps to determine whether this specific vulnerability is present in the given C code.\n\n"
            f"**1. Initial Analysis (Up to 3 Attempts)**\n"
            f"**<thinking>**\n"
            f"* Examine the code structure for potential {cwe_id} instances.\n"
            f"* Identify coding patterns that could introduce {cwe_id}.\n"
            f"* Consider attack vectors and real-world exploitation scenarios related to {cwe_id}.\n"
            f"* Document any uncertainties or doubts regarding the presence of {cwe_id}.\n\n"
            f"**<findings>**\n"
            f"* List occurrences of {cwe_id} with supporting evidence from the code.\n\n"
            f"**<confidence>**\n"
            f"* Assign a confidence score (0-100%) to each identified instance of {cwe_id}.\n"
            f"* If confidence is >=90%, proceed to verification; otherwise, reanalyze the code.\n\n"
            f"**2. Verification (Required for High-Confidence Findings)**\n"
            f"**<verification>**\n"
            f"* Validate each identified instance of {cwe_id}.\n"
            f"* Check for false positives and confirm exploitability.\n"
            f"* Consider edge cases and uncommon scenarios.\n\n"
            f"**3. Final Assessment**\n"
            f"**<assessment>**\n"
            f"* Provide a final, verified list of {cwe_id} vulnerabilities.\n"
            f"* Map each finding to {cwe_id} and justify its classification.\n"
            f"* Assign a severity rating (Low, Medium, High, Critical).\n"
            f"* Optionally, recommend specific security fixes or mitigations.\n\n"
            f"**Code to analyze:**\n{code_block}"
        )
    
    def parse_response(self, result: str) -> Optional[int]:
        """
        Parse the LLM's response for the Think & Verify prompt.
        
        This method delegates the extraction of the final decision to the deepseek‑r1‑7b model,
        by calling the base class's parse_vulnerability() (which calls llm_final_decision()).
        
        Returns:
            1 if the vulnerability is confirmed,
            0 if it is not,
            or None if the decision is ambiguous.
        """
        return self.parse_vulnerability(result)
