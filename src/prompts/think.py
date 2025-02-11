import re
from typing import Optional
from .base_prompt import BasePrompt

class ThinkPrompt(BasePrompt):
    """
    Think prompt for analytical vulnerability detection.
    
    This prompt instructs the LLM to explain its analysis process in detail
    and then provide a clear final decision within a designated section.
    """
    
    def create_prompt(self, code_block: str, cwe_id: str) -> str:
        """
        Create a Think prompt that directs the LLM to perform a thorough analysis
        of the provided C code and conclude with a vulnerability assessment.
        
        The prompt includes:
         - A <thinking> section for detailed analysis.
         - A <vulnerability_assessment> section where the final decision (YES/NO)
           should be clearly stated.
        """
        return (
            f"You are a security expert analyzing C code for vulnerabilities, with a focus on **{cwe_id}**. "
            f"Use the following structured approach to determine whether this specific vulnerability is present in the code.\n\n"
            f"**<thinking>**\n"
            f"Explain your analysis process step by step:\n"
            f"* Identify potential instances of {cwe_id} in the code.\n"
            f"* Consider various attack scenarios relevant to {cwe_id}.\n"
            f"* Examine function interactions, data flows, and potential pitfalls in memory management.\n"
            f"* Validate your initial observations to rule out false positives.\n"
            f"* Document your confidence level for each finding.\n\n"
            f"**<vulnerability_assessment>**\n"
            f"Summarize your final conclusions by clearly stating whether {cwe_id} is present (YES or NO). "
            f"You may also include a brief explanation and a severity rating (Low, Medium, High, Critical).\n\n"
            f"**Code to analyze:**\n{code_block}"
        )
    
    def parse_response(self, result: str) -> Optional[int]:
        """
        Parse the LLM's response for the Think prompt.
        
        This method delegates the extraction of the final decision to the deepseek‑r1‑7b model.
        It calls the base class's parse_vulnerability() (which in turn calls llm_final_decision())
        to obtain a final single-digit answer:
          - 1 if the vulnerability is present,
          - 0 if it is not,
          - None if ambiguous.
        """
        return self.parse_vulnerability(result)