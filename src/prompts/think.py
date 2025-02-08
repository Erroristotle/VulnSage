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
        Parse the Think prompt response to determine if the vulnerability is present.
        
        The parsing process follows these steps:
          1. Normalize the response text using inherited normalization.
          2. Apply the core vulnerability parsing logic from BasePrompt.
          3. Look explicitly for the <vulnerability_assessment> section and extract a decision.
          4. As a fallback, scan the overall response for concluding phrases.
        
        Returns:
            1 if the vulnerability is detected,
            0 if it is not,
            or None if the response is inconclusive.
        """
        normalized = self._normalize_text(result)
        
        # Step 1: Try using the core parsing logic from BasePrompt.
        base_result = self.parse_vulnerability(normalized)
        if base_result is not None:
            return base_result
        
        # Step 2: Look for a dedicated vulnerability assessment section.
        assessment_match = re.search(r'<vulnerability_assessment>\s*(.*)', normalized, re.DOTALL)
        if assessment_match:
            assessment_text = assessment_match.group(1)
            if re.search(r'\byes\b', assessment_text):
                return 1
            if re.search(r'\bno\b', assessment_text):
                return 0
        
        # Step 3: Fallback - Check for concluding phrases in the overall text.
        if re.search(r'(?:vulnerability present|found vulnerability|vulnerable)', normalized):
            return 1
        if re.search(r'(?:no vulnerability|not present|secure|safe)', normalized):
            return 0
        
        return None
