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
        Parse the Think & Verify prompt response to determine whether the vulnerability is present.
        
        The parsing strategy is as follows:
          1. Normalize the response text.
          2. Attempt the core vulnerability detection using the inherited logic.
          3. Look explicitly for a final decision in the <assessment> section.
          4. If not clearly labeled, fallback to checking the <verification> section and then overall text.
          5. Optionally, use any provided confidence scores as additional indicators.
        
        Returns:
            1 if the vulnerability is confirmed,
            0 if it is not,
            or None if the response is inconclusive.
        """
        normalized = self._normalize_text(result)
        
        # Step 1: Use the core parsing logic from BasePrompt.
        base_result = self.parse_vulnerability(normalized)
        if base_result is not None:
            return base_result
        
        # Step 2: Look for an <assessment> section with a clear decision.
        assessment_match = re.search(r'<assessment>\s*(.*)', normalized, re.DOTALL)
        if assessment_match:
            assessment_text = assessment_match.group(1)
            if re.search(r'\b(yes|vulnerable|present)\b', assessment_text):
                return 1
            if re.search(r'\b(no|not present|secure|safe)\b', assessment_text):
                return 0
        
        # Step 3: If <assessment> is not found, check the <verification> section.
        verification_match = re.search(r'<verification>\s*(.*)', normalized, re.DOTALL)
        if verification_match:
            verification_text = verification_match.group(1)
            if re.search(r'\b(confirmed|verified)\b', verification_text):
                return 1
            if re.search(r'\b(no vulnerability|not found|clean)\b', verification_text):
                return 0
        
        # Step 4: Fallback: scan the overall text for concluding phrases.
        if re.search(r'(?:vulnerability present|found vulnerability|exists)', normalized):
            return 1
        if re.search(r'(?:no vulnerability|not present|secure|safe)', normalized):
            return 0
        
        # Step 5: Optionally, check for a confidence score indicator.
        confidence_match = re.search(r'confidence (?:score|level|rating).*?(\d+)%', normalized)
        if confidence_match:
            confidence = int(confidence_match.group(1))
            if confidence >= 90:
                # If high confidence and text includes verification keywords, assume vulnerability is confirmed.
                if re.search(r'verified', normalized):
                    return 1
                if re.search(r'no vulnerability', normalized):
                    return 0
        
        # If no clear decision is extracted, return None.
        return None
