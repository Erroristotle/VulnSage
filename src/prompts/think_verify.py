import re
from typing import Optional
from .base_prompt import BasePrompt

class ThinkVerifyPrompt(BasePrompt):
    """Think & Verify prompt for thorough vulnerability detection."""

    def create_prompt(self, code_block: str, cwe_id: str) -> str:
        """Create a Think & Verify prompt for in-depth vulnerability analysis."""
        return f"""You are a security expert conducting an **in-depth vulnerability assessment** focused on **{cwe_id}**. Follow these structured steps to determine whether this specific vulnerability is present in the given C code.

**1. Initial Analysis (Up to 3 Attempts)**
**<thinking>**
* Examine the code structure for potential {cwe_id} instances.
* Identify coding patterns that could introduce {cwe_id}.
* Consider attack vectors and real-world exploitation related to this vulnerability.
* Document any uncertainties or doubts regarding the presence of {cwe_id}.

**<findings>**
* List occurrences of {cwe_id} with supporting evidence from the code.

**<confidence>**
* Assign a confidence score (0–100%) for each {cwe_id} finding.
* If confidence is **=90%**, proceed to verification.
* If confidence is **<90%**, reanalyze the code before verification.

**2. Verification (Required for High-Confidence Findings)**
**<verification>**
* Validate each identified instance of {cwe_id}.
* Check for false positives and confirm its exploitability.
* Ensure accurate vulnerability classification.
* Consider edge cases and uncommon attack scenarios.

**3. Final Assessment**
**<assessment>**
* Provide a final list of verified **{cwe_id}** vulnerabilities.
* Map each finding to {cwe_id} and justify its classification.
* Assign severity ratings (**Low, Medium, High, Critical**).
* Recommend security fixes or mitigations specifically for {cwe_id}.

**Code to analyze:**
{code_block}"""

    def parse_response(self, result: str) -> Optional[int]:
        """Parse response looking for confidence score and final assessment."""
        confidence_match = re.search(r'confidence score.*?(\d+)%', 
                                   result, re.IGNORECASE | re.DOTALL)
        assessment_match = re.search(r'<assessment>.*?(verified.*?vulnerabilities).*?</assessment>', 
                                   result, re.IGNORECASE | re.DOTALL)
        
        if confidence_match and assessment_match:
            confidence = int(confidence_match.group(1))
            assessment = assessment_match.group(1).lower()
            
            if confidence >= 90 and ('verified' in assessment and 'vulnerabilit' in assessment):
                return 1
            elif confidence >= 90:
                return 0
        
        return None