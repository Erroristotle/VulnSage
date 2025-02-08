from abc import ABC, abstractmethod
import re
from typing import Optional, Dict, Any

class BasePrompt(ABC):
    """Base class for all prompt types with common parsing utilities."""
    
    def __init__(self):
        # Core patterns for determining vulnerability (case-insensitive matching)
        self.patterns = {
            'positive': [
                r'\b1\b',
                r'\byes\b',
                r'has a vulnerability',
                r'is vulnerable',
                r'contains a vulnerability',
                r'has a security issue',
                r'has a security vulnerability',
                r'has a security flaw',
                r'the code has the',
                r'found a vulnerability',
                r'the code has vulnerabilities associated with',
                r'vulnerability you are looking for is likely related to',
                r'is vulnerable to',
                r'vulnerability associated with cve and cwe that i can identify is',
                r'found a potential vulnerability associated with',
                r'the code contains the',
                r'the code has the',
                r'it appears to be vulnerable to',
                r"the specific vulnerability you're asking about is",
                r'code appears to be vulnerable to',
                r'i can identify a potential vulnerability',
                r'provided c code has a specific cwe vulnerability',
                r'code has the following cwe vulnerability',
                r'code is associated with the following cve and cwe'
            ],
            'negative': [
                r'\b0\b',
                r'\bno\b',
                r'does not have a vulnerability',
                r'does not contain',
                r'is not vulnerable',
                r'does not have a security issue',
                r'does not have a security vulnerability',
                r'does not have a security flaw',
                r'the code does not have the',
                r'the code does not contain the',
                r'the code does not have a',
                r'the code does not contain a',
                r'the code does not have an',
                r'the code does not contain an',
                r'the code does not have any',
                r'the code does not contain any',
                r'the code does not have',
                r'the code does not contain',
                r'the code does not',
                r"it doesn't appear to have a specific",
                r'cwe-\d+ is not present',
                r'cwe-\d+ not present',
                r'cwe-\d+ is not found',
                r'cwe-\d+ not found',
                r'cwe-\d+ is not in the code'
            ]
        }
        
        # Patterns for extracting additional security info from responses
        self.info_patterns = {
            'cve': r"CVE-\d{4}-\d{4,7}",
            'cwe': r"CWE-\d{1,4}",
            'confidence': r'confidence (?:score|level|rating).*?(\d+)%',
            'severity': r'severity[:\s]*(Critical|High|Medium|Low)'
        }
        
        # Indicators to help detect if a matching phrase is negated by context
        self.negation_indicators = [
            'not', 'no', "doesn't", 'does not', 'cannot', "can't",
            'unable', 'lack', 'missing', 'without', 'absence'
        ]
    
    def _normalize_text(self, text: str) -> str:
        """
        Normalize the response text by lowercasing, removing markdown formatting,
        and condensing whitespace. This improves the robustness of our regex matching.
        """
        normalized = text.lower().strip()
        # Remove common markdown artifacts (e.g., asterisks)
        normalized = re.sub(r'\*+', '', normalized)
        normalized = re.sub(r'\s+', ' ', normalized)
        return normalized
    
    def _check_negative_context(self, text: str, match_start: int) -> bool:
        """
        Check whether a detected positive match is negated by nearby context.
        Looks at a window of 50 characters before the match.
        """
        context = text[max(0, match_start - 50):match_start]
        return any(neg in context for neg in self.negation_indicators)
    
    def extract_security_info(self, text: str) -> Dict[str, Any]:
        """
        Extract additional security information such as CVE IDs, CWE IDs,
        confidence score, and severity rating from the response.
        """
        return {
            'cve_ids': re.findall(self.info_patterns['cve'], text),
            'cwe_ids': re.findall(self.info_patterns['cwe'], text),
            'confidence': self._extract_confidence(text),
            'severity': self._extract_severity(text)
        }
    
    def _extract_confidence(self, text: str) -> Optional[float]:
        """Extract a confidence score from the text if available."""
        match = re.search(self.info_patterns['confidence'], text, re.IGNORECASE)
        return float(match.group(1)) if match else None
    
    def _extract_severity(self, text: str) -> Optional[str]:
        """Extract a severity rating (e.g., Critical, High, Medium, Low) from the text if available."""
        match = re.search(self.info_patterns['severity'], text, re.IGNORECASE)
        return match.group(1).lower() if match else None
    
    @abstractmethod
    def create_prompt(self, code_block: str, cwe_id: str) -> str:
        """
        Generate the prompt to be sent to the LLM.
        Each subclass should tailor the prompt to its specific strategy.
        """
        pass
    
    @abstractmethod
    def parse_response(self, result: str) -> Optional[int]:
        """
        Parse the LLM response and return:
          - 1 if the response indicates the vulnerability is present,
          - 0 if the response indicates it is not present,
          - None if the response is inconclusive.
        """
        pass
    
    def parse_vulnerability(self, result: str) -> Optional[int]:
        """
        Core vulnerability parsing logic used by all prompt strategies.
        
        The method follows these steps:
          1. Normalize the response text.
          2. Look for a simple, formatted answer (e.g., "1. Vulnerability Present? YES").
          3. Attempt to extract a "final decision" section (e.g., marked by "final decision" or
             embedded tags like <assessment> or <vulnerability_assessment>) and look for clear positive
             or negative indicators.
          4. As a fallback, scan the entire text for any shared negative patterns (which take precedence)
             and then for positive patterns (checking nearby context to avoid false positives).
          5. If no clear decision is found, return None.
        """
        normalized = self._normalize_text(result)
        
        # Step 1: Look for a simple formatted answer at the very start.
        simple_match = re.search(r'^1\.\s*vulnerability present\?\s*(yes|no)\b', normalized)
        if simple_match:
            return 1 if simple_match.group(1) == 'yes' else 0
        
        # Step 2: Try to extract a final decision section from longer responses.
        final_decision_match = re.search(r'(?:final decision|<assessment>|<vulnerability_assessment>)\s*:?\s*(.*)', normalized, re.DOTALL)
        if final_decision_match:
            decision_text = final_decision_match.group(1)
            if re.search(r'(?:no vulnerability|not present|secure|safe)', decision_text):
                return 0
            if re.search(r'(?:vulnerability present|found vulnerability|vulnerable)', decision_text):
                return 1
        
        # Step 3: Fallback to scanning for negative patterns.
        for pattern in self.patterns['negative']:
            if re.search(pattern, normalized):
                return 0
        
        # Step 4: Fallback to scanning for positive patterns with context check.
        for pattern in self.patterns['positive']:
            m = re.search(pattern, normalized)
            if m and not self._check_negative_context(normalized, m.start()):
                return 1
        
        # No clear decision could be made.
        return None
