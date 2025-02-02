from abc import ABC, abstractmethod
import re
from typing import Optional, Tuple, Dict, Any

class BasePrompt(ABC):
    def __init__(self):
        self.patterns = {
            'cve': r"CVE-\d{4}-\d{4,7}",
            'cwe': r"CWE-\d{1,4}",
            'confidence': r'confidence (?:score|level|rating).*?(\d+)%',
            'severity': r'severity[:\s]*(Critical|High|Medium|Low)',
            'yes_patterns': [r'\byes\b', r'vulnerability.*(?:present|exists|found)'],
            'no_patterns': [r'\bno\b', r'no.*vulnerability.*(?:found|present)']
        }

    @abstractmethod
    def create_prompt(self, code_block: str, cwe_id: str) -> str:
        pass

    @abstractmethod
    def parse_response(self, result: str) -> Optional[int]:
        pass

    def extract_vulnerability_info(self, text: str) -> Dict[str, Any]:
        return {
            'cve_ids': re.findall(self.patterns['cve'], text),
            'cwe_ids': re.findall(self.patterns['cwe'], text),
            'confidence': self._extract_confidence(text),
            'severity': self._extract_severity(text),
            'is_vulnerable': self._check_vulnerability(text)
        }

    def _extract_confidence(self, text: str) -> Optional[float]:
        match = re.search(self.patterns['confidence'], text, re.IGNORECASE | re.DOTALL)
        return float(match.group(1)) if match else None

    def _extract_severity(self, text: str) -> Optional[str]:
        match = re.search(self.patterns['severity'], text, re.IGNORECASE)
        return match.group(1).lower() if match else None

    def _check_vulnerability(self, text: str) -> Optional[int]:
        text = text.lower()
        if any(re.search(pattern, text, re.IGNORECASE) for pattern in self.patterns['yes_patterns']):
            return 1
        if any(re.search(pattern, text, re.IGNORECASE) for pattern in self.patterns['no_patterns']):
            return 0
        return None