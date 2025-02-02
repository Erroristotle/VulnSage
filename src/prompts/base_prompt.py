from abc import ABC, abstractmethod
import re
from typing import Optional, Tuple, Dict, Any
import dspy

class VulnerabilitySignature(dspy.Signature):
    """DSPy signature for vulnerability assessment."""
    
    input = dspy.InputField(desc="Raw LLM response text")
    is_vulnerable = dspy.OutputField(desc="Whether vulnerability exists (1, 0, or None)")
    confidence = dspy.OutputField(desc="Confidence score (0-100)")
    severity = dspy.OutputField(desc="Severity rating (Critical, High, Medium, Low)")
    cwe_matches = dspy.OutputField(desc="List of CWE IDs found")
    cve_matches = dspy.OutputField(desc="List of CVE IDs found")

class BasePrompt(ABC):
    """Base class for all prompt strategies."""

    def __init__(self):
        self.patterns = {
            'cve': r"CVE-\d{4}-\d{4,7}",
            'cwe': r"CWE-\d{1,4}",
            'confidence': r'confidence (?:score|level|rating).*?(\d+)%',
            'severity': r'severity[:\s]*(Critical|High|Medium|Low)',
            'yes_patterns': [
                r'\byes\b',
                r'vulnerability.*(?:present|exists|found|detected|confirmed)',
                r'code.*(?:vulnerable|contains vulnerability)',
                r'security.*(?:issue|flaw|vulnerability).*detected'
            ],
            'no_patterns': [
                r'\bno\b',
                r'no.*vulnerability.*(?:found|detected|present)',
                r'code.*(?:safe|secure|clean)',
                r'not.*vulnerable'
            ]
        }
        # Initialize DSPy program
        self.dspy_program = dspy.Program(
            VulnerabilitySignature(),
            temperature=0.0  # Deterministic output
        )

    @abstractmethod
    def create_prompt(self, code_block: str, cwe_id: str) -> str:
        """Create a prompt for the given code block and CWE ID."""
        pass

    def parse_response(self, result: str) -> Optional[int]:
        """Parse the response using DSPy and regex fallback."""
        try:
            # Try DSPy first
            assessment = self.dspy_program(input=result)
            if assessment.is_vulnerable is not None:
                return assessment.is_vulnerable
        except Exception as e:
            print(f"DSPy parsing failed, falling back to regex: {e}")

        # Fallback to regex
        return self.check_vulnerability_presence(result)

    def extract_vulnerability_info(self, text: str) -> Tuple[list, list]:
        """Extract CVE and CWE IDs using DSPy and regex fallback."""
        try:
            assessment = self.dspy_program(input=text)
            cve_names = assessment.cve_matches
            cwe_names = assessment.cwe_matches
            if cve_names and cwe_names:
                return cve_names, cwe_names
        except Exception:
            pass

        # Fallback to regex
        cve_names = re.findall(self.patterns['cve'], text)
        cwe_names = re.findall(self.patterns['cwe'], text)
        return cve_names, cwe_names

    def extract_confidence_and_severity(self, text: str) -> Dict[str, Any]:
        """Extract confidence and severity using DSPy."""
        try:
            assessment = self.dspy_program(input=text)
            return {
                'confidence': assessment.confidence,
                'severity': assessment.severity.lower() if assessment.severity else None
            }
        except Exception as e:
            # Fallback to regex
            return {
                'confidence': self._extract_confidence_regex(text),
                'severity': self._extract_severity_regex(text)
            }

    def _extract_confidence_regex(self, text: str) -> Optional[float]:
        """Regex fallback for confidence extraction."""
        match = re.search(self.patterns['confidence'], text, re.IGNORECASE | re.DOTALL)
        if match:
            return float(match.group(1))
        return None

    def _extract_severity_regex(self, text: str) -> Optional[str]:
        """Regex fallback for severity extraction."""
        match = re.search(self.patterns['severity'], text, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        return None

    def check_vulnerability_presence(self, text: str) -> Optional[int]:
        """Check vulnerability presence using regex patterns."""
        text = text.lower()
        
        for pattern in self.patterns['yes_patterns']:
            if re.search(pattern, text, re.IGNORECASE):
                return 1
        
        for pattern in self.patterns['no_patterns']:
            if re.search(pattern, text, re.IGNORECASE):
                return 0
                
        return None

    def get_full_assessment(self, text: str) -> Dict[str, Any]:
        """Get comprehensive assessment using DSPy and regex fallbacks."""
        try:
            assessment = self.dspy_program(input=text)
            return {
                'is_vulnerable': assessment.is_vulnerable,
                'confidence': assessment.confidence,
                'severity': assessment.severity,
                'cve_ids': assessment.cve_matches,
                'cwe_ids': assessment.cwe_matches
            }
        except Exception as e:
            print(f"DSPy assessment failed, using regex fallbacks: {e}")
            cve_names, cwe_names = self.extract_vulnerability_info(text)
            confidence_severity = self.extract_confidence_and_severity(text)
            return {
                'is_vulnerable': self.check_vulnerability_presence(text),
                'confidence': confidence_severity['confidence'],
                'severity': confidence_severity['severity'],
                'cve_ids': cve_names,
                'cwe_ids': cwe_names
            }