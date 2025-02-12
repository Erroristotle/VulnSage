from abc import ABC, abstractmethod
import json
import logging
import requests
from typing import Optional, Dict, Any
from ..config import Config

logger = logging.getLogger(__name__)

class BasePrompt(ABC):
    """
    Base class for all prompt types with common parsing utilities.
    
    This version delegates the extraction of the final decision to the benchmarking LLM 
    (using the provided model command) rather than relying on regex.
    The final decision is obtained by sending the complete response to the LLM 
    with a prompt that asks for a single-digit answer.
    """
    
    def __init__(self, model_command: Optional[str] = None):
        """
        Initialize the prompt with a model command.
        
        The model_command is expected to be provided from the user‐selection.
        """
        if model_command is None:
            raise ValueError("A model command must be provided.")
        else:
            self.model_command = model_command

    def extract_security_info(self, text: str) -> Dict[str, Any]:
        import re
        info_patterns = {
            'cve': r"CVE-\d{4}-\d{4,7}",
            'cwe': r"CWE-\d{1,4}",
            'confidence': r'confidence (?:score|level|rating).*?(\d+)%',
            'severity': r'severity[:\s]*(Critical|High|Medium|Low)',
        }
        return {
            'cve_ids': re.findall(info_patterns['cve'], text),
            'cwe_ids': re.findall(info_patterns['cwe'], text),
            'confidence': self._extract_confidence(text, info_patterns['confidence']),
            'severity': self._extract_severity(text, info_patterns['severity']),
        }
    
    def _extract_confidence(self, text: str, pattern: str) -> Optional[float]:
        import re
        match = re.search(pattern, text, re.IGNORECASE)
        return float(match.group(1)) if match else None
    
    def _extract_severity(self, text: str, pattern: str) -> Optional[str]:
        import re
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1).lower() if match else None

    @abstractmethod
    def create_prompt(self, code_block: str, cwe_id: str) -> str:
        """
        Each subclass must implement this method to create a prompt tailored to its specific analysis.
        """
        pass
    
    @abstractmethod
    def parse_response(self, result: str) -> Optional[int]:
        """
        Each subclass must implement this method to parse the LLM response and determine
        whether the vulnerability is present.
        """
        pass

    def llm_final_decision(self, text: str) -> Optional[int]:
        """
        Use deepseek-r1 to extract the final decision, with improved parsing to handle
        cases where the LLM provides explanation with its decision.
        """
        prompt = (
            "You are a security expert analyzing a detailed vulnerability assessment. "
            "Based on the following analysis, determine if a vulnerability is present.\n\n"
            "VERY IMPORTANT: Your response must start with a single digit on its own line:\n"
            "1 - if a vulnerability is present\n"
            "0 - if no vulnerability is present\n"
            "2 - if the analysis is ambiguous\n\n"
            "After the digit, you may provide your reasoning on new lines.\n\n"
            "Analysis text:\n" + text + "\n\n"
            "Remember: First line must be ONLY the digit (0, 1, or 2)."
        )
        
        payload = {
            "model": "deepseek-r1",
            "prompt": prompt,
            "temperature": 0.0,
            "stream": False
        }
        
        try:
            response = requests.post("http://localhost:11434/api/generate", json=payload)
            if response.status_code == 200:
                response_lines = response.content.decode('utf-8').splitlines()
                full_response = ''.join([json.loads(line)["response"] for line in response_lines if line])
                
                # Split into lines and get first non-empty line
                lines = [line.strip() for line in full_response.split('\n')]
                first_line = next((line for line in lines if line), '')
                
                # Extract first digit found in the first line
                import re
                digit_match = re.search(r'^[012]$', first_line)
                
                if digit_match:
                    decision = int(digit_match.group(0))
                    logger.debug(f"Extracted decision {decision} from first line: '{first_line}'")
                    return decision
                
                # If no clean digit found in first line, try to infer from full text
                logger.warning(f"No clear digit in first line. Analyzing full response: {full_response[:200]}...")
                
                # Look for clear yes/no language in the full response
                lower_response = full_response.lower()
                if ("vulnerability exists" in lower_response or 
                    "is vulnerable" in lower_response or 
                    "vulnerability is present" in lower_response):
                    return 1
                if ("no vulnerability" in lower_response or 
                    "not vulnerable" in lower_response or 
                    "vulnerability is not present" in lower_response):
                    return 0
                    
                # If still no clear decision, look for the first lone digit in the text
                digit_match = re.search(r'\b[012]\b', full_response)
                if digit_match:
                    decision = int(digit_match.group(0))
                    logger.debug(f"Found decision {decision} in full text")
                    return decision
                
                logger.warning("Could not determine clear decision, marking as ambiguous")
                return Config.AMBIGUOUS_DECISION_VALUE
                
            else:
                logger.error(f"LLM API returned status code: {response.status_code}")
                return Config.AMBIGUOUS_DECISION_VALUE
                
        except Exception as e:
            logger.error(f"Error in llm_final_decision: {e}")
            return Config.AMBIGUOUS_DECISION_VALUE

    def parse_vulnerability(self, result: str) -> Optional[int]:
        """
        Delegate final decision extraction to the benchmarking LLM via llm_final_decision.
        """
        return self.llm_final_decision(result)
