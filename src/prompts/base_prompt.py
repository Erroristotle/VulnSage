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
        Use the benchmarking LLM to extract a final decision.
        
        The prompt instructs the LLM to provide a final decision as a single digit:
        - "1" if the vulnerability is present
        - "0" if it is not present
        - "2" if the analysis is ambiguous
        """
        prompt = (
            "You are a security expert. Based on the following text, provide a final decision "
            "as a single digit:\n"
            "1 - if the vulnerability is present\n"
            "0 - if it is not present\n"
            "2 - if the analysis is ambiguous or unclear\n\n"
            "Text:\n" + text
        )
        payload = {
            "model": self.model_command,
            "prompt": prompt,
            "temperature": 0.0,
            "stream": False
        }
        try:
            response = requests.post("http://localhost:11434/api/generate", json=payload)
            if response.status_code == 200:
                response_lines = response.content.decode('utf-8').splitlines()
                full_response = ''.join([json.loads(line)["response"] for line in response_lines if line])
                decision_str = full_response.strip()
                logger.debug("LLM final decision response: '%s'", decision_str)
                if decision_str in ["0", "1", "2"]:
                    return int(decision_str)
                # If no clear decision, return ambiguous
                return Config.AMBIGUOUS_DECISION_VALUE
            else:
                logger.error("LLM API returned status code: %s", response.status_code)
        except Exception as e:
            logger.error("Error calling LLM API for final decision: %s", e)
        return Config.AMBIGUOUS_DECISION_VALUE

    def parse_vulnerability(self, result: str) -> Optional[int]:
        """
        Delegate final decision extraction to the benchmarking LLM via llm_final_decision.
        """
        return self.llm_final_decision(result)
