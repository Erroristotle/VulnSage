from abc import ABC, abstractmethod
import json
import logging
import requests
from typing import Optional, Dict, Any

# Import configuration settings.
from config import Config

logger = logging.getLogger(__name__)

class BasePrompt(ABC):
    """
    Base class for all prompt types with common parsing utilities.
    
    This version delegates the extraction of the final decision to the benchmarking LLM 
    (the same model used throughout the system) rather than relying on regex.
    The final decision is obtained by sending the complete response to the LLM 
    (using a provided model command) with a prompt that asks for a single-digit answer.
    """
    
    def __init__(self, model_command: Optional[str] = None):
        """
        Initialize the prompt with a model command.
        
        If no model_command is provided, the default from Config (for the current benchmarked model) is used.
        """
        if model_command is None:
            # Assumes that Config.DEFAULT_MODEL is defined in your configuration.
            self.model_command = Config.get_model_command(Config.DEFAULT_MODEL)
        else:
            self.model_command = model_command

    def extract_security_info(self, text: str) -> Dict[str, Any]:
        """
        Extract additional security-related information (e.g., CVE/CWE IDs, confidence, severity)
        from the given text.
        """
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
        Use the benchmarking LLM (via the provided model command) to extract a final decision.
        
        The prompt instructs the LLM to provide a final decision as a single digit:
          - "1" if the vulnerability is present,
          - "0" if it is not.
        """
        prompt = (
            "You are a security expert. Based on the following text, provide a final decision "
            "as a single digit: 1 if the vulnerability is present, and 0 if it is not present.\n\n"
            "Text:\n" + text
        )
        payload = {
            "model": self.model_command,  # Use the benchmarking model command
            "prompt": prompt,
            "temperature": 0.0
        }
        try:
            response = requests.post(Config.API_URL, json=payload)
            if response.status_code == 200:
                response_lines = response.content.decode('utf-8').splitlines()
                full_response = ''.join([json.loads(line)["response"] for line in response_lines if line])
                decision_str = full_response.strip()
                logger.debug("LLM final decision response: '%s'", decision_str)
                if decision_str == "1":
                    return 1
                if decision_str == "0":
                    return 0
                # Fallback logic if one digit is clearly present:
                if "1" in decision_str and "0" not in decision_str:
                    return 1
                if "0" in decision_str and "1" not in decision_str:
                    return 0
            else:
                logger.error("LLM API returned status code: %s", response.status_code)
        except Exception as e:
            logger.error("Error calling LLM API for final decision: %s", e)
        return None

    def parse_vulnerability(self, result: str) -> Optional[int]:
        """
        Delegate final decision extraction to the benchmarking LLM via llm_final_decision.
        """
        return self.llm_final_decision(result)
