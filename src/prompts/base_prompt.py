from abc import ABC, abstractmethod
import re
from typing import Optional, Tuple

class BasePrompt(ABC):
    """Base class for all prompt strategies."""

    @abstractmethod
    def create_prompt(self, code_block: str, cwe_id: str) -> str:
        """Create a prompt for the given code block and CWE ID.
        
        Args:
            code_block (str): The code to analyze
            cwe_id (str): The CWE ID to check for
            
        Returns:
            str: The formatted prompt
        """
        pass

    @abstractmethod
    def parse_response(self, result: str) -> Optional[int]:
        """Parse the response from the LLM.
        
        Args:
            result (str): The raw response from the LLM
            
        Returns:
            Optional[int]: 1 if vulnerable, 0 if not vulnerable, None if unclear
        """
        pass

    def extract_vulnerability_info(self, text: str) -> Tuple[list, list]:
        """Extract CVE and CWE IDs from text.
        
        Args:
            text (str): Text to search for vulnerability IDs
            
        Returns:
            Tuple[list, list]: Lists of CVE and CWE IDs found
        """
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cwe_pattern = r"CWE-\d{1,4}"
        cve_names = re.findall(cve_pattern, text)
        cwe_names = re.findall(cwe_pattern, text)
        return cve_names, cwe_names