import re
import json
from typing import Optional, Dict, Any, Tuple

class ResponseParser:
    """Handles parsing and processing of LLM responses."""
    
    @staticmethod
    def parse_json_response(response: str) -> str:
        """Parse JSON response from API."""
        response_lines = response.splitlines()
        full_response = ''.join([
            json.loads(line)["response"]
            for line in response_lines
            if line
        ])
        return full_response

    @staticmethod
    def extract_confidence(text: str) -> Optional[float]:
        """Extract confidence score from response."""
        confidence_match = re.search(
            r'confidence (?:score|level|rating).*?(\d+)%',
            text,
            re.IGNORECASE | re.DOTALL
        )
        if confidence_match:
            return float(confidence_match.group(1))
        return None

    @staticmethod
    def extract_severity(text: str) -> Optional[str]:
        """Extract severity rating from response."""
        severity_match = re.search(
            r'severity.*?(Critical|High|Medium|Low)',
            text,
            re.IGNORECASE | re.DOTALL
        )
        if severity_match:
            return severity_match.group(1).lower()
        return None

    @staticmethod
    def extract_vulnerability_info(text: str) -> Dict[str, Any]:
        """Extract comprehensive vulnerability information."""
        info = {
            'confidence': None,
            'severity': None,
            'vulnerabilities_found': [],
            'recommendations': []
        }
        
        # Extract confidence
        info['confidence'] = ResponseParser.extract_confidence(text)
        
        # Extract severity
        info['severity'] = ResponseParser.extract_severity(text)
        
        # Extract vulnerabilities
        vuln_section = re.search(
            r'<findings>.*?</findings>',
            text,
            re.DOTALL
        )
        if vuln_section:
            vulnerabilities = re.findall(
                r'\*\s*(.*?)(?=\*|$)',
                vuln_section.group(0),
                re.DOTALL
            )
            info['vulnerabilities_found'] = [v.strip() for v in vulnerabilities if v.strip()]
        
        # Extract recommendations
        recom_section = re.search(
            r'Security Improvements:.*?(?=\n\n|$)',
            text,
            re.DOTALL
        )
        if recom_section:
            recommendations = re.findall(
                r'\*\s*(.*?)(?=\*|$)',
                recom_section.group(0),
                re.DOTALL
            )
            info['recommendations'] = [r.strip() for r in recommendations if r.strip()]
        
        return info