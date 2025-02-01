from dataclasses import dataclass
from typing import Optional, List, Dict
from datetime import datetime

@dataclass
class VulnerabilityData:
    """Data class for vulnerability information."""
    commit_hash: str
    vulnerable_code: str
    patched_code: Optional[str]
    cwe_id: str
    year: Optional[int]
    description: Optional[str]

@dataclass
class ProcessingResult:
    """Data class for processing results."""
    commit_hash: str
    strategy: str
    is_vulnerable: bool
    confidence: float
    timestamp: datetime
    status: int  # 1 for vulnerable, 0 for not vulnerable, -1 for error

class ModelResult:
    """Class to handle model results and statistics."""
    
    def __init__(self, model_name: str):
        self.model_name = model_name
        self.results: List[ProcessingResult] = []
        self.error_count: int = 0
        self.success_count: int = 0
        
    def add_result(self, result: ProcessingResult) -> None:
        """Add a processing result."""
        self.results.append(result)
        if result.status != -1:
            self.success_count += 1
        else:
            self.error_count += 1
    
    def get_statistics(self) -> Dict:
        """Get statistics about the model's performance."""
        return {
            "model_name": self.model_name,
            "total_processed": len(self.results),
            "success_rate": self.success_count / (len(self.results) or 1),
            "error_rate": self.error_count / (len(self.results) or 1),
            "average_confidence": sum(r.confidence for r in self.results) / (len(self.results) or 1)
        }