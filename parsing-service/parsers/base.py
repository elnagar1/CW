"""
Base Parser class for all source-specific parsers.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any


class BaseParser(ABC):
    """Abstract base class for alert parsers."""
    
    source_id: str = 'unknown'
    version: str = '1.0.0'
    
    @abstractmethod
    def parse(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse raw alert data into standard format.
        
        Args:
            raw_data: Raw alert data from the source
            
        Returns:
            Standardized alert dictionary with fields:
            - id: Unique alert identifier
            - timestamp: Alert timestamp (ISO format)
            - severity: low/medium/high/critical
            - title: Alert title
            - description: Alert description
            - category: Alert category
            - source_ip: Source IP address
            - destination_ip: Destination IP address
            - user: Associated username
            - hostname: Associated hostname
            - indicators: List of IOCs
        """
        pass
    
    def normalize_severity(self, value: Any) -> str:
        """Normalize severity to standard values."""
        if isinstance(value, (int, float)):
            if value <= 3:
                return 'low'
            elif value <= 6:
                return 'medium'
            elif value <= 8:
                return 'high'
            else:
                return 'critical'
        
        severity_map = {
            'low': 'low', 'informational': 'low', 'info': 'low',
            'medium': 'medium', 'warning': 'medium', 'warn': 'medium',
            'high': 'high', 'error': 'high',
            'critical': 'critical', 'severe': 'critical', 'emergency': 'critical'
        }
        return severity_map.get(str(value).lower(), 'medium')
