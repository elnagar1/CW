"""QRadar Parser - Converts QRadar offenses to standard format."""

from typing import Dict, Any
from datetime import datetime
from .base import BaseParser


class QRadarParser(BaseParser):
    """Parser for IBM QRadar SIEM offenses."""
    
    source_id = 'qradar'
    version = '1.0.0'
    
    def parse(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse QRadar offense to standard format."""
        
        # Convert QRadar timestamp (milliseconds) to ISO format
        start_time = raw_data.get('start_time', 0)
        if start_time:
            timestamp = datetime.utcfromtimestamp(start_time / 1000).isoformat()
        else:
            timestamp = datetime.utcnow().isoformat()
        
        return {
            'id': f"qradar_{raw_data.get('id', '')}",
            'timestamp': timestamp,
            'severity': self.normalize_severity(raw_data.get('severity', 5)),
            'title': raw_data.get('description', 'QRadar Offense'),
            'description': raw_data.get('description', ''),
            'category': self._get_category(raw_data.get('categories', [])),
            'status': self._map_status(raw_data.get('status', '')),
            'source_ip': raw_data.get('offense_source', ''),
            'destination_ip': None,
            'user': None,
            'hostname': None,
            'indicators': self._extract_indicators(raw_data),
        }
    
    def _get_category(self, categories: list) -> str:
        """Extract primary category."""
        if categories and len(categories) > 0:
            return categories[0] if isinstance(categories[0], str) else str(categories[0])
        return 'unknown'
    
    def _map_status(self, status: str) -> str:
        """Map QRadar status to standard status."""
        status_map = {'OPEN': 'new', 'HIDDEN': 'suppressed', 'CLOSED': 'closed'}
        return status_map.get(status, 'new')
    
    def _extract_indicators(self, raw_data: Dict[str, Any]) -> list:
        """Extract IOCs from QRadar offense."""
        indicators = []
        if raw_data.get('offense_source'):
            indicators.append({'type': 'ip', 'value': raw_data['offense_source']})
        return indicators
