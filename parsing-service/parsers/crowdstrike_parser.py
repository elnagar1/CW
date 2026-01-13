"""CrowdStrike Parser - Converts CrowdStrike detections to standard format."""

from typing import Dict, Any
from .base import BaseParser


class CrowdStrikeParser(BaseParser):
    """Parser for CrowdStrike Falcon detections."""
    
    source_id = 'crowdstrike'
    version = '1.0.0'
    
    def parse(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse CrowdStrike detection to standard format."""
        
        device = raw_data.get('device', {})
        behaviors = raw_data.get('behaviors', [])
        first_behavior = behaviors[0] if behaviors else {}
        
        return {
            'id': f"cs_{raw_data.get('detection_id', '')}",
            'timestamp': raw_data.get('created_timestamp', ''),
            'severity': self.normalize_severity(raw_data.get('max_severity', 50) / 10),
            'title': first_behavior.get('scenario', 'CrowdStrike Detection'),
            'description': first_behavior.get('description', ''),
            'category': first_behavior.get('tactic', 'unknown'),
            'status': self._map_status(raw_data.get('status', '')),
            'source_ip': device.get('local_ip', ''),
            'destination_ip': device.get('external_ip', ''),
            'user': first_behavior.get('user_name', ''),
            'hostname': device.get('hostname', ''),
            'indicators': self._extract_indicators(raw_data),
        }
    
    def _map_status(self, status: str) -> str:
        """Map CrowdStrike status to standard status."""
        status_map = {'new': 'new', 'in_progress': 'investigating', 'closed': 'closed', 'reopened': 'new'}
        return status_map.get(status, 'new')
    
    def _extract_indicators(self, raw_data: Dict[str, Any]) -> list:
        """Extract IOCs from CrowdStrike detection."""
        indicators = []
        for behavior in raw_data.get('behaviors', []):
            if behavior.get('sha256'):
                indicators.append({'type': 'sha256', 'value': behavior['sha256']})
            if behavior.get('md5'):
                indicators.append({'type': 'md5', 'value': behavior['md5']})
            if behavior.get('filename'):
                indicators.append({'type': 'filename', 'value': behavior['filename']})
        return indicators
