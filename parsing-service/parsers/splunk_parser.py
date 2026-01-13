"""Splunk Parser - Converts Splunk notable events to standard format."""

from typing import Dict, Any
from .base import BaseParser


class SplunkParser(BaseParser):
    """Parser for Splunk Enterprise Security notable events."""
    
    source_id = 'splunk'
    version = '1.0.0'
    
    def parse(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Splunk notable event to standard format."""
        
        return {
            'id': f"splunk_{raw_data.get('event_id', raw_data.get('_cd', ''))}",
            'timestamp': raw_data.get('_time', ''),
            'severity': self.normalize_severity(raw_data.get('urgency', 'medium')),
            'title': raw_data.get('rule_name', raw_data.get('search_name', 'Splunk Alert')),
            'description': raw_data.get('rule_description', raw_data.get('description', '')),
            'category': raw_data.get('rule_title', 'unknown'),
            'status': self._map_status(raw_data.get('status', '')),
            'source_ip': raw_data.get('src', raw_data.get('src_ip', '')),
            'destination_ip': raw_data.get('dest', raw_data.get('dest_ip', '')),
            'user': raw_data.get('user', raw_data.get('src_user', '')),
            'hostname': raw_data.get('host', raw_data.get('dest_host', '')),
            'indicators': self._extract_indicators(raw_data),
        }
    
    def _map_status(self, status: str) -> str:
        """Map Splunk status to standard status."""
        status_map = {'new': 'new', 'in progress': 'investigating', 'resolved': 'closed', 'closed': 'closed'}
        return status_map.get(status.lower() if status else '', 'new')
    
    def _extract_indicators(self, raw_data: Dict[str, Any]) -> list:
        """Extract IOCs from Splunk event."""
        indicators = []
        if raw_data.get('file_hash'):
            indicators.append({'type': 'hash', 'value': raw_data['file_hash']})
        if raw_data.get('url'):
            indicators.append({'type': 'url', 'value': raw_data['url']})
        if raw_data.get('domain'):
            indicators.append({'type': 'domain', 'value': raw_data['domain']})
        return indicators
