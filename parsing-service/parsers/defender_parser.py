"""Defender Parser - Converts Microsoft Defender alerts to standard format."""

from typing import Dict, Any
from .base import BaseParser


class DefenderParser(BaseParser):
    """Parser for Microsoft Defender for Endpoint alerts."""
    
    source_id = 'defender'
    version = '1.0.0'
    
    def parse(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Defender alert to standard format."""
        
        evidence = raw_data.get('evidence', [])
        
        return {
            'id': f"defender_{raw_data.get('id', '')}",
            'timestamp': raw_data.get('createdDateTime', ''),
            'severity': self.normalize_severity(raw_data.get('severity', 'medium')),
            'title': raw_data.get('title', 'Microsoft Defender Alert'),
            'description': raw_data.get('description', ''),
            'category': raw_data.get('category', 'unknown'),
            'status': self._map_status(raw_data.get('status', '')),
            'source_ip': self._extract_ip(evidence, 'source'),
            'destination_ip': self._extract_ip(evidence, 'destination'),
            'user': self._extract_user(evidence),
            'hostname': self._extract_device(evidence),
            'indicators': self._extract_indicators(evidence),
        }
    
    def _map_status(self, status: str) -> str:
        """Map Defender status to standard status."""
        status_map = {'new': 'new', 'inProgress': 'investigating', 'resolved': 'closed'}
        return status_map.get(status, 'new')
    
    def _extract_ip(self, evidence: list, direction: str) -> str:
        """Extract IP address from evidence."""
        for item in evidence:
            if item.get('@odata.type') == '#microsoft.graph.security.ipEvidence':
                return item.get('ipAddress', '')
        return ''
    
    def _extract_user(self, evidence: list) -> str:
        """Extract username from evidence."""
        for item in evidence:
            if item.get('@odata.type') == '#microsoft.graph.security.userEvidence':
                return item.get('userAccount', {}).get('accountName', '')
        return ''
    
    def _extract_device(self, evidence: list) -> str:
        """Extract device name from evidence."""
        for item in evidence:
            if item.get('@odata.type') == '#microsoft.graph.security.deviceEvidence':
                return item.get('deviceDnsName', '')
        return ''
    
    def _extract_indicators(self, evidence: list) -> list:
        """Extract IOCs from evidence."""
        indicators = []
        for item in evidence:
            if item.get('@odata.type') == '#microsoft.graph.security.fileEvidence':
                if item.get('fileDetails', {}).get('sha256'):
                    indicators.append({'type': 'sha256', 'value': item['fileDetails']['sha256']})
        return indicators
