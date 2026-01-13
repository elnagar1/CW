"""
Universal Smart Parser - Handles any unknown data format.
Uses pattern detection and heuristics to map any data to standard schema.
"""

import re
import json
import hashlib
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from dateutil import parser as date_parser

from .base import BaseParser

logger = logging.getLogger(__name__)


class UniversalParser(BaseParser):
    """
    Universal Parser that can handle ANY data format.
    
    Uses intelligent pattern matching to detect and map fields
    to a standard alert schema, regardless of the source format.
    """
    
    source_id = 'universal'
    version = '2.0.0'
    
    # Standard output schema fields
    STANDARD_FIELDS = [
        'id', 'timestamp', 'severity', 'title', 'description',
        'category', 'status', 'source_ip', 'destination_ip',
        'user', 'hostname', 'indicators', 'raw_data'
    ]
    
    # Field patterns for auto-detection (regex patterns)
    FIELD_PATTERNS = {
        'id': [
            r'(?:alert[_-]?id|event[_-]?id|incident[_-]?id|offense[_-]?id|detection[_-]?id|id|uuid|guid)',
        ],
        'timestamp': [
            r'(?:timestamp|time|date|created[_-]?at|updated[_-]?at|event[_-]?time|start[_-]?time|occurred[_-]?at|when|@timestamp)',
        ],
        'severity': [
            r'(?:severity|priority|urgency|risk[_-]?level|threat[_-]?level|criticality|importance|level)',
        ],
        'title': [
            r'(?:title|name|subject|summary|rule[_-]?name|alert[_-]?name|headline|short[_-]?description)',
        ],
        'description': [
            r'(?:description|details|message|body|long[_-]?description|notes|explanation|reason)',
        ],
        'category': [
            r'(?:category|type|class|classification|tactic|technique|attack[_-]?type|threat[_-]?type|rule[_-]?type)',
        ],
        'status': [
            r'(?:status|state|disposition|resolution|workflow[_-]?status)',
        ],
        'source_ip': [
            r'(?:source[_-]?ip|src[_-]?ip|src|attacker[_-]?ip|remote[_-]?ip|client[_-]?ip|from[_-]?ip|origin[_-]?ip)',
        ],
        'destination_ip': [
            r'(?:destination[_-]?ip|dest[_-]?ip|dst[_-]?ip|dst|dest|target[_-]?ip|local[_-]?ip|to[_-]?ip|victim[_-]?ip)',
        ],
        'user': [
            r'(?:user|username|user[_-]?name|account|account[_-]?name|src[_-]?user|target[_-]?user|actor)',
        ],
        'hostname': [
            r'(?:hostname|host|computer[_-]?name|machine[_-]?name|device[_-]?name|endpoint|asset[_-]?name|workstation)',
        ],
    }
    
    # IP address regex pattern
    IP_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    
    # Hash patterns for IOC detection
    HASH_PATTERNS = {
        'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
        'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
    }
    
    # Severity mapping variations
    SEVERITY_MAP = {
        # Numeric
        '1': 'low', '2': 'low', '3': 'low',
        '4': 'medium', '5': 'medium', '6': 'medium',
        '7': 'high', '8': 'high',
        '9': 'critical', '10': 'critical',
        # Text variations
        'informational': 'low', 'info': 'low', 'low': 'low', 'minor': 'low',
        'medium': 'medium', 'moderate': 'medium', 'warning': 'medium', 'warn': 'medium',
        'high': 'high', 'major': 'high', 'error': 'high', 'important': 'high',
        'critical': 'critical', 'severe': 'critical', 'emergency': 'critical', 'fatal': 'critical',
    }
    
    def __init__(self):
        self._field_cache: Dict[str, Dict[str, str]] = {}
        # Import here to avoid circular imports
        from .format_detector import get_format_detector
        self._format_detector = get_format_detector()
    
    def parse(self, raw_data: Any) -> Dict[str, Any]:
        """
        Parse any data format into standard alert schema.
        
        Handles:
        - JSON
        - XML
        - Syslog (RFC 3164 & 5424)
        - CEF (Common Event Format)
        - LEEF (Log Event Extended Format)
        - CSV
        - Key-Value pairs
        - Plain text
        - Dict/JSON objects
        - Nested structures
        - Lists of alerts
        - Unknown field names
        """
        detected_format = 'unknown'
        
        # Use FormatDetector ف handle non-JSON formats
        if isinstance(raw_data, str) or isinstance(raw_data, bytes):
            raw_data, detected_format = self._format_detector.detect_and_parse(raw_data)
            logger.info(f"Detected format: {detected_format}")
        elif isinstance(raw_data, dict):
            detected_format = 'json'
        
        if isinstance(raw_data, list):
            # If it's a list, parse the first item
            raw_data = raw_data[0] if raw_data else {}
        
        if not isinstance(raw_data, dict):
            raw_data = {'value': raw_data}
        
        # Flatten nested structures
        flat_data = self._flatten_dict(raw_data)
        
        # Map fields to standard schema
        mapped = self._map_fields(flat_data)
        
        # Extract IOCs
        indicators = self._extract_indicators(flat_data)
        
        # Build standard alert
        return {
            'id': mapped.get('id') or self._generate_id(raw_data),
            'timestamp': self._parse_timestamp(mapped.get('timestamp')),
            'severity': self._normalize_severity(mapped.get('severity', 'medium')),
            'title': mapped.get('title') or self._generate_title(flat_data),
            'description': mapped.get('description') or self._generate_description(flat_data),
            'category': mapped.get('category') or 'unknown',
            'status': self._normalize_status(mapped.get('status', 'new')),
            'source_ip': mapped.get('source_ip') or self._find_ip(flat_data, 'source'),
            'destination_ip': mapped.get('destination_ip') or self._find_ip(flat_data, 'destination'),
            'user': mapped.get('user'),
            'hostname': mapped.get('hostname'),
            'indicators': indicators,
            'extra_fields': self._get_extra_fields(flat_data, mapped),
            'detected_format': detected_format,
        }
    
    def _flatten_dict(self, d: Dict, parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
        """Flatten nested dictionary."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep).items())
            elif isinstance(v, list):
                if v and isinstance(v[0], dict):
                    for i, item in enumerate(v[:5]):  # Limit to first 5 items
                        items.extend(self._flatten_dict(item, f"{new_key}[{i}]", sep).items())
                else:
                    items.append((new_key, v))
            else:
                items.append((new_key, v))
        return dict(items)
    
    def _map_fields(self, flat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Map source fields to standard fields using pattern matching."""
        mapped = {}
        used_fields = set()
        
        for standard_field, patterns in self.FIELD_PATTERNS.items():
            for pattern in patterns:
                regex = re.compile(pattern, re.IGNORECASE)
                for key, value in flat_data.items():
                    if key in used_fields:
                        continue
                    # Match against the last part of the key (after last dot)
                    key_part = key.split('.')[-1]
                    if regex.fullmatch(key_part):
                        mapped[standard_field] = value
                        used_fields.add(key)
                        break
                if standard_field in mapped:
                    break
        
        return mapped
    
    def _generate_id(self, data: Dict) -> str:
        """Generate a unique ID from the data."""
        data_str = json.dumps(data, sort_keys=True, default=str)
        hash_obj = hashlib.sha256(data_str.encode())
        return f"alert_{hash_obj.hexdigest()[:16]}"
    
    def _parse_timestamp(self, value: Any) -> str:
        """Parse any timestamp format to ISO format."""
        if not value:
            return datetime.utcnow().isoformat()
        
        if isinstance(value, (int, float)):
            # Unix timestamp
            if value > 1e12:  # Milliseconds
                value = value / 1000
            try:
                return datetime.utcfromtimestamp(value).isoformat()
            except (ValueError, OSError):
                return datetime.utcnow().isoformat()
        
        if isinstance(value, str):
            try:
                return date_parser.parse(value).isoformat()
            except (ValueError, TypeError):
                return datetime.utcnow().isoformat()
        
        return datetime.utcnow().isoformat()
    
    def _normalize_severity(self, value: Any) -> str:
        """Normalize severity to standard values."""
        if value is None:
            return 'medium'
        
        str_value = str(value).lower().strip()
        
        # Check direct mapping
        if str_value in self.SEVERITY_MAP:
            return self.SEVERITY_MAP[str_value]
        
        # Try numeric conversion
        try:
            num = float(value)
            if num <= 3:
                return 'low'
            elif num <= 6:
                return 'medium'
            elif num <= 8:
                return 'high'
            else:
                return 'critical'
        except (ValueError, TypeError):
            pass
        
        # Default
        return 'medium'
    
    def _normalize_status(self, value: Any) -> str:
        """Normalize status to standard values."""
        if not value:
            return 'new'
        
        status_map = {
            'new': 'new', 'open': 'new', 'pending': 'new', 'unassigned': 'new',
            'in_progress': 'investigating', 'investigating': 'investigating', 
            'assigned': 'investigating', 'in progress': 'investigating',
            'resolved': 'closed', 'closed': 'closed', 'done': 'closed', 
            'completed': 'closed', 'fixed': 'closed',
            'false_positive': 'false_positive', 'fp': 'false_positive',
        }
        
        return status_map.get(str(value).lower().strip(), 'new')
    
    def _generate_title(self, flat_data: Dict) -> str:
        """Generate a title from available data."""
        # Try common title-like fields
        for key in ['alert_type', 'event_type', 'rule', 'signature', 'threat', 'attack']:
            for flat_key, value in flat_data.items():
                if key in flat_key.lower() and value and isinstance(value, str):
                    return str(value)[:200]
        
        return 'Security Alert'
    
    def _generate_description(self, flat_data: Dict) -> str:
        """Generate description from available data."""
        desc_parts = []
        
        # Look for description-like fields
        for key in ['message', 'details', 'info', 'reason', 'action']:
            for flat_key, value in flat_data.items():
                if key in flat_key.lower() and value and isinstance(value, str):
                    desc_parts.append(str(value))
        
        if desc_parts:
            return ' | '.join(desc_parts[:3])[:1000]
        
        return ''
    
    def _find_ip(self, flat_data: Dict, ip_type: str) -> Optional[str]:
        """Find IP address in data."""
        # First try specific fields
        keywords = ['source', 'src', 'attacker', 'remote'] if ip_type == 'source' else ['dest', 'dst', 'target', 'victim', 'local']
        
        for flat_key, value in flat_data.items():
            key_lower = flat_key.lower()
            if any(kw in key_lower for kw in keywords) and 'ip' in key_lower:
                if value and self.IP_PATTERN.match(str(value)):
                    return str(value)
        
        # Search for any IP in relevant fields
        for flat_key, value in flat_data.items():
            key_lower = flat_key.lower()
            if any(kw in key_lower for kw in keywords):
                if value:
                    match = self.IP_PATTERN.search(str(value))
                    if match:
                        return match.group()
        
        return None
    
    def _extract_indicators(self, flat_data: Dict) -> List[Dict[str, str]]:
        """Extract IOCs (Indicators of Compromise) from data."""
        indicators = []
        seen = set()
        
        # Search all string values for IOCs
        for key, value in flat_data.items():
            if not isinstance(value, str):
                value = str(value)
            
            # Find IPs
            for ip in self.IP_PATTERN.findall(value):
                if ip not in seen and not ip.startswith('10.') and not ip.startswith('192.168.'):
                    indicators.append({'type': 'ip', 'value': ip})
                    seen.add(ip)
            
            # Find hashes
            for hash_type, pattern in self.HASH_PATTERNS.items():
                for hash_val in pattern.findall(value):
                    if hash_val not in seen:
                        indicators.append({'type': hash_type, 'value': hash_val.lower()})
                        seen.add(hash_val)
        
        return indicators[:20]  # Limit to 20 indicators
    
    def _get_extra_fields(self, flat_data: Dict, mapped: Dict) -> Dict[str, Any]:
        """Get fields that weren't mapped to standard schema."""
        mapped_values = set(str(v) for v in mapped.values() if v)
        extra = {}
        
        for key, value in flat_data.items():
            if str(value) not in mapped_values and value is not None:
                # Use shortened key
                short_key = key.split('.')[-1]
                if short_key not in extra:
                    extra[short_key] = value
        
        return extra
