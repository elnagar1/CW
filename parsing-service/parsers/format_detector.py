"""
Format Detector and Converter - Detects and converts any data format to dict.
Supports: JSON, XML, Syslog, CEF, CSV, Key-Value, Plain Text
"""

import re
import json
import logging
from typing import Dict, Any, Optional, Tuple
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)


class FormatDetector:
    """
    Detects the format of incoming data and converts it to a dictionary.
    
    Supported formats:
    - JSON
    - XML
    - Syslog (RFC 3164 & RFC 5424)
    - CEF (Common Event Format)
    - LEEF (Log Event Extended Format)
    - CSV (single line)
    - Key-Value pairs
    - Plain text
    """
    
    # Syslog pattern (RFC 3164)
    SYSLOG_PATTERN = re.compile(
        r'^<(\d+)>(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$'
    )
    
    # Syslog RFC 5424 pattern
    SYSLOG_5424_PATTERN = re.compile(
        r'^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:\[([^\]]*)\])?\s*(.*)$'
    )
    
    # CEF pattern
    CEF_PATTERN = re.compile(
        r'^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$'
    )
    
    # LEEF pattern
    LEEF_PATTERN = re.compile(
        r'^LEEF:(\d+(?:\.\d+)?)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$'
    )
    
    # Key-Value pattern
    KV_PATTERN = re.compile(r'(\w+)=("[^"]*"|\S+)')
    
    # IP pattern for extraction
    IP_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    
    def detect_and_parse(self, data: Any) -> Tuple[Dict[str, Any], str]:
        """
        Detect the format of incoming data and parse it to a dictionary.
        
        Args:
            data: Raw incoming data (string, bytes, or dict)
            
        Returns:
            Tuple of (parsed_dict, detected_format)
        """
        # If already a dict, return as-is
        if isinstance(data, dict):
            return data, 'json'
        
        # Convert bytes to string
        if isinstance(data, bytes):
            try:
                data = data.decode('utf-8')
            except UnicodeDecodeError:
                data = data.decode('latin-1')
        
        # Ensure string
        if not isinstance(data, str):
            data = str(data)
        
        data = data.strip()
        
        # Try each format
        formats = [
            ('json', self._parse_json),
            ('xml', self._parse_xml),
            ('cef', self._parse_cef),
            ('leef', self._parse_leef),
            ('syslog_5424', self._parse_syslog_5424),
            ('syslog', self._parse_syslog),
            ('kv', self._parse_key_value),
            ('csv', self._parse_csv),
            ('text', self._parse_text),
        ]
        
        for format_name, parser in formats:
            try:
                result = parser(data)
                if result:
                    logger.debug(f"Detected format: {format_name}")
                    result['_detected_format'] = format_name
                    return result, format_name
            except Exception as e:
                logger.debug(f"Format {format_name} failed: {e}")
                continue
        
        # Fallback to text
        return self._parse_text(data), 'text'
    
    def _parse_json(self, data: str) -> Optional[Dict[str, Any]]:
        """Parse JSON data."""
        if not (data.startswith('{') or data.startswith('[')):
            return None
        
        parsed = json.loads(data)
        if isinstance(parsed, list):
            return {'items': parsed, 'count': len(parsed)}
        return parsed
    
    def _parse_xml(self, data: str) -> Optional[Dict[str, Any]]:
        """Parse XML data to dictionary."""
        if not data.startswith('<') or data.startswith('<1'):
            return None
        
        # Skip if it looks like syslog priority
        if re.match(r'^<\d+>', data):
            return None
        
        root = ET.fromstring(data)
        return self._xml_to_dict(root)
    
    def _xml_to_dict(self, element: ET.Element) -> Dict[str, Any]:
        """Convert XML element to dictionary recursively."""
        result = {}
        
        # Add attributes
        if element.attrib:
            result.update(element.attrib)
        
        # Add child elements
        for child in element:
            child_data = self._xml_to_dict(child)
            tag = child.tag.split('}')[-1]  # Remove namespace
            
            if tag in result:
                # Convert to list if multiple same tags
                if not isinstance(result[tag], list):
                    result[tag] = [result[tag]]
                result[tag].append(child_data)
            else:
                result[tag] = child_data
        
        # Add text content
        if element.text and element.text.strip():
            if result:
                result['_text'] = element.text.strip()
            else:
                return element.text.strip()
        
        return result if result else element.text or ''
    
    def _parse_cef(self, data: str) -> Optional[Dict[str, Any]]:
        """Parse CEF (Common Event Format) data."""
        match = self.CEF_PATTERN.match(data)
        if not match:
            return None
        
        version, vendor, product, dev_version, signature_id, name, severity, extensions = match.groups()
        
        result = {
            'cef_version': version,
            'vendor': vendor,
            'product': product,
            'device_version': dev_version,
            'signature_id': signature_id,
            'name': name,
            'severity': severity,
        }
        
        # Parse extensions (key=value pairs)
        if extensions:
            ext_dict = self._parse_cef_extensions(extensions)
            result.update(ext_dict)
        
        return result
    
    def _parse_cef_extensions(self, extensions: str) -> Dict[str, str]:
        """Parse CEF extension key-value pairs."""
        result = {}
        # CEF uses space-separated key=value, but values can contain spaces
        parts = extensions.split(' ')
        current_key = None
        current_value = []
        
        for part in parts:
            if '=' in part and not current_key:
                key, _, value = part.partition('=')
                if not value:
                    current_key = key
                else:
                    result[key] = value
            elif '=' in part and current_key:
                # Save previous
                result[current_key] = ' '.join(current_value)
                # Start new
                key, _, value = part.partition('=')
                if not value:
                    current_key = key
                    current_value = []
                else:
                    result[key] = value
                    current_key = None
                    current_value = []
            elif current_key:
                current_value.append(part)
        
        if current_key and current_value:
            result[current_key] = ' '.join(current_value)
        
        return result
    
    def _parse_leef(self, data: str) -> Optional[Dict[str, Any]]:
        """Parse LEEF (Log Event Extended Format) data."""
        match = self.LEEF_PATTERN.match(data)
        if not match:
            return None
        
        version, vendor, product, prod_version, attributes = match.groups()
        
        result = {
            'leef_version': version,
            'vendor': vendor,
            'product': product,
            'product_version': prod_version,
        }
        
        # Parse attributes (tab or custom delimiter separated)
        delimiter = '\t'
        if version.startswith('2'):
            # LEEF 2.0 can have custom delimiter as first char
            if attributes and len(attributes) > 1:
                delimiter = attributes[0]
                attributes = attributes[1:]
        
        for pair in attributes.split(delimiter):
            if '=' in pair:
                key, _, value = pair.partition('=')
                result[key.strip()] = value.strip()
        
        return result
    
    def _parse_syslog(self, data: str) -> Optional[Dict[str, Any]]:
        """Parse Syslog RFC 3164 format."""
        match = self.SYSLOG_PATTERN.match(data)
        if not match:
            return None
        
        priority, timestamp, hostname, app, pid, message = match.groups()
        
        # Calculate facility and severity from priority
        pri = int(priority)
        facility = pri // 8
        severity = pri % 8
        
        result = {
            'priority': pri,
            'facility': facility,
            'severity': self._syslog_severity_to_text(severity),
            'timestamp': timestamp,
            'hostname': hostname,
            'application': app,
            'message': message,
        }
        
        if pid:
            result['pid'] = pid
        
        # Try to parse message as key-value
        kv = self._parse_key_value(message)
        if kv and len(kv) > 1:
            result['parsed_message'] = kv
        
        return result
    
    def _parse_syslog_5424(self, data: str) -> Optional[Dict[str, Any]]:
        """Parse Syslog RFC 5424 format."""
        match = self.SYSLOG_5424_PATTERN.match(data)
        if not match:
            return None
        
        priority, version, timestamp, hostname, app, procid, msgid, sd, message = match.groups()
        
        pri = int(priority)
        
        result = {
            'priority': pri,
            'syslog_version': version,
            'facility': pri // 8,
            'severity': self._syslog_severity_to_text(pri % 8),
            'timestamp': timestamp,
            'hostname': hostname,
            'application': app,
            'process_id': procid,
            'message_id': msgid,
            'message': message,
        }
        
        # Parse structured data
        if sd and sd != '-':
            result['structured_data'] = self._parse_structured_data(sd)
        
        return result
    
    def _syslog_severity_to_text(self, severity: int) -> str:
        """Convert syslog severity number to text."""
        severities = {
            0: 'critical',  # Emergency
            1: 'critical',  # Alert
            2: 'critical',  # Critical
            3: 'high',      # Error
            4: 'medium',    # Warning
            5: 'low',       # Notice
            6: 'low',       # Info
            7: 'low',       # Debug
        }
        return severities.get(severity, 'medium')
    
    def _parse_structured_data(self, sd: str) -> Dict[str, Any]:
        """Parse syslog structured data."""
        result = {}
        # Format: [id param="value" param2="value2"][id2 ...]
        pattern = re.compile(r'\[(\S+)\s+([^\]]+)\]')
        for match in pattern.finditer(sd):
            sd_id, params = match.groups()
            result[sd_id] = {}
            for param_match in re.finditer(r'(\w+)="([^"]*)"', params):
                key, value = param_match.groups()
                result[sd_id][key] = value
        return result
    
    def _parse_key_value(self, data: str) -> Optional[Dict[str, Any]]:
        """Parse key=value formatted data."""
        matches = self.KV_PATTERN.findall(data)
        if len(matches) < 2:
            return None
        
        result = {}
        for key, value in matches:
            # Remove quotes from value
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            result[key] = value
        
        return result
    
    def _parse_csv(self, data: str) -> Optional[Dict[str, Any]]:
        """Parse CSV-like data (single line with comma separation)."""
        if ',' not in data or '\n' in data:
            return None
        
        # Skip if looks like JSON or other format
        if data.startswith('{') or data.startswith('<') or '=' in data:
            return None
        
        parts = [p.strip().strip('"') for p in data.split(',')]
        
        # Only parse if we have reasonable number of fields
        if len(parts) < 2 or len(parts) > 50:
            return None
        
        return {
            'csv_fields': parts,
            'field_count': len(parts),
            'raw_line': data
        }
    
    def _parse_text(self, data: str) -> Dict[str, Any]:
        """Parse plain text - extract any useful information."""
        result = {
            'raw_message': data,
            'message_length': len(data),
        }
        
        # Extract IPs
        ips = self.IP_PATTERN.findall(data)
        if ips:
            result['extracted_ips'] = list(set(ips))
        
        # Look for common keywords
        data_lower = data.lower()
        
        # Severity keywords
        if any(w in data_lower for w in ['critical', 'emergency', 'fatal']):
            result['severity'] = 'critical'
        elif any(w in data_lower for w in ['error', 'high', 'alert']):
            result['severity'] = 'high'
        elif any(w in data_lower for w in ['warning', 'warn']):
            result['severity'] = 'medium'
        else:
            result['severity'] = 'low'
        
        # Try to extract timestamp patterns
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}',
            r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}',
            r'\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}',
        ]
        for pattern in timestamp_patterns:
            match = re.search(pattern, data)
            if match:
                result['extracted_timestamp'] = match.group()
                break
        
        return result


# Singleton instance
_detector = None

def get_format_detector() -> FormatDetector:
    """Get the singleton FormatDetector instance."""
    global _detector
    if _detector is None:
        _detector = FormatDetector()
    return _detector
