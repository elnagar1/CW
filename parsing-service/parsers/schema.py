"""
Standard Alert Schema - Defines the unified output format.
All parsers convert their data to this schema.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    """Standard severity levels."""
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'


class Status(str, Enum):
    """Standard alert status."""
    NEW = 'new'
    INVESTIGATING = 'investigating'
    CLOSED = 'closed'
    FALSE_POSITIVE = 'false_positive'


@dataclass
class Indicator:
    """Indicator of Compromise (IOC)."""
    type: str  # ip, domain, url, md5, sha1, sha256, email, filename
    value: str
    
    def to_dict(self) -> Dict[str, str]:
        return {'type': self.type, 'value': self.value}


@dataclass
class StandardAlert:
    """
    Standard Alert Schema - The unified format for all alerts.
    
    All data from any source gets converted to this format
    to enable consistent processing downstream.
    """
    
    # Core identification
    id: str
    source_id: str
    source_type: str
    
    # Timing
    timestamp: str  # ISO 8601 format
    ingestion_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    parsed_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    # Classification
    severity: str = 'medium'  # low, medium, high, critical
    title: str = 'Security Alert'
    description: str = ''
    category: str = 'unknown'
    status: str = 'new'  # new, investigating, closed, false_positive
    
    # Network context
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    
    # Identity context
    user: Optional[str] = None
    user_domain: Optional[str] = None
    email: Optional[str] = None
    
    # Asset context
    hostname: Optional[str] = None
    device_id: Optional[str] = None
    os: Optional[str] = None
    
    # Threat context
    threat_name: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    
    # IOCs
    indicators: List[Dict[str, str]] = field(default_factory=list)
    
    # File information (if applicable)
    filename: Optional[str] = None
    file_path: Optional[str] = None
    file_hash_md5: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    
    # Process information (if applicable)
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None
    
    # Extra data that doesn't fit standard fields
    extra_fields: Dict[str, Any] = field(default_factory=dict)
    
    # Original data (for reference)
    raw_data: Optional[Dict[str, Any]] = None
    
    # Metadata
    parser_version: str = '1.0.0'
    confidence: float = 1.0  # 0.0 to 1.0 - how confident are we in the parsing
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StandardAlert':
        """Create StandardAlert from dictionary."""
        # Filter only valid fields
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered_data)
    
    def validate(self) -> List[str]:
        """Validate the alert and return list of issues."""
        issues = []
        
        if not self.id:
            issues.append("Missing required field: id")
        if not self.source_id:
            issues.append("Missing required field: source_id")
        if not self.timestamp:
            issues.append("Missing required field: timestamp")
        if self.severity not in ['low', 'medium', 'high', 'critical']:
            issues.append(f"Invalid severity: {self.severity}")
        if self.status not in ['new', 'investigating', 'closed', 'false_positive']:
            issues.append(f"Invalid status: {self.status}")
        
        return issues
    
    def get_risk_score(self) -> int:
        """Calculate risk score based on alert properties."""
        score = 0
        
        # Severity contribution
        severity_scores = {'low': 10, 'medium': 30, 'high': 60, 'critical': 90}
        score += severity_scores.get(self.severity, 30)
        
        # IOC count contribution
        score += min(len(self.indicators) * 2, 10)
        
        return min(score, 100)


# Example of the standard JSON output format
EXAMPLE_STANDARD_ALERT = {
    "id": "qradar_12345",
    "source_id": "qradar",
    "source_type": "SIEM",
    "timestamp": "2026-01-13T12:00:00Z",
    "ingestion_time": "2026-01-13T12:00:01Z",
    "parsed_time": "2026-01-13T12:00:02Z",
    "severity": "high",
    "title": "Suspicious Login Activity",
    "description": "Multiple failed login attempts detected from external IP",
    "category": "authentication",
    "status": "new",
    "source_ip": "203.0.113.50",
    "destination_ip": "192.168.1.100",
    "source_port": 49152,
    "destination_port": 22,
    "protocol": "SSH",
    "user": "admin",
    "hostname": "server-prod-01",
    "threat_name": "Brute Force Attack",
    "mitre_tactic": "Credential Access",
    "mitre_technique": "T1110",
    "indicators": [
        {"type": "ip", "value": "203.0.113.50"},
        {"type": "ip", "value": "203.0.113.51"}
    ],
    "extra_fields": {
        "attempt_count": 150,
        "geo_country": "Unknown"
    },
    "parser_version": "1.0.0",
    "confidence": 0.95
}
