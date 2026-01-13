"""
Parser Registry and Base Parser for CyberWatch.
Includes UniversalParser for handling unknown data formats.
Supports: JSON, XML, Syslog, CEF, LEEF, CSV, Key-Value, Plain Text
"""

from .registry import ParserRegistry
from .base import BaseParser
from .qradar_parser import QRadarParser
from .crowdstrike_parser import CrowdStrikeParser
from .defender_parser import DefenderParser
from .splunk_parser import SplunkParser
from .universal_parser import UniversalParser
from .format_detector import FormatDetector, get_format_detector
from .schema import StandardAlert, Severity, Status, Indicator

__all__ = [
    'ParserRegistry',
    'BaseParser',
    'QRadarParser',
    'CrowdStrikeParser',
    'DefenderParser',
    'SplunkParser',
    'UniversalParser',
    'FormatDetector',
    'get_format_detector',
    'StandardAlert',
    'Severity',
    'Status',
    'Indicator',
]
