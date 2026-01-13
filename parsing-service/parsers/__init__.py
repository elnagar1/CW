"""
Parser Registry and Base Parser for CyberWatch.
Includes UniversalParser for handling unknown data formats.
"""

from .registry import ParserRegistry
from .base import BaseParser
from .qradar_parser import QRadarParser
from .crowdstrike_parser import CrowdStrikeParser
from .defender_parser import DefenderParser
from .splunk_parser import SplunkParser
from .universal_parser import UniversalParser
from .schema import StandardAlert, Severity, Status, Indicator

__all__ = [
    'ParserRegistry',
    'BaseParser',
    'QRadarParser',
    'CrowdStrikeParser',
    'DefenderParser',
    'SplunkParser',
    'UniversalParser',
    'StandardAlert',
    'Severity',
    'Status',
    'Indicator',
]
