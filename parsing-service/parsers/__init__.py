"""
Parser Registry and Base Parser for CyberWatch.
"""

from .registry import ParserRegistry
from .base import BaseParser
from .qradar_parser import QRadarParser
from .crowdstrike_parser import CrowdStrikeParser
from .defender_parser import DefenderParser
from .splunk_parser import SplunkParser

__all__ = [
    'ParserRegistry',
    'BaseParser',
    'QRadarParser',
    'CrowdStrikeParser',
    'DefenderParser',
    'SplunkParser',
]
