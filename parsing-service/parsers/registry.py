"""
Parser Registry - Manages all available parsers.
Includes UniversalParser as fallback for unknown sources.
"""

import logging
from typing import Dict, Optional

from .base import BaseParser
from .qradar_parser import QRadarParser
from .crowdstrike_parser import CrowdStrikeParser
from .defender_parser import DefenderParser
from .splunk_parser import SplunkParser
from .universal_parser import UniversalParser

logger = logging.getLogger(__name__)


class ParserRegistry:
    """
    Registry for managing source-specific parsers.
    
    Uses UniversalParser as fallback for unknown sources,
    enabling parsing of ANY data format.
    """
    
    def __init__(self):
        self._parsers: Dict[str, BaseParser] = {}
        self._universal_parser = UniversalParser()
    
    def register(self, source_id: str, parser: BaseParser):
        """Register a parser for a source."""
        self._parsers[source_id] = parser
        logger.info(f"Registered parser for {source_id} (v{parser.version})")
    
    def get_parser(self, source_id: str) -> BaseParser:
        """
        Get parser for a specific source.
        
        If no specific parser exists, returns the UniversalParser
        which can handle ANY data format.
        """
        parser = self._parsers.get(source_id)
        if parser:
            return parser
        
        # Fallback to universal parser
        logger.info(f"No specific parser for {source_id}, using UniversalParser")
        return self._universal_parser
    
    def has_specific_parser(self, source_id: str) -> bool:
        """Check if a specific parser exists for this source."""
        return source_id in self._parsers
    
    def load_parsers(self):
        """Load all built-in parsers."""
        self.register('qradar', QRadarParser())
        self.register('crowdstrike', CrowdStrikeParser())
        self.register('defender', DefenderParser())
        self.register('splunk', SplunkParser())
        self.register('universal', self._universal_parser)
        logger.info(f"Loaded {len(self._parsers)} parsers (+ UniversalParser fallback)")
    
    def list_parsers(self) -> Dict[str, str]:
        """List all registered parsers with their versions."""
        parsers = {sid: p.version for sid, p in self._parsers.items()}
        parsers['_fallback'] = self._universal_parser.version
        return parsers
