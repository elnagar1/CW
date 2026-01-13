"""
Parser Registry - Manages all available parsers.
"""

import logging
from typing import Dict, Optional

from .base import BaseParser
from .qradar_parser import QRadarParser
from .crowdstrike_parser import CrowdStrikeParser
from .defender_parser import DefenderParser
from .splunk_parser import SplunkParser

logger = logging.getLogger(__name__)


class ParserRegistry:
    """Registry for managing source-specific parsers."""
    
    def __init__(self):
        self._parsers: Dict[str, BaseParser] = {}
    
    def register(self, source_id: str, parser: BaseParser):
        """Register a parser for a source."""
        self._parsers[source_id] = parser
        logger.info(f"Registered parser for {source_id} (v{parser.version})")
    
    def get_parser(self, source_id: str) -> Optional[BaseParser]:
        """Get parser for a specific source."""
        return self._parsers.get(source_id)
    
    def load_parsers(self):
        """Load all built-in parsers."""
        self.register('qradar', QRadarParser())
        self.register('crowdstrike', CrowdStrikeParser())
        self.register('defender', DefenderParser())
        self.register('splunk', SplunkParser())
        logger.info(f"Loaded {len(self._parsers)} parsers")
    
    def list_parsers(self) -> Dict[str, str]:
        """List all registered parsers with their versions."""
        return {sid: p.version for sid, p in self._parsers.items()}
