"""
Base Source Connector - Abstract class for all source connectors.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class BaseSourceConnector(ABC):
    """
    Abstract base class for all alert source connectors.
    
    Each source connector must implement:
    - authenticate(): Handle authentication with the source
    - fetch_alerts(): Pull alerts from the source
    - get_source_id(): Return unique source identifier
    - get_source_type(): Return source type (SIEM, EDR, etc.)
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the connector with configuration.
        
        Args:
            config: Dictionary containing connection details
                - api_url: Base URL for the source API
                - api_key: API key or token
                - auth_type: Authentication type
                - Additional source-specific config
        """
        self.config = config
        self.api_url = config.get('api_url', '')
        self.api_key = config.get('api_key', '')
        self.auth_type = config.get('auth_type', 'bearer')
        self.last_fetch_time: Optional[datetime] = None
        self._authenticated = False
    
    @abstractmethod
    def get_source_id(self) -> str:
        """Return unique identifier for this source."""
        pass
    
    @abstractmethod
    def get_source_type(self) -> str:
        """Return the type of source (SIEM, EDR, AV, etc.)."""
        pass
    
    @abstractmethod
    def authenticate(self) -> bool:
        """
        Authenticate with the source.
        
        Returns:
            bool: True if authentication successful
        """
        pass
    
    @abstractmethod
    def fetch_alerts(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Fetch alerts from the source.
        
        Args:
            since: Only fetch alerts after this timestamp
            
        Returns:
            List of raw alert dictionaries
        """
        pass
    
    def test_connection(self) -> bool:
        """
        Test connectivity to the source.
        
        Returns:
            bool: True if connection successful
        """
        try:
            return self.authenticate()
        except Exception as e:
            logger.error(f"Connection test failed for {self.get_source_id()}: {e}")
            return False
    
    def get_headers(self) -> Dict[str, str]:
        """
        Get HTTP headers for API requests.
        
        Returns:
            Dict of headers
        """
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        
        if self.auth_type == 'bearer':
            headers['Authorization'] = f'Bearer {self.api_key}'
        elif self.auth_type == 'api_key':
            headers['X-API-Key'] = self.api_key
        
        return headers
