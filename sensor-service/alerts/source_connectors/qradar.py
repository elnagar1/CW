"""
IBM QRadar Source Connector.
Pulls alerts/offenses from QRadar SIEM via REST API.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import requests

from .base import BaseSourceConnector

logger = logging.getLogger(__name__)


class QRadarConnector(BaseSourceConnector):
    """
    Connector for IBM QRadar SIEM.
    
    QRadar uses 'offenses' as its primary alert type.
    This connector fetches offenses and their associated events.
    """
    
    SOURCE_ID = 'qradar'
    SOURCE_TYPE = 'SIEM'
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.version = config.get('api_version', '15.0')
        self.verify_ssl = config.get('verify_ssl', True)
    
    def get_source_id(self) -> str:
        return self.SOURCE_ID
    
    def get_source_type(self) -> str:
        return self.SOURCE_TYPE
    
    def get_headers(self) -> Dict[str, str]:
        """QRadar uses SEC token for authentication."""
        return {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'SEC': self.api_key,
            'Version': self.version,
        }
    
    def authenticate(self) -> bool:
        """
        Test authentication by fetching QRadar system info.
        """
        try:
            url = f"{self.api_url}/api/system/about"
            response = requests.get(
                url,
                headers=self.get_headers(),
                verify=self.verify_ssl,
                timeout=30
            )
            
            if response.status_code == 200:
                self._authenticated = True
                logger.info(f"QRadar authentication successful")
                return True
            else:
                logger.error(f"QRadar auth failed: {response.status_code}")
                return False
                
        except requests.RequestException as e:
            logger.error(f"QRadar connection error: {e}")
            return False
    
    def fetch_alerts(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Fetch offenses from QRadar.
        
        Args:
            since: Only fetch offenses updated after this time
            
        Returns:
            List of raw offense data
        """
        try:
            # Build filter for offenses
            filters = ['status != CLOSED']
            
            if since:
                # QRadar uses milliseconds since epoch
                since_ms = int(since.timestamp() * 1000)
                filters.append(f'last_updated_time > {since_ms}')
            
            filter_str = ' AND '.join(filters)
            
            url = f"{self.api_url}/api/siem/offenses"
            params = {
                'filter': filter_str,
                'fields': 'id,description,severity,offense_type,status,start_time,last_updated_time,source_network,destination_networks,categories,offense_source,log_sources',
            }
            
            response = requests.get(
                url,
                headers=self.get_headers(),
                params=params,
                verify=self.verify_ssl,
                timeout=60
            )
            
            if response.status_code == 200:
                offenses = response.json()
                logger.info(f"Fetched {len(offenses)} offenses from QRadar")
                
                # Update last fetch time
                self.last_fetch_time = datetime.utcnow()
                
                return offenses
            else:
                logger.error(f"Failed to fetch QRadar offenses: {response.status_code}")
                return []
                
        except requests.RequestException as e:
            logger.error(f"Error fetching QRadar offenses: {e}")
            return []
    
    def fetch_offense_events(self, offense_id: int, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch events associated with a specific offense.
        
        Args:
            offense_id: QRadar offense ID
            limit: Maximum number of events to fetch
            
        Returns:
            List of event data
        """
        try:
            # Create AQL query for offense events
            aql = f"SELECT * FROM events WHERE INOFFENSE({offense_id}) LIMIT {limit}"
            
            url = f"{self.api_url}/api/ariel/searches"
            
            # Start the search
            response = requests.post(
                url,
                headers=self.get_headers(),
                params={'query_expression': aql},
                verify=self.verify_ssl,
                timeout=30
            )
            
            if response.status_code == 201:
                search_id = response.json().get('search_id')
                # In production, you'd poll for search completion
                # and then retrieve results
                logger.info(f"Started event search for offense {offense_id}: {search_id}")
                return []  # Placeholder for async result
            
            return []
            
        except requests.RequestException as e:
            logger.error(f"Error fetching offense events: {e}")
            return []
