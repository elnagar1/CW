"""
Splunk Source Connector.
Pulls alerts from Splunk via REST API.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import requests

from .base import BaseSourceConnector

logger = logging.getLogger(__name__)


class SplunkConnector(BaseSourceConnector):
    """Connector for Splunk SIEM using REST API."""
    
    SOURCE_ID = 'splunk'
    SOURCE_TYPE = 'SIEM'
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.username = config.get('username', '')
        self.password = config.get('password', '')
        self.verify_ssl = config.get('verify_ssl', True)
    
    def get_source_id(self) -> str:
        return self.SOURCE_ID
    
    def get_source_type(self) -> str:
        return self.SOURCE_TYPE
    
    def authenticate(self) -> bool:
        """Test authentication with Splunk."""
        try:
            url = f"{self.api_url}/services/authentication/current-context"
            response = requests.get(url, auth=(self.username, self.password),
                                   verify=self.verify_ssl, timeout=30)
            self._authenticated = response.status_code == 200
            return self._authenticated
        except requests.RequestException as e:
            logger.error(f"Splunk connection error: {e}")
            return False
    
    def fetch_alerts(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Fetch notable events from Splunk Enterprise Security."""
        try:
            url = f"{self.api_url}/services/search/jobs"
            search_query = '| from datamodel:"Risk"."All_Risk" | where status!="resolved"'
            if since:
                search_query += f' | where _time > "{since.strftime("%Y-%m-%d %H:%M:%S")}"'
            
            response = requests.post(url, auth=(self.username, self.password),
                data={'search': f'search {search_query}', 'output_mode': 'json', 'exec_mode': 'oneshot'},
                verify=self.verify_ssl, timeout=120)
            
            if response.status_code == 200:
                results = response.json().get('results', [])
                self.last_fetch_time = datetime.utcnow()
                return results
            return []
        except requests.RequestException as e:
            logger.error(f"Error fetching Splunk alerts: {e}")
            return []
