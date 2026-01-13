"""
CrowdStrike Falcon Source Connector.
Pulls detections from CrowdStrike EDR via Falcon API.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import requests

from .base import BaseSourceConnector

logger = logging.getLogger(__name__)


class CrowdStrikeConnector(BaseSourceConnector):
    """
    Connector for CrowdStrike Falcon EDR.
    
    CrowdStrike uses OAuth2 for authentication and provides
    detections through the Falcon API.
    """
    
    SOURCE_ID = 'crowdstrike'
    SOURCE_TYPE = 'EDR'
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.client_id = config.get('client_id', '')
        self.client_secret = config.get('client_secret', '')
        self.access_token: Optional[str] = None
        self.token_expiry: Optional[datetime] = None
    
    def get_source_id(self) -> str:
        return self.SOURCE_ID
    
    def get_source_type(self) -> str:
        return self.SOURCE_TYPE
    
    def authenticate(self) -> bool:
        """
        Obtain OAuth2 access token from CrowdStrike.
        """
        try:
            url = f"{self.api_url}/oauth2/token"
            
            response = requests.post(
                url,
                data={
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                },
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=30
            )
            
            if response.status_code == 201:
                token_data = response.json()
                self.access_token = token_data.get('access_token')
                expires_in = token_data.get('expires_in', 1800)
                
                from datetime import timedelta
                self.token_expiry = datetime.utcnow() + timedelta(seconds=expires_in - 60)
                
                self._authenticated = True
                logger.info("CrowdStrike authentication successful")
                return True
            else:
                logger.error(f"CrowdStrike auth failed: {response.status_code}")
                return False
                
        except requests.RequestException as e:
            logger.error(f"CrowdStrike connection error: {e}")
            return False
    
    def _ensure_authenticated(self) -> bool:
        """Ensure we have a valid access token."""
        if not self.access_token or (
            self.token_expiry and datetime.utcnow() >= self.token_expiry
        ):
            return self.authenticate()
        return True
    
    def get_headers(self) -> Dict[str, str]:
        return {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': f'Bearer {self.access_token}',
        }
    
    def fetch_alerts(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Fetch detections from CrowdStrike.
        
        Args:
            since: Only fetch detections after this time
            
        Returns:
            List of raw detection data
        """
        if not self._ensure_authenticated():
            return []
        
        try:
            # First, get detection IDs
            url = f"{self.api_url}/detects/queries/detects/v1"
            
            filters = ['status:["new","in_progress"]']
            if since:
                since_str = since.strftime('%Y-%m-%dT%H:%M:%SZ')
                filters.append(f'last_behavior:>"{since_str}"')
            
            params = {
                'filter': '+'.join(filters),
                'limit': 500,
                'sort': 'last_behavior|desc',
            }
            
            response = requests.get(
                url,
                headers=self.get_headers(),
                params=params,
                timeout=60
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to query CrowdStrike detections: {response.status_code}")
                return []
            
            detection_ids = response.json().get('resources', [])
            
            if not detection_ids:
                logger.info("No new CrowdStrike detections found")
                return []
            
            # Now fetch full detection details
            details_url = f"{self.api_url}/detects/entities/summaries/GET/v1"
            
            details_response = requests.post(
                details_url,
                headers=self.get_headers(),
                json={'ids': detection_ids},
                timeout=60
            )
            
            if details_response.status_code == 200:
                detections = details_response.json().get('resources', [])
                logger.info(f"Fetched {len(detections)} detections from CrowdStrike")
                
                self.last_fetch_time = datetime.utcnow()
                return detections
            else:
                logger.error(f"Failed to get detection details: {details_response.status_code}")
                return []
                
        except requests.RequestException as e:
            logger.error(f"Error fetching CrowdStrike detections: {e}")
            return []
