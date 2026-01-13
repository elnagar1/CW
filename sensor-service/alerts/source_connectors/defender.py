"""
Microsoft Defender for Endpoint Source Connector.
Pulls alerts from Microsoft 365 Defender via Graph API.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import requests

from .base import BaseSourceConnector

logger = logging.getLogger(__name__)


class DefenderConnector(BaseSourceConnector):
    """Connector for Microsoft Defender for Endpoint using Microsoft Graph API."""
    
    SOURCE_ID = 'defender'
    SOURCE_TYPE = 'EDR'
    GRAPH_URL = 'https://graph.microsoft.com/v1.0'
    AUTH_URL = 'https://login.microsoftonline.com'
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.tenant_id = config.get('tenant_id', '')
        self.client_id = config.get('client_id', '')
        self.client_secret = config.get('client_secret', '')
        self.access_token: Optional[str] = None
        self.token_expiry: Optional[datetime] = None
    
    def get_source_id(self) -> str:
        return self.SOURCE_ID
    
    def get_source_type(self) -> str:
        return self.SOURCE_TYPE
    
    def authenticate(self) -> bool:
        """Obtain OAuth2 access token from Azure AD."""
        try:
            url = f"{self.AUTH_URL}/{self.tenant_id}/oauth2/v2.0/token"
            response = requests.post(url, data={
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'scope': 'https://graph.microsoft.com/.default',
                'grant_type': 'client_credentials',
            }, timeout=30)
            
            if response.status_code == 200:
                token_data = response.json()
                self.access_token = token_data.get('access_token')
                self.token_expiry = datetime.utcnow() + timedelta(seconds=token_data.get('expires_in', 3600) - 60)
                self._authenticated = True
                return True
            return False
        except requests.RequestException as e:
            logger.error(f"Defender connection error: {e}")
            return False
    
    def get_headers(self) -> Dict[str, str]:
        return {'Authorization': f'Bearer {self.access_token}', 'Content-Type': 'application/json'}
    
    def fetch_alerts(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Fetch security alerts from Microsoft Defender."""
        if not self.access_token or (self.token_expiry and datetime.utcnow() >= self.token_expiry):
            if not self.authenticate():
                return []
        
        try:
            url = f"{self.GRAPH_URL}/security/alerts_v2"
            filters = ["status ne 'resolved'"]
            if since:
                filters.append(f"createdDateTime ge {since.strftime('%Y-%m-%dT%H:%M:%SZ')}")
            
            response = requests.get(url, headers=self.get_headers(), 
                                   params={'$filter': ' and '.join(filters), '$top': 500}, timeout=60)
            
            if response.status_code == 200:
                alerts = response.json().get('value', [])
                self.last_fetch_time = datetime.utcnow()
                return alerts
            return []
        except requests.RequestException as e:
            logger.error(f"Error fetching Defender alerts: {e}")
            return []
