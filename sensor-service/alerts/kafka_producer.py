"""
Kafka Producer for sending raw alerts to alerts.raw topic.
This is the core component that pushes data into the Kafka pipeline.
"""

import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from kafka import KafkaProducer
from kafka.errors import KafkaError
from django.conf import settings

logger = logging.getLogger(__name__)


class AlertKafkaProducer:
    """
    Kafka Producer for CyberWatch alerts.
    Sends raw alerts to alerts.raw topic without any parsing.
    """
    
    _instance: Optional['AlertKafkaProducer'] = None
    _producer: Optional[KafkaProducer] = None
    
    def __new__(cls):
        """Singleton pattern for Kafka producer."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize Kafka producer if not already initialized."""
        if self._producer is None:
            self._connect()
    
    def _connect(self):
        """Establish connection to Kafka."""
        try:
            self._producer = KafkaProducer(
                bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS.split(','),
                value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
                key_serializer=lambda k: k.encode('utf-8') if k else None,
                acks='all',  # Wait for all replicas
                retries=3,
                retry_backoff_ms=1000,
                max_block_ms=10000,
            )
            logger.info(f"Connected to Kafka at {settings.KAFKA_BOOTSTRAP_SERVERS}")
        except KafkaError as e:
            logger.error(f"Failed to connect to Kafka: {e}")
            raise
    
    def send_raw_alert(
        self,
        source_id: str,
        source_type: str,
        raw_data: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Send a raw alert to the alerts.raw Kafka topic.
        
        The alert is wrapped with metadata but the actual alert data
        remains untouched (raw) for the Parsing Service to process.
        
        Args:
            source_id: Unique identifier of the alert source (e.g., 'qradar', 'crowdstrike')
            source_type: Type of source (e.g., 'SIEM', 'EDR')
            raw_data: The raw alert data exactly as received from the source
            metadata: Optional additional metadata
            
        Returns:
            bool: True if sent successfully, False otherwise
        """
        try:
            # Wrap raw data with envelope metadata
            message = {
                'envelope': {
                    'source_id': source_id,
                    'source_type': source_type,
                    'ingestion_time': datetime.utcnow().isoformat(),
                    'sensor_version': '1.0.0',
                    'metadata': metadata or {}
                },
                'raw_data': raw_data  # Keep raw data untouched
            }
            
            # Use source_id as the message key for partitioning
            future = self._producer.send(
                topic=settings.KAFKA_RAW_TOPIC,
                key=source_id,
                value=message
            )
            
            # Wait for confirmation
            record_metadata = future.get(timeout=10)
            
            logger.debug(
                f"Alert sent to {record_metadata.topic} "
                f"partition {record_metadata.partition} "
                f"offset {record_metadata.offset}"
            )
            
            return True
            
        except KafkaError as e:
            logger.error(f"Failed to send alert to Kafka: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending alert: {e}")
            return False
    
    def send_batch(
        self,
        source_id: str,
        source_type: str,
        alerts: list,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, int]:
        """
        Send a batch of raw alerts to Kafka.
        
        Args:
            source_id: Unique identifier of the alert source
            source_type: Type of source
            alerts: List of raw alert data
            metadata: Optional additional metadata
            
        Returns:
            Dict with 'success' and 'failed' counts
        """
        results = {'success': 0, 'failed': 0}
        
        for alert in alerts:
            if self.send_raw_alert(source_id, source_type, alert, metadata):
                results['success'] += 1
            else:
                results['failed'] += 1
        
        # Ensure all messages are sent
        self._producer.flush()
        
        logger.info(
            f"Batch send complete for {source_id}: "
            f"{results['success']} success, {results['failed']} failed"
        )
        
        return results
    
    def close(self):
        """Close the Kafka producer connection."""
        if self._producer:
            self._producer.flush()
            self._producer.close()
            self._producer = None
            logger.info("Kafka producer closed")


# Global producer instance
def get_kafka_producer() -> AlertKafkaProducer:
    """Get the singleton Kafka producer instance."""
    return AlertKafkaProducer()
