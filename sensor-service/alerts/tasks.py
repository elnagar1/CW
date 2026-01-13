"""
Celery Tasks for Sensor Service.
Handles periodic polling from alert sources and webhook processing.
"""

import logging
from datetime import datetime, timedelta
from celery import shared_task
from django.utils import timezone

from .kafka_producer import get_kafka_producer
from .models import AlertSource, IngestionLog
from .source_connectors import QRadarConnector, CrowdStrikeConnector, DefenderConnector, SplunkConnector

logger = logging.getLogger(__name__)


def get_connector_for_source(source: AlertSource):
    """Get the appropriate connector for an alert source."""
    connectors = {
        'qradar': QRadarConnector,
        'crowdstrike': CrowdStrikeConnector,
        'defender': DefenderConnector,
        'splunk': SplunkConnector,
    }
    
    connector_class = connectors.get(source.source_id)
    if not connector_class:
        return None
    
    config = {
        'api_url': source.api_url,
        'api_key': source.api_key,
        'auth_type': source.auth_type,
    }
    return connector_class(config)


def poll_source(source_id: str):
    """Generic polling function for any source."""
    try:
        source = AlertSource.objects.filter(source_id=source_id, is_active=True, polling_enabled=True).first()
        if not source:
            logger.info(f"Source {source_id} not found or not enabled")
            return
        
        log = IngestionLog.objects.create(source=source, ingestion_type='poll')
        connector = get_connector_for_source(source)
        
        if not connector:
            log.status = 'error'
            log.error_message = f"No connector for {source_id}"
            log.completed_at = timezone.now()
            log.save()
            return
        
        since = source.last_poll_time or (timezone.now() - timedelta(hours=24))
        alerts = connector.fetch_alerts(since=since)
        
        log.alerts_received = len(alerts)
        
        if alerts:
            producer = get_kafka_producer()
            result = producer.send_batch(source_id, connector.get_source_type(), alerts)
            log.alerts_sent_to_kafka = result['success']
        
        source.last_poll_time = timezone.now()
        source.last_poll_status = 'success'
        source.save()
        
        log.status = 'success'
        log.completed_at = timezone.now()
        log.save()
        
        logger.info(f"Polled {len(alerts)} alerts from {source_id}")
        
    except Exception as e:
        logger.error(f"Error polling {source_id}: {e}")


@shared_task(name='alerts.tasks.poll_qradar_alerts')
def poll_qradar_alerts():
    """Poll alerts from QRadar."""
    poll_source('qradar')


@shared_task(name='alerts.tasks.poll_crowdstrike_alerts')
def poll_crowdstrike_alerts():
    """Poll alerts from CrowdStrike."""
    poll_source('crowdstrike')


@shared_task(name='alerts.tasks.poll_defender_alerts')
def poll_defender_alerts():
    """Poll alerts from Microsoft Defender."""
    poll_source('defender')


@shared_task(name='alerts.tasks.poll_splunk_alerts')
def poll_splunk_alerts():
    """Poll alerts from Splunk."""
    poll_source('splunk')


@shared_task(name='alerts.tasks.health_check')
def health_check():
    """Health check task."""
    logger.info(f"Sensor health check at {timezone.now()}")
    return {'status': 'healthy', 'timestamp': str(timezone.now())}


@shared_task(name='alerts.tasks.process_webhook')
def process_webhook(source_id: str, payload: dict):
    """Process incoming webhook data."""
    try:
        source = AlertSource.objects.filter(source_id=source_id, webhook_enabled=True).first()
        if not source:
            return
        
        log = IngestionLog.objects.create(source=source, ingestion_type='webhook', alerts_received=1)
        
        producer = get_kafka_producer()
        if producer.send_raw_alert(source_id, source.source_type, payload):
            log.alerts_sent_to_kafka = 1
            log.status = 'success'
        else:
            log.status = 'error'
        
        log.completed_at = timezone.now()
        log.save()
        
    except Exception as e:
        logger.error(f"Error processing webhook from {source_id}: {e}")
