from celery import shared_task
import requests
import json
import logging
from django.conf import settings
from .models import AlertSource
from kafka import KafkaProducer

logger = logging.getLogger(__name__)

# Kafka Producer Configuration
producer = KafkaProducer(
    bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

def send_to_kafka(data, source_type, data_format):
    """Helper to send pulled data to Kafka"""
    topic = getattr(settings, 'KAFKA_RAW_TOPIC', 'alerts.raw')
    
    # Wrap in envelope similar to webhooks
    envelope = {
        'envelope': {
            'source_id': source_type,
            'source_type': source_type,
            'ingestion_time': 'now', # Will be parsed by parser
            'metadata': {
                'ingestion_method': 'pull',
                'data_format': data_format
            }
        },
        'raw_data': data
    }
    
    producer.send(topic, envelope)
    producer.flush()

@shared_task
def pull_qradar_alerts():
    """Pull offenses from QRadar Mock API"""
    try:
        # In a real app, URL and Token would be in DB or Vault. 
        # Using service name 'mock-sources' resolvable in docker network
        url = "http://mock-sources:9000/api/siem/offenses"
        response = requests.get(url, params={'limit': 10}, timeout=10)
        
        if response.status_code == 200:
            offenses = response.json()
            for offense in offenses:
                send_to_kafka(offense, 'qradar', 'json')
            logger.info(f"Successfully pulled {len(offenses)} offenses from QRadar")
            return f"Pulled {len(offenses)} offenses"
        else:
            logger.error(f"Failed to pull from QRadar: {response.text}")
    except Exception as e:
        logger.error(f"Error pulling from QRadar: {str(e)}")

@shared_task
def pull_crowdstrike_alerts():
    """Pull detections from CrowdStrike Mock API"""
    try:
        # Step 1: Get Detection IDs
        base_url = "http://mock-sources:9000"
        ids_response = requests.get(f"{base_url}/detects/queries/detects/v1", params={'limit': 10}, timeout=10)
        
        if ids_response.status_code == 200:
            ids = ids_response.json().get('resources', [])
            if ids:
                # Step 2: Get Details
                details_response = requests.post(
                    f"{base_url}/detects/entities/summaries/GET/v2",
                    json={'ids': ids},
                    timeout=10
                )
                if details_response.status_code == 200:
                    detections = details_response.json().get('resources', [])
                    for detection in detections:
                        send_to_kafka(detection, 'crowdstrike', 'json')
                    logger.info(f"Successfully pulled {len(detections)} detections from CrowdStrike")
                    return f"Pulled {len(detections)} detections"
    except Exception as e:
        logger.error(f"Error pulling from CrowdStrike: {str(e)}")

@shared_task
def pull_defender_alerts():
    """Pull alerts from Microsoft Defender Mock API"""
    try:
        url = "http://mock-sources:9000/api/alerts"
        # OData format simulation
        response = requests.get(url, params={'$top': 10}, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            alerts = data.get('value', [])
            for alert in alerts:
                send_to_kafka(alert, 'defender', 'json')
            logger.info(f"Successfully pulled {len(alerts)} alerts from Defender")
            return f"Pulled {len(alerts)} alerts"
    except Exception as e:
        logger.error(f"Error pulling from Defender: {str(e)}")

@shared_task
def pull_splunk_alerts():
    """Pull notable events from Splunk Mock API"""
    try:
        url = "http://mock-sources:9000/services/notable"
        response = requests.get(url, params={'count': 10}, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            events = data.get('results', [])
            for event in events:
                send_to_kafka(event, 'splunk', 'json')
            logger.info(f"Successfully pulled {len(events)} events from Splunk")
            return f"Pulled {len(events)} events"
    except Exception as e:
        logger.error(f"Error pulling from Splunk: {str(e)}")
