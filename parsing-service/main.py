"""
CyberWatch Parsing Service
Consumes raw alerts from alerts.raw and produces parsed alerts to alerts.parsed
"""

import os
import json
import logging
import signal
import sys
from datetime import datetime

from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError

from parsers import ParserRegistry

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('parsing-service')

# Configuration
KAFKA_BOOTSTRAP_SERVERS = os.environ.get('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092')
KAFKA_GROUP_ID = os.environ.get('KAFKA_GROUP_ID', 'parsing-service-group')
KAFKA_INPUT_TOPIC = os.environ.get('KAFKA_INPUT_TOPIC', 'alerts.raw')
KAFKA_OUTPUT_TOPIC = os.environ.get('KAFKA_OUTPUT_TOPIC', 'alerts.parsed')

# Global flag for graceful shutdown
running = True


def signal_handler(signum, frame):
    """Handle shutdown signals."""
    global running
    logger.info("Shutdown signal received")
    running = False


def create_consumer() -> KafkaConsumer:
    """Create Kafka consumer for alerts.raw topic."""
    return KafkaConsumer(
        KAFKA_INPUT_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS.split(','),
        group_id=KAFKA_GROUP_ID,
        auto_offset_reset='earliest',
        enable_auto_commit=True,
        value_deserializer=lambda m: json.loads(m.decode('utf-8')),
        max_poll_interval_ms=300000,
        session_timeout_ms=30000,
    )


def create_producer() -> KafkaProducer:
    """Create Kafka producer for alerts.parsed topic."""
    return KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS.split(','),
        value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
        key_serializer=lambda k: k.encode('utf-8') if k else None,
        acks='all',
        retries=3,
    )


def process_message(message: dict, parser_registry: ParserRegistry) -> dict:
    """
    Process a raw alert message and convert to standard format.
    
    Uses specific parsers when available, falls back to UniversalParser
    for unknown data formats. This ensures ALL data is parsed successfully.
    
    Args:
        message: Raw message from alerts.raw topic
        parser_registry: Registry containing all parsers
        
    Returns:
        Parsed alert in standard format
    """
    envelope = message.get('envelope', {})
    raw_data = message.get('raw_data', {})
    source_id = envelope.get('source_id', 'unknown')
    source_type = envelope.get('source_type', 'unknown')
    
    # Get appropriate parser (UniversalParser is used as fallback)
    parser = parser_registry.get_parser(source_id)
    using_universal = not parser_registry.has_specific_parser(source_id)
    
    try:
        parsed_data = parser.parse(raw_data)
        parse_success = True
        parse_error = None
    except Exception as e:
        logger.error(f"Parser error for {source_id}: {e}")
        parse_success = False
        parse_error = str(e)
        parsed_data = {}
    
    # Build standard alert structure
    alert = {
        'id': parsed_data.get('id', f"{source_id}_{datetime.utcnow().timestamp()}"),
        'source_id': source_id,
        'source_type': source_type,
        'timestamp': parsed_data.get('timestamp', datetime.utcnow().isoformat()),
        'severity': parsed_data.get('severity', 'medium'),
        'title': parsed_data.get('title', 'Security Alert'),
        'description': parsed_data.get('description', ''),
        'category': parsed_data.get('category', 'unknown'),
        'status': parsed_data.get('status', 'new'),
        'source_ip': parsed_data.get('source_ip'),
        'destination_ip': parsed_data.get('destination_ip'),
        'user': parsed_data.get('user'),
        'hostname': parsed_data.get('hostname'),
        'indicators': parsed_data.get('indicators', []),
        'extra_fields': parsed_data.get('extra_fields', {}),
        'raw_data': raw_data,
        'metadata': {
            'ingestion_time': envelope.get('ingestion_time'),
            'parsed_time': datetime.utcnow().isoformat(),
            'parser_version': parser.version,
            'parser_type': 'universal' if using_universal else 'specific',
            'parse_success': parse_success,
            'parse_error': parse_error,
        }
    }
    
    # Log parsing method
    if using_universal:
        logger.info(f"Parsed {source_id} alert using UniversalParser -> {alert['id']}")
    else:
        logger.debug(f"Parsed {source_id} alert using {parser.source_id} parser -> {alert['id']}")
    
    return alert


def main():
    """Main entry point for the Parsing Service."""
    global running
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info(f"Starting Parsing Service")
    logger.info(f"Kafka: {KAFKA_BOOTSTRAP_SERVERS}")
    logger.info(f"Consumer Group: {KAFKA_GROUP_ID}")
    logger.info(f"Input Topic: {KAFKA_INPUT_TOPIC}")
    logger.info(f"Output Topic: {KAFKA_OUTPUT_TOPIC}")
    
    # Initialize parser registry
    parser_registry = ParserRegistry()
    parser_registry.load_parsers()
    
    consumer = None
    producer = None
    
    try:
        consumer = create_consumer()
        producer = create_producer()
        
        logger.info("Connected to Kafka, starting to consume messages...")
        
        while running:
            messages = consumer.poll(timeout_ms=1000)
            
            for topic_partition, records in messages.items():
                for record in records:
                    try:
                        parsed_alert = process_message(record.value, parser_registry)
                        
                        producer.send(
                            topic=KAFKA_OUTPUT_TOPIC,
                            key=parsed_alert['source_id'],
                            value=parsed_alert
                        )
                        
                        logger.debug(f"Processed alert: {parsed_alert['id']}")
                        
                    except Exception as e:
                        logger.error(f"Error processing message: {e}")
            
            producer.flush()
            
    except KafkaError as e:
        logger.error(f"Kafka error: {e}")
        sys.exit(1)
    finally:
        if consumer:
            consumer.close()
        if producer:
            producer.close()
        logger.info("Parsing Service stopped")


if __name__ == '__main__':
    main()
