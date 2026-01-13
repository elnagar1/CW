"""
Syslog Listener Service - Receives syslog messages on UDP/TCP and forwards to Kafka.
Supports RFC 3164, RFC 5424, CEF, and LEEF formats.
"""

import os
import json
import socket
import logging
import threading
import signal
import sys
from datetime import datetime
from typing import Optional
from kafka import KafkaProducer

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('syslog-listener')

# Configuration
SYSLOG_UDP_PORT = int(os.environ.get('SYSLOG_UDP_PORT', 1514))
SYSLOG_TCP_PORT = int(os.environ.get('SYSLOG_TCP_PORT', 1515))
KAFKA_BOOTSTRAP_SERVERS = os.environ.get('KAFKA_BOOTSTRAP_SERVERS', 'kafka:29092')
KAFKA_TOPIC = os.environ.get('KAFKA_TOPIC', 'alerts.raw')
BUFFER_SIZE = 65535


class SyslogKafkaProducer:
    """Kafka producer for syslog messages."""
    
    def __init__(self):
        self._producer: Optional[KafkaProducer] = None
        self._connect()
    
    def _connect(self):
        """Connect to Kafka with retry logic."""
        max_retries = 10
        for attempt in range(max_retries):
            try:
                self._producer = KafkaProducer(
                    bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS.split(','),
                    value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
                    acks='all',
                    retries=3,
                    max_block_ms=10000
                )
                logger.info(f"Connected to Kafka at {KAFKA_BOOTSTRAP_SERVERS}")
                return
            except Exception as e:
                logger.warning(f"Kafka connection attempt {attempt + 1}/{max_retries} failed: {e}")
                if attempt < max_retries - 1:
                    import time
                    time.sleep(5)
        
        logger.error("Failed to connect to Kafka after all retries")
        raise Exception("Kafka connection failed")
    
    def send(self, message: str, source_ip: str, protocol: str):
        """Send syslog message to Kafka."""
        try:
            envelope = {
                'envelope': {
                    'source_id': 'syslog',
                    'source_type': 'Syslog',
                    'ingestion_time': datetime.utcnow().isoformat(),
                    'sensor_version': '1.0.0',
                    'metadata': {
                        'received_at': datetime.utcnow().isoformat(),
                        'content_type': 'text/plain',
                        'data_format': 'syslog',
                        'source_ip': source_ip,
                        'protocol': protocol
                    }
                },
                'raw_data': message
            }
            
            future = self._producer.send(KAFKA_TOPIC, value=envelope)
            future.get(timeout=10)
            logger.debug(f"Sent message from {source_ip} to Kafka")
            return True
        except Exception as e:
            logger.error(f"Failed to send to Kafka: {e}")
            return False
    
    def close(self):
        """Close the producer."""
        if self._producer:
            self._producer.close()


class UDPSyslogListener(threading.Thread):
    """UDP Syslog listener."""
    
    def __init__(self, producer: SyslogKafkaProducer, port: int = SYSLOG_UDP_PORT):
        super().__init__(daemon=True)
        self.producer = producer
        self.port = port
        self.running = False
        self.socket: Optional[socket.socket] = None
        self.message_count = 0
    
    def run(self):
        """Start listening for UDP syslog messages."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            self.socket.settimeout(1.0)
            self.running = True
            
            logger.info(f"UDP Syslog listener started on port {self.port}")
            
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(BUFFER_SIZE)
                    message = data.decode('utf-8', errors='replace').strip()
                    
                    if message:
                        self.producer.send(message, addr[0], 'UDP')
                        self.message_count += 1
                        
                        if self.message_count % 100 == 0:
                            logger.info(f"UDP: Received {self.message_count} messages")
                            
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"UDP receive error: {e}")
                    
        except Exception as e:
            logger.error(f"UDP listener error: {e}")
        finally:
            if self.socket:
                self.socket.close()
            logger.info("UDP Syslog listener stopped")
    
    def stop(self):
        """Stop the listener."""
        self.running = False


class TCPSyslogListener(threading.Thread):
    """TCP Syslog listener with connection handling."""
    
    def __init__(self, producer: SyslogKafkaProducer, port: int = SYSLOG_TCP_PORT):
        super().__init__(daemon=True)
        self.producer = producer
        self.port = port
        self.running = False
        self.socket: Optional[socket.socket] = None
        self.clients: list = []
        self.message_count = 0
    
    def run(self):
        """Start listening for TCP syslog connections."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            self.socket.listen(50)
            self.socket.settimeout(1.0)
            self.running = True
            
            logger.info(f"TCP Syslog listener started on port {self.port}")
            
            while self.running:
                try:
                    client_socket, addr = self.socket.accept()
                    client_handler = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, addr),
                        daemon=True
                    )
                    client_handler.start()
                    self.clients.append(client_handler)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"TCP accept error: {e}")
                        
        except Exception as e:
            logger.error(f"TCP listener error: {e}")
        finally:
            if self.socket:
                self.socket.close()
            logger.info("TCP Syslog listener stopped")
    
    def _handle_client(self, client_socket: socket.socket, addr: tuple):
        """Handle a TCP client connection."""
        client_socket.settimeout(60.0)
        buffer = ""
        
        try:
            logger.debug(f"TCP connection from {addr[0]}:{addr[1]}")
            
            while self.running:
                try:
                    data = client_socket.recv(BUFFER_SIZE)
                    if not data:
                        break
                    
                    buffer += data.decode('utf-8', errors='replace')
                    
                    # Process complete messages (newline delimited)
                    while '\n' in buffer:
                        message, buffer = buffer.split('\n', 1)
                        message = message.strip()
                        
                        if message:
                            self.producer.send(message, addr[0], 'TCP')
                            self.message_count += 1
                            
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"TCP client error: {e}")
                    break
                    
        finally:
            client_socket.close()
            logger.debug(f"TCP connection closed from {addr[0]}:{addr[1]}")
    
    def stop(self):
        """Stop the listener."""
        self.running = False


class SyslogService:
    """Main syslog service that manages UDP and TCP listeners."""
    
    def __init__(self):
        self.producer = SyslogKafkaProducer()
        self.udp_listener = UDPSyslogListener(self.producer)
        self.tcp_listener = TCPSyslogListener(self.producer)
        self.running = False
    
    def start(self):
        """Start the syslog service."""
        logger.info("Starting Syslog Service...")
        self.running = True
        
        # Start listeners
        self.udp_listener.start()
        self.tcp_listener.start()
        
        logger.info("=" * 60)
        logger.info("🔊 Syslog Listener Service Started!")
        logger.info(f"   UDP Port: {SYSLOG_UDP_PORT}")
        logger.info(f"   TCP Port: {SYSLOG_TCP_PORT}")
        logger.info(f"   Kafka: {KAFKA_BOOTSTRAP_SERVERS}")
        logger.info("=" * 60)
        
        # Wait for shutdown
        try:
            while self.running:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Received shutdown signal")
        
        self.stop()
    
    def stop(self):
        """Stop the syslog service."""
        logger.info("Stopping Syslog Service...")
        self.running = False
        self.udp_listener.stop()
        self.tcp_listener.stop()
        self.producer.close()
        logger.info("Syslog Service stopped")


def main():
    """Main entry point."""
    service = SyslogService()
    
    # Handle signals
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}")
        service.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    service.start()


if __name__ == '__main__':
    main()
