"""
REST API Views for Sensor Service.
Handles webhook endpoints and status APIs.
"""

import json
import hmac
import hashlib
import logging
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.utils import timezone

from .models import AlertSource, IngestionLog
from .tasks import process_webhook
from .kafka_producer import get_kafka_producer

logger = logging.getLogger(__name__)


class WebhookView(APIView):
    """
    Generic webhook endpoint for receiving alerts from external sources.
    URL: POST /api/webhook/<source_id>/
    """
    
    def post(self, request, source_id):
        try:
            source = AlertSource.objects.filter(source_id=source_id, webhook_enabled=True, is_active=True).first()
            
            if not source:
                return Response({'error': 'Source not found or webhook not enabled'}, status=status.HTTP_404_NOT_FOUND)
            
            # Verify webhook signature if configured
            if source.webhook_secret:
                signature = request.headers.get('X-Signature', request.headers.get('X-Hub-Signature-256', ''))
                if not self._verify_signature(request.body, source.webhook_secret, signature):
                    return Response({'error': 'Invalid signature'}, status=status.HTTP_401_UNAUTHORIZED)
            
            # Send raw data directly to Kafka
            producer = get_kafka_producer()
            success = producer.send_raw_alert(
                source_id=source_id,
                source_type=source.source_type,
                raw_data=request.data,
                metadata={'received_at': timezone.now().isoformat(), 'content_type': request.content_type}
            )
            
            if success:
                IngestionLog.objects.create(
                    source=source, ingestion_type='webhook', status='success',
                    alerts_received=1, alerts_sent_to_kafka=1, completed_at=timezone.now()
                )
                return Response({'status': 'accepted'}, status=status.HTTP_202_ACCEPTED)
            else:
                return Response({'error': 'Failed to queue alert'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        except Exception as e:
            logger.error(f"Webhook error for {source_id}: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def _verify_signature(self, payload: bytes, secret: str, signature: str) -> bool:
        """Verify HMAC signature."""
        if not signature:
            return False
        expected = 'sha256=' + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)


class HealthView(APIView):
    """Health check endpoint."""
    
    def get(self, request):
        return Response({
            'status': 'healthy',
            'service': 'sensor',
            'timestamp': timezone.now().isoformat()
        })


class SourcesView(APIView):
    """List and manage alert sources."""
    
    def get(self, request):
        sources = AlertSource.objects.filter(is_active=True).values(
            'name', 'source_id', 'source_type', 'polling_enabled', 'webhook_enabled', 'last_poll_time', 'last_poll_status'
        )
        return Response(list(sources))


class StatsView(APIView):
    """Ingestion statistics."""
    
    def get(self, request):
        from django.db.models import Sum, Count
        from datetime import timedelta
        
        last_24h = timezone.now() - timedelta(hours=24)
        logs = IngestionLog.objects.filter(started_at__gte=last_24h)
        
        stats = logs.aggregate(
            total_received=Sum('alerts_received'),
            total_sent=Sum('alerts_sent_to_kafka'),
            total_ingestions=Count('id')
        )
        
        return Response({
            'period': 'last_24_hours',
            'alerts_received': stats['total_received'] or 0,
            'alerts_sent_to_kafka': stats['total_sent'] or 0,
            'total_ingestions': stats['total_ingestions'] or 0
        })
