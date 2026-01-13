"""
Models for tracking alert sources and ingestion status.
"""

from django.db import models
from django.utils import timezone


class AlertSource(models.Model):
    """Registered alert sources (SIEM, EDR, etc.)"""
    
    SOURCE_TYPES = [
        ('SIEM', 'Security Information and Event Management'),
        ('EDR', 'Endpoint Detection and Response'),
        ('AV', 'Antivirus'),
        ('FIREWALL', 'Firewall'),
        ('IDS', 'Intrusion Detection System'),
        ('CUSTOM', 'Custom Source'),
    ]
    
    name = models.CharField(max_length=100, unique=True)
    source_type = models.CharField(max_length=20, choices=SOURCE_TYPES)
    source_id = models.CharField(max_length=50, unique=True, help_text="Unique identifier for this source")
    
    # API Configuration
    api_url = models.URLField(blank=True, null=True)
    api_key = models.CharField(max_length=500, blank=True, null=True)
    auth_type = models.CharField(max_length=50, default='bearer', 
                                  choices=[('bearer', 'Bearer Token'), 
                                          ('basic', 'Basic Auth'),
                                          ('api_key', 'API Key'),
                                          ('oauth2', 'OAuth2')])
    
    # Polling configuration
    polling_enabled = models.BooleanField(default=True)
    polling_interval = models.IntegerField(default=60, help_text="Polling interval in seconds")
    last_poll_time = models.DateTimeField(null=True, blank=True)
    last_poll_status = models.CharField(max_length=20, default='pending',
                                         choices=[('pending', 'Pending'),
                                                 ('success', 'Success'),
                                                 ('error', 'Error')])
    
    # Webhook configuration
    webhook_enabled = models.BooleanField(default=False)
    webhook_secret = models.CharField(max_length=200, blank=True, null=True)
    
    # Metadata
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
        verbose_name = 'Alert Source'
        verbose_name_plural = 'Alert Sources'
    
    def __str__(self):
        return f"{self.name} ({self.source_type})"


class IngestionLog(models.Model):
    """Log of all ingestion activities."""
    
    STATUS_CHOICES = [
        ('started', 'Started'),
        ('success', 'Success'),
        ('partial', 'Partial Success'),
        ('error', 'Error'),
    ]
    
    source = models.ForeignKey(AlertSource, on_delete=models.CASCADE, related_name='ingestion_logs')
    ingestion_type = models.CharField(max_length=20, choices=[('poll', 'Polling'), ('webhook', 'Webhook')])
    
    started_at = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='started')
    alerts_received = models.IntegerField(default=0)
    alerts_sent_to_kafka = models.IntegerField(default=0)
    
    error_message = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-started_at']
        verbose_name = 'Ingestion Log'
        verbose_name_plural = 'Ingestion Logs'
    
    def __str__(self):
        return f"{self.source.name} - {self.ingestion_type} - {self.started_at}"
