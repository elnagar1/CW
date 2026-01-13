"""Django Admin configuration for Alert Sources."""

from django.contrib import admin
from .models import AlertSource, IngestionLog


@admin.register(AlertSource)
class AlertSourceAdmin(admin.ModelAdmin):
    list_display = ['name', 'source_type', 'source_id', 'polling_enabled', 'webhook_enabled', 'is_active', 'last_poll_status']
    list_filter = ['source_type', 'is_active', 'polling_enabled', 'webhook_enabled', 'last_poll_status']
    search_fields = ['name', 'source_id']
    readonly_fields = ['last_poll_time', 'created_at', 'updated_at']
    
    fieldsets = (
        ('Basic Info', {'fields': ('name', 'source_type', 'source_id', 'is_active')}),
        ('API Configuration', {'fields': ('api_url', 'api_key', 'auth_type')}),
        ('Polling', {'fields': ('polling_enabled', 'polling_interval', 'last_poll_time', 'last_poll_status')}),
        ('Webhook', {'fields': ('webhook_enabled', 'webhook_secret')}),
        ('Timestamps', {'fields': ('created_at', 'updated_at'), 'classes': ('collapse',)}),
    )


@admin.register(IngestionLog)
class IngestionLogAdmin(admin.ModelAdmin):
    list_display = ['source', 'ingestion_type', 'status', 'alerts_received', 'alerts_sent_to_kafka', 'started_at']
    list_filter = ['source', 'ingestion_type', 'status', 'started_at']
    readonly_fields = ['source', 'ingestion_type', 'started_at', 'completed_at', 'status', 'alerts_received', 'alerts_sent_to_kafka', 'error_message']
    ordering = ['-started_at']
