"""
Celery configuration for CyberWatch Sensor Service.
Handles periodic polling tasks using Celery Beat.
"""

import os
from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'sensor.settings')

# Create Celery app
app = Celery('sensor')

# Load config from Django settings
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks in all installed apps
app.autodiscover_tasks()

# ============================================
# Celery Beat Schedule (Periodic Tasks)
# ============================================
app.conf.beat_schedule = {
    # Poll QRadar every 60 seconds
    'poll-qradar-alerts': {
        'task': 'alerts.tasks.poll_qradar_alerts',
        'schedule': 60.0,
        'options': {'queue': 'polling'}
    },
    
    # Poll CrowdStrike every 30 seconds
    'poll-crowdstrike-alerts': {
        'task': 'alerts.tasks.poll_crowdstrike_alerts',
        'schedule': 30.0,
        'options': {'queue': 'polling'}
    },
    
    # Poll Defender every 60 seconds
    'poll-defender-alerts': {
        'task': 'alerts.tasks.poll_defender_alerts',
        'schedule': 60.0,
        'options': {'queue': 'polling'}
    },
    
    # Poll Splunk every 60 seconds
    'poll-splunk-alerts': {
        'task': 'alerts.tasks.poll_splunk_alerts',
        'schedule': 60.0,
        'options': {'queue': 'polling'}
    },
    
    # Health check every 5 minutes
    'sensor-health-check': {
        'task': 'alerts.tasks.health_check',
        'schedule': 300.0,
    },
}

# Task routing
app.conf.task_routes = {
    'alerts.tasks.poll_*': {'queue': 'polling'},
    'alerts.tasks.process_webhook': {'queue': 'webhook'},
}


@app.task(bind=True, ignore_result=True)
def debug_task(self):
    """Debug task for testing Celery."""
    print(f'Request: {self.request!r}')
