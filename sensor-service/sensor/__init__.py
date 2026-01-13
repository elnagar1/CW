# Sensor Service - CyberWatch Alert Pipeline
# This module handles ingestion from various alert sources

from .celery import app as celery_app

__all__ = ('celery_app',)
