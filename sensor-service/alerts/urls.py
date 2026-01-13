"""URL configuration for alerts app."""

from django.urls import path
from .views import WebhookView, HealthView, SourcesView, StatsView, PullTriggerView

urlpatterns = [
    path('health/', HealthView.as_view(), name='health'),
    path('sources/', SourcesView.as_view(), name='sources'),
    path('stats/', StatsView.as_view(), name='stats'),
    path('webhook/<str:source_id>/', WebhookView.as_view(), name='webhook'),
    path('pull/<str:source_id>/', PullTriggerView.as_view(), name='pull-trigger'),
]
