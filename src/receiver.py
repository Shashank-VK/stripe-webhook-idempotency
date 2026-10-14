"""Convenience alias for WebhookReceiver."""
from stripe_idempotency.receiver import WebhookReceiver, WebhookResponse
from stripe_idempotency.exceptions import *

__all__ = ["WebhookReceiver", "WebhookResponse"]
