"""Exceptions for stripe-webhook-idempotency."""


class WebhookVerificationError(Exception):
    """Base exception for all webhook signature verification failures."""
    pass


class MissingHeaderError(WebhookVerificationError):
    """Raised when the Stripe-Signature header is missing or empty."""
    pass


class MalformedHeaderError(WebhookVerificationError):
    """Raised when the Stripe-Signature header cannot be parsed or lacks required fields."""
    pass


class StaleTimestampError(WebhookVerificationError):
    """Raised when the webhook timestamp falls outside the configured tolerance window (replay attack)."""
    pass


class InvalidSignatureError(WebhookVerificationError):
    """Raised when HMAC signature computation does not match any v1 signature in header."""
    pass


class LedgerError(Exception):
    """Base exception for ledger operations."""
    pass


class MissingIdempotencyKeyError(LedgerError):
    """Raised when an event lacks an idempotency key."""
    pass
