"""Convenience alias for IdempotentLedger."""
from stripe_idempotency.ledger import IdempotentLedger, RecordResult
from stripe_idempotency.exceptions import *

__all__ = ["IdempotentLedger", "RecordResult"]
