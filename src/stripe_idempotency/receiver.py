"""Webhook receiver module connecting signature verification with the idempotent ledger."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Union

from stripe_idempotency.exceptions import (
    MissingHeaderError,
    MalformedHeaderError,
    StaleTimestampError,
    InvalidSignatureError,
)
from stripe_idempotency.ledger import IdempotentLedger, RecordResult
from stripe_idempotency.verifier import StripeSignatureVerifier


@dataclass(frozen=True)
class WebhookResponse:
    """HTTP response representation for a processed webhook."""
    status_code: int
    outcome: str
    reason: str | None = None
    event_id: str | None = None
    idempotency_key: str | None = None
    error: str | None = None


class WebhookReceiver:
    """Coordinates webhook signature verification and idempotent ledger recording."""

    def __init__(
        self,
        verifier: StripeSignatureVerifier | None = None,
        ledger: IdempotentLedger | None = None,
    ) -> None:
        """Initialize receiver with verifier and ledger instances."""
        self.verifier = verifier or StripeSignatureVerifier()
        self.ledger = ledger or IdempotentLedger()

    def handle_webhook(
        self,
        raw_body: Union[bytes, str],
        sig_header: str | None,
        current_time: float | None = None,
    ) -> WebhookResponse:
        """Process an incoming webhook request through verification and ledger idempotency.

        1. Verifies Stripe-Signature header.
        2. Parses JSON payload.
        3. Records event into the idempotent ledger.
        """
        raw_bytes = raw_body.encode("utf-8") if isinstance(raw_body, str) else raw_body

        # 1. Signature Verification
        try:
            self.verifier.verify(raw_bytes, sig_header, current_time=current_time)
        except MissingHeaderError as e:
            self.ledger.record_rejection(reason="missing_header")
            return WebhookResponse(
                status_code=400,
                outcome=RecordResult.REJECTED.value,
                reason="missing_header",
                error=str(e),
            )
        except MalformedHeaderError as e:
            self.ledger.record_rejection(reason="malformed_header")
            return WebhookResponse(
                status_code=400,
                outcome=RecordResult.REJECTED.value,
                reason="malformed_header",
                error=str(e),
            )
        except StaleTimestampError as e:
            self.ledger.record_rejection(reason="stale_timestamp")
            return WebhookResponse(
                status_code=400,
                outcome=RecordResult.REJECTED.value,
                reason="stale_timestamp",
                error=str(e),
            )
        except InvalidSignatureError as e:
            self.ledger.record_rejection(reason="invalid_signature")
            return WebhookResponse(
                status_code=401,
                outcome=RecordResult.REJECTED.value,
                reason="invalid_signature",
                error=str(e),
            )

        # 2. Payload Parsing
        try:
            payload: dict[str, Any] = json.loads(raw_bytes.decode("utf-8"))
        except Exception as e:
            self.ledger.record_rejection(reason="invalid_json")
            return WebhookResponse(
                status_code=400,
                outcome=RecordResult.REJECTED.value,
                reason="invalid_json",
                error=str(e),
            )

        if not isinstance(payload, dict):
            self.ledger.record_rejection(reason="malformed_payload")
            return WebhookResponse(
                status_code=400,
                outcome=RecordResult.REJECTED.value,
                reason="malformed_payload",
                error="Payload must be a JSON object",
            )

        event_id = payload.get("id")
        event_type = payload.get("type")

        # Resolve idempotency key from payload (direct or inside data.object)
        idempotency_key = payload.get("idempotency_key")
        if not idempotency_key and isinstance(payload.get("data"), dict):
            obj = payload["data"].get("object", {})
            if isinstance(obj, dict):
                idempotency_key = obj.get("idempotency_key")

        sequence = payload.get("sequence")

        # 3. Ledger Recording
        outcome = self.ledger.record_event(
            event_id=event_id,
            idempotency_key=idempotency_key,
            event_type=event_type,
            payload=payload,
            sequence=sequence,
        )

        if outcome == RecordResult.APPLIED:
            return WebhookResponse(
                status_code=200,
                outcome=RecordResult.APPLIED.value,
                event_id=event_id,
                idempotency_key=idempotency_key,
            )
        elif outcome == RecordResult.DUPLICATE:
            # Duplicate deliveries return 200 OK to acknowledge Stripe
            return WebhookResponse(
                status_code=200,
                outcome=RecordResult.DUPLICATE.value,
                event_id=event_id,
                idempotency_key=idempotency_key,
            )
        else:
            return WebhookResponse(
                status_code=400,
                outcome=RecordResult.REJECTED.value,
                reason="missing_idempotency_key",
                event_id=event_id,
            )
