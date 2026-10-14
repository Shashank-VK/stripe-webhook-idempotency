import json
import secrets
import pytest
from stripe_idempotency.verifier import StripeSignatureVerifier, generate_signature
from stripe_idempotency.ledger import IdempotentLedger
from stripe_idempotency.receiver import WebhookReceiver


@pytest.fixture
def webhook_secret() -> str:
    """Generate a high-entropy test secret at runtime (never committed, test-mode only)."""
    return f"whsec_test_{secrets.token_hex(24)}"


@pytest.fixture
def verifier(webhook_secret: str) -> StripeSignatureVerifier:
    """Stripe-style signature verifier with 300s tolerance."""
    return StripeSignatureVerifier(secret=webhook_secret, tolerance=300)


@pytest.fixture
def ledger() -> IdempotentLedger:
    """In-memory SQLite idempotent ledger for fast, isolated tests."""
    return IdempotentLedger(db_path=":memory:")


@pytest.fixture
def receiver(verifier: StripeSignatureVerifier, ledger: IdempotentLedger) -> WebhookReceiver:
    """Integrated receiver combining signature verifier and idempotent ledger."""
    return WebhookReceiver(verifier=verifier, ledger=ledger)


@pytest.fixture
def sample_payload() -> dict:
    """A realistic Stripe-style payment_intent webhook payload."""
    return {
        "id": "evt_test_charge_001",
        "type": "payment_intent.succeeded",
        "idempotency_key": "idem_req_abc12345",
        "created": 1700000000,
        "data": {
            "object": {
                "id": "pi_3MtwBwLkdIwHu7ix28a3tqPa",
                "object": "payment_intent",
                "amount": 2000,
                "currency": "usd",
                "status": "succeeded",
            }
        },
    }


@pytest.fixture
def sample_raw_body(sample_payload: dict) -> str:
    """Raw JSON body for the sample payload."""
    return json.dumps(sample_payload, separators=(",", ":"))
