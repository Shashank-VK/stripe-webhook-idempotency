import json
import time
import pytest
from stripe_idempotency.receiver import WebhookReceiver
from stripe_idempotency.verifier import generate_signature


def test_receiver_valid_webhook_flow(receiver: WebhookReceiver, webhook_secret: str, sample_payload: dict):
    """Test full pipeline: valid signature, parsed payload, ledger entry created."""
    body = json.dumps(sample_payload)
    now = int(time.time())
    sig_header = generate_signature(body, webhook_secret, timestamp=now)

    response = receiver.handle_webhook(body, sig_header, current_time=now)
    assert response.status_code == 200
    assert response.outcome == "applied"
    assert response.event_id == sample_payload["id"]
    assert response.idempotency_key == sample_payload["idempotency_key"]
    assert receiver.ledger.count_entries() == 1


def test_receiver_duplicate_webhook_flow(receiver: WebhookReceiver, webhook_secret: str, sample_payload: dict):
    """Test duplicate webhook delivery returns 200 OK (so Stripe stops retrying) but collapses in ledger."""
    body = json.dumps(sample_payload)
    now = int(time.time())
    sig_header = generate_signature(body, webhook_secret, timestamp=now)

    res1 = receiver.handle_webhook(body, sig_header, current_time=now)
    res2 = receiver.handle_webhook(body, sig_header, current_time=now)

    assert res1.outcome == "applied"
    assert res1.status_code == 200
    assert res2.outcome == "duplicate"
    assert res2.status_code == 200  # Acknowledge Stripe delivery
    assert receiver.ledger.count_entries() == 1


def test_receiver_tampered_payload_rejected(receiver: WebhookReceiver, webhook_secret: str, sample_payload: dict):
    """Test that a tampered payload is rejected before reaching the ledger."""
    original_body = json.dumps(sample_payload)
    now = int(time.time())
    sig_header = generate_signature(original_body, webhook_secret, timestamp=now)

    tampered_payload = dict(sample_payload)
    tampered_payload["data"]["object"]["amount"] = 999999
    tampered_body = json.dumps(tampered_payload)

    response = receiver.handle_webhook(tampered_body, sig_header, current_time=now)
    assert response.status_code == 401
    assert response.outcome == "rejected"
    assert response.reason == "invalid_signature"
    assert receiver.ledger.count_entries() == 0


def test_receiver_stale_timestamp_replay_rejected(receiver: WebhookReceiver, webhook_secret: str, sample_payload: dict):
    """Test replay attack rejection via receiver."""
    body = json.dumps(sample_payload)
    now = 1700000000
    stale_ts = now - 600  # 10 minutes old
    sig_header = generate_signature(body, webhook_secret, timestamp=stale_ts)

    response = receiver.handle_webhook(body, sig_header, current_time=now)
    assert response.status_code == 400
    assert response.outcome == "rejected"
    assert response.reason == "stale_timestamp"
    assert receiver.ledger.count_entries() == 0


def test_receiver_missing_header_rejected(receiver: WebhookReceiver, sample_payload: dict):
    """Test webhook with missing Stripe-Signature header is rejected."""
    body = json.dumps(sample_payload)
    response = receiver.handle_webhook(body, None)
    assert response.status_code == 400
    assert response.outcome == "rejected"
    assert response.reason == "missing_header"
    assert receiver.ledger.count_entries() == 0


def test_receiver_malformed_header_rejected(receiver: WebhookReceiver, sample_payload: dict):
    """Test webhook with malformed Stripe-Signature header is rejected."""
    body = json.dumps(sample_payload)
    response = receiver.handle_webhook(body, "nonsense_format_123")
    assert response.status_code == 400
    assert response.outcome == "rejected"
    assert response.reason == "malformed_header"
    assert receiver.ledger.count_entries() == 0


def test_receiver_missing_idempotency_key_rejected(receiver: WebhookReceiver, webhook_secret: str):
    """Test validly signed webhook payload with missing idempotency key is rejected safely."""
    payload_no_key = {
        "id": "evt_no_key_001",
        "type": "payment_intent.succeeded",
        # No idempotency_key
        "data": {"object": {"amount": 500}},
    }
    body = json.dumps(payload_no_key)
    now = int(time.time())
    sig_header = generate_signature(body, webhook_secret, timestamp=now)

    response = receiver.handle_webhook(body, sig_header, current_time=now)
    assert response.status_code == 400
    assert response.outcome == "rejected"
    assert response.reason == "missing_idempotency_key"
    assert receiver.ledger.count_entries() == 0


def test_receiver_distinct_webhooks_create_distinct_entries(receiver: WebhookReceiver, webhook_secret: str):
    """Test that multiple distinct valid webhooks create separate ledger entries."""
    now = int(time.time())
    for i in range(3):
        payload = {
            "id": f"evt_{i}",
            "type": "payment_intent.succeeded",
            "idempotency_key": f"key_distinct_{i}",
            "amount": (i + 1) * 1000,
        }
        body = json.dumps(payload)
        sig = generate_signature(body, webhook_secret, timestamp=now)
        res = receiver.handle_webhook(body, sig, current_time=now)
        assert res.outcome == "applied"

    assert receiver.ledger.count_entries() == 3


def test_receiver_audit_log_records_rejections(receiver: WebhookReceiver, sample_payload: dict):
    """Test that signature rejections are logged into the audit log."""
    body = json.dumps(sample_payload)
    # 1. Missing header rejection
    receiver.handle_webhook(body, None)
    # 2. Malformed header rejection
    receiver.handle_webhook(body, "corrupt")

    audit = receiver.ledger.get_audit_log()
    assert len(audit) == 2
    assert audit[0]["outcome"] == "rejected"
    assert audit[0]["reason"] == "missing_header"
    assert audit[1]["outcome"] == "rejected"
    assert audit[1]["reason"] == "malformed_header"
