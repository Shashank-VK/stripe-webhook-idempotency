import hashlib
import json
import sqlite3
import pytest
from stripe_idempotency.ledger import IdempotentLedger, RecordResult


def test_first_event_applied(ledger: IdempotentLedger, sample_payload: dict):
    """Test that a new event is applied and creates exactly one ledger entry."""
    outcome = ledger.record_event(
        event_id="evt_001",
        idempotency_key="key_001",
        event_type="payment_intent.succeeded",
        payload=sample_payload,
    )
    assert outcome == RecordResult.APPLIED
    assert outcome == "applied"
    assert ledger.count_entries() == 1

    entry = ledger.get_entry("key_001")
    assert entry is not None
    assert entry["event_id"] == "evt_001"
    assert entry["idempotency_key"] == "key_001"
    assert entry["event_type"] == "payment_intent.succeeded"
    assert entry["outcome"] == "applied"
    assert entry["first_applied_at"] is not None
    assert entry["received_at"] is not None


def test_duplicate_delivery_collapses_to_one_ledger_entry(ledger: IdempotentLedger, sample_payload: dict):
    """Test that redelivering the exact same event collapses to duplicate and keeps 1 ledger entry."""
    outcome1 = ledger.record_event("evt_001", "key_001", "payment_intent.succeeded", sample_payload)
    outcome2 = ledger.record_event("evt_001", "key_001", "payment_intent.succeeded", sample_payload)

    assert outcome1 == "applied"
    assert outcome2 == "duplicate"
    assert ledger.count_entries() == 1


def test_multiple_redeliveries_collapse_to_one_entry(ledger: IdempotentLedger, sample_payload: dict):
    """Test that 10 redeliveries of the same key result in 1 applied, 9 duplicates, and 1 entry."""
    outcomes = [
        ledger.record_event("evt_001", "key_001", "payment_intent.succeeded", sample_payload)
        for _ in range(10)
    ]
    assert outcomes[0] == "applied"
    assert all(o == "duplicate" for o in outcomes[1:])
    assert ledger.count_entries() == 1

    audit_logs = ledger.get_audit_log(idempotency_key="key_001")
    assert len(audit_logs) == 10
    assert audit_logs[0]["outcome"] == "applied"
    assert all(a["outcome"] == "duplicate" for a in audit_logs[1:])


def test_distinct_keys_give_distinct_entries(ledger: IdempotentLedger, sample_payload: dict):
    """Test that distinct idempotency keys create distinct entries in the ledger."""
    for i in range(5):
        key = f"key_{i}"
        outcome = ledger.record_event(f"evt_{i}", key, "payment_intent.succeeded", sample_payload)
        assert outcome == "applied"

    assert ledger.count_entries() == 5
    entries = ledger.get_entries()
    assert len(entries) == 5
    assert {e["idempotency_key"] for e in entries} == {f"key_{i}" for i in range(5)}


def test_out_of_order_events_reconcile_to_one_entry(ledger: IdempotentLedger):
    """
    Test reconciliation when events arrive out of order for the same payment.
    Scenario: 'payment_intent.succeeded' (seq 2) arrives BEFORE 'payment_intent.created' (seq 1).
    The late 'created' event must not overwrite the succeeded status, and the ledger
    must maintain exactly ONE entry for this idempotency key.
    """
    idem_key = "key_pay_out_of_order"
    payload_succeeded = {"status": "succeeded", "amount": 5000}
    payload_created = {"status": "created", "amount": 5000}

    # Event 2 arrives first
    outcome_succ = ledger.record_event(
        event_id="evt_succ_002",
        idempotency_key=idem_key,
        event_type="payment_intent.succeeded",
        payload=payload_succeeded,
        sequence=2,
    )
    assert outcome_succ == "applied"
    assert ledger.count_entries() == 1

    # Event 1 arrives out of order later
    outcome_creat = ledger.record_event(
        event_id="evt_creat_001",
        idempotency_key=idem_key,
        event_type="payment_intent.created",
        payload=payload_created,
        sequence=1,
    )
    assert outcome_creat == "duplicate"  # Collapses as superseded duplicate
    assert ledger.count_entries() == 1

    # Verify the ledger state reflects the authoritative succeeded state
    entry = ledger.get_entry(idem_key)
    assert entry is not None
    assert entry["event_type"] == "payment_intent.succeeded"
    assert entry["event_id"] == "evt_succ_002"


def test_missing_idempotency_key_handled_safely(ledger: IdempotentLedger, sample_payload: dict):
    """Test that missing, None, or blank idempotency keys are handled safely without crashing."""
    outcome_none = ledger.record_event("evt_001", None, "payment_intent.succeeded", sample_payload)
    assert outcome_none == "rejected"
    assert ledger.count_entries() == 0

    outcome_empty = ledger.record_event("evt_002", "", "payment_intent.succeeded", sample_payload)
    assert outcome_empty == "rejected"
    assert ledger.count_entries() == 0

    outcome_blank = ledger.record_event("evt_003", "   ", "payment_intent.succeeded", sample_payload)
    assert outcome_blank == "rejected"
    assert ledger.count_entries() == 0

    # Ensure rejection was recorded in the audit log
    rejections = [a for a in ledger.get_audit_log() if a["outcome"] == "rejected"]
    assert len(rejections) == 3
    assert all(r["reason"] == "missing_idempotency_key" for r in rejections)


def test_ledger_audit_log_records_every_decision(ledger: IdempotentLedger, sample_payload: dict):
    """Test that every decision (applied, duplicate, rejected) is written to audit log with all required columns."""
    ledger.record_event("evt_001", "key_audit_1", "payment_intent.succeeded", sample_payload)
    ledger.record_event("evt_001", "key_audit_1", "payment_intent.succeeded", sample_payload)  # duplicate
    ledger.record_event("evt_002", None, "payment_intent.succeeded", sample_payload)  # rejected

    audit_rows = ledger.get_audit_log()
    assert len(audit_rows) == 3

    # Check required columns per spec:
    # event_id, idempotency key, event type, payload hash, received-at, first-applied-at, and outcome
    for row in audit_rows:
        assert "event_id" in row
        assert "idempotency_key" in row
        assert "event_type" in row
        assert "payload_hash" in row
        assert "received_at" in row
        assert "first_applied_at" in row
        assert "outcome" in row

    assert audit_rows[0]["outcome"] == "applied"
    assert audit_rows[1]["outcome"] == "duplicate"
    assert audit_rows[2]["outcome"] == "rejected"


def test_payload_hash_matches_sha256(ledger: IdempotentLedger, sample_payload: dict):
    """Test that payload_hash stored in ledger rows is the exact SHA256 of the payload."""
    payload_str = json.dumps(sample_payload, sort_keys=True, separators=(",", ":"))
    expected_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

    ledger.record_event("evt_hash_1", "key_hash_1", "payment_intent.succeeded", sample_payload)
    entry = ledger.get_entry("key_hash_1")
    assert entry is not None
    assert entry["payload_hash"] == expected_hash


def test_sqlite_primary_key_guarantees_uniqueness(ledger: IdempotentLedger, sample_payload: dict):
    """Test that the underlying SQLite schema enforces unique idempotency keys via PRIMARY KEY."""
    ledger.record_event("evt_pk_1", "key_pk_1", "payment_intent.succeeded", sample_payload)

    # Attempting raw direct INSERT with duplicate key must trigger IntegrityError
    with pytest.raises(sqlite3.IntegrityError):
        with ledger._conn:
            ledger._conn.execute(
                "INSERT INTO ledger_entries (idempotency_key, event_id, event_type, payload_hash, payload, "
                "status, version, received_at, first_applied_at, outcome) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("key_pk_1", "evt_pk_2", "payment_intent.succeeded", "hash", "{}", "applied", 1, "now", "now", "applied"),
            )
