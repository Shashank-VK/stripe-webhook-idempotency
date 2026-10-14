# Test and Storm Simulation Results

This file documents the real, unedited results from running the test suite and redelivery storm simulation for `stripe-webhook-idempotency`.

---

## 1. Pytest Suite Execution

Run command:
```bash
pytest
```

Output:
```text
============================= test session starts ==============================
platform linux -- Python 3.12.3, pytest-9.1.1, pluggy-1.6.0 -- /usr/bin/python3
cachedir: .pytest_cache
rootdir: /home/hatch/workspace/goals/land-a-ds-ml-internship-or-job/builds/stripe-webhook-idempotency
configfile: pyproject.toml
testpaths: tests
plugins: asyncio-1.4.0, anyio-4.15.1, langsmith-0.14.7
asyncio: mode=Mode.STRICT, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collecting ... collected 36 items

tests/test_ledger.py::test_first_event_applied PASSED                    [  2%]
tests/test_ledger.py::test_duplicate_delivery_collapses_to_one_ledger_entry PASSED [  5%]
tests/test_ledger.py::test_multiple_redeliveries_collapse_to_one_entry PASSED [  8%]
tests/test_ledger.py::test_distinct_keys_give_distinct_entries PASSED    [ 11%]
tests/test_ledger.py::test_out_of_order_events_reconcile_to_one_entry PASSED [ 13%]
tests/test_ledger.py::test_missing_idempotency_key_handled_safely PASSED [ 16%]
tests/test_ledger.py::test_ledger_audit_log_records_every_decision PASSED [ 19%]
tests/test_ledger.py::test_payload_hash_matches_sha256 PASSED            [ 22%]
tests/test_ledger.py::test_sqlite_primary_key_guarantees_uniqueness PASSED [ 25%]
tests/test_receiver.py::test_receiver_valid_webhook_flow PASSED          [ 27%]
tests/test_receiver.py::test_receiver_duplicate_webhook_flow PASSED      [ 30%]
tests/test_receiver.py::test_receiver_tampered_payload_rejected PASSED   [ 33%]
tests/test_receiver.py::test_receiver_stale_timestamp_replay_rejected PASSED [ 36%]
tests/test_receiver.py::test_receiver_missing_header_rejected PASSED     [ 38%]
tests/test_receiver.py::test_receiver_malformed_header_rejected PASSED   [ 41%]
tests/test_receiver.py::test_receiver_missing_idempotency_key_rejected PASSED [ 44%]
tests/test_receiver.py::test_receiver_distinct_webhooks_create_distinct_entries PASSED [ 47%]
tests/test_receiver.py::test_receiver_audit_log_records_rejections PASSED [ 50%]
tests/test_storm.py::test_redelivery_storm_simulation_invariants PASSED  [ 52%]
tests/test_verifier.py::test_valid_signature_accepted PASSED             [ 55%]
tests/test_verifier.py::test_invalid_signature_rejected PASSED           [ 58%]
tests/test_verifier.py::test_tampered_payload_rejected PASSED            [ 61%]
tests/test_verifier.py::test_stale_timestamp_rejected_as_replay PASSED   [ 63%]
tests/test_verifier.py::test_future_timestamp_beyond_tolerance_rejected PASSED [ 66%]
tests/test_verifier.py::test_timestamp_at_tolerance_boundary_accepted PASSED [ 69%]
tests/test_verifier.py::test_missing_header_rejected PASSED              [ 72%]
tests/test_verifier.py::test_malformed_header_rejected[t=not_a_number,v1=abcdef] PASSED [ 75%]
tests/test_verifier.py::test_malformed_header_rejected[t=1700000000] PASSED [ 77%]
tests/test_verifier.py::test_malformed_header_rejected[v1=abcdef] PASSED [ 80%]
tests/test_verifier.py::test_malformed_header_rejected[garbage_header_without_keys] PASSED [ 83%]
tests/test_verifier.py::test_malformed_header_rejected[t=1700000000,v2=abcdef] PASSED [ 86%]
tests/test_verifier.py::test_malformed_header_rejected[=,=,] PASSED      [ 88%]
tests/test_verifier.py::test_multiple_v1_signatures_accepted_if_one_matches PASSED [ 91%]
tests/test_verifier.py::test_replay_attack_with_old_timestamp_and_valid_sig_rejected PASSED [ 94%]
tests/test_verifier.py::test_verifier_reads_secret_from_env_var PASSED   [ 97%]
tests/test_verifier.py::test_verifier_missing_secret_raises_value_error PASSED [100%]

============================== 36 passed in 0.29s ==============================
```

---

## 2. Redelivery Storm Simulation Execution

Run command:
```bash
python3 scripts/redelivery_storm.py --deliveries 1000 --unique-keys 200 --seed 42
```

Output:
```text
========================================================================
  STRIPE WEBHOOK REDELIVERY STORM SIMULATION
========================================================================
  Total deliveries scheduled: 1000
  Target unique keys:         200
  Random seed:                42
  Database:                   :memory:
------------------------------------------------------------------------

[MEASURED RESULTS]
  Total Deliveries Sent:      1,000
  Unique Idempotency Keys:    200
  Ledger Entries Created:     200
  Duplicates Collapsed:       600
  Rejections:                 200
    - Stale replay attacks:   50
    - Bad/tampered signature: 50
    - Missing signature:      50
    - Missing idempotency key:50
  Duration:                   145.28 ms (6,883 req/s)
------------------------------------------------------------------------

[INVARIANT VERIFICATION]
  Invariant [ledger entries (200) == unique keys (200)]: PASSED
  Balance [entries (200) + dups (600) + rejects (200) == 1000 / 1000]: PASSED
========================================================================
```

---

## 3. Analysis & Key Invariants Verified

1. **Exactly-Once Semantics Under Redelivery:**
   - 1,000 total deliveries were sent with 200 unique idempotency keys.
   - Despite 600 duplicate redeliveries and out-of-order deliveries, **exactly 200 ledger entries** were created (`ledger_entries == unique_keys`).
2. **Deterministic Collapse:**
   - Every redelivery or late out-of-order event for an existing key was safely collapsed to `outcome = duplicate`.
   - The ledger entry preserved the authoritative financial state and original `first_applied_at` timestamp.
3. **Replay & Tamper Defense:**
   - 50 stale timestamp replay attacks (> 300s old) were rejected.
   - 50 tampered/invalid signature attacks were rejected via constant-time HMAC comparison.
   - 50 missing signature headers and 50 missing idempotency keys were rejected safely without crashing.
4. **Complete Auditability:**
   - All 1,000 decisions (200 applied + 600 duplicates + 200 rejections) were recorded in the SQLite audit log with exact timestamps, hashes, outcomes, and reasons.
