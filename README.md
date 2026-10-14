# stripe-webhook-idempotency

[![Tests](https://img.shields.io/badge/pytest-36%20passed-brightgreen.svg)](RESULTS.md)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A production-grade, test-mode reference implementation of Stripe-style webhook signature verification and an idempotent SQLite ledger. Built to satisfy the financial systems bar for money movement: **"exactly correct, idempotent, auditable, and fast."**

---

## Architecture Overview

```
                      ┌────────────────────────────────────────┐
                      │        Incoming Webhook Request        │
                      └───────────────────┬────────────────────┘
                                          │
                        Stripe-Signature & Raw Body
                                          ▼
                      ┌────────────────────────────────────────┐
                      │        StripeSignatureVerifier         │
                      │  - Parse t=<ts>,v1=<sig>               │
                      │  - Reject stale ts (|now - t| > 300s)   │
                      │  - HMAC-SHA256 constant-time check     │
                      └───────┬────────────────────────┬───────┘
                     Rejected │                        │ Verified
                              ▼                        ▼
                      ┌───────────────┐        ┌────────────────────────┐
                      │   Audit Log   │        │    IdempotentLedger    │
                      │ (400/401 Log) │        │  - Extract Idem-Key    │
                      └───────────────┘        │  - SQLite Transaction  │
                                               └───────────┬────────────┘
                                                           │
                                        ┌──────────────────┴──────────────────┐
                                        ▼                                     ▼
                             First-Time Key                          Duplicate / Out-of-Order
                         ┌─────────────────────┐                     ┌─────────────────────┐
                         │ INSERT ledger_entry │                     │ Check version/seq   │
                         │ INSERT audit_log    │                     │ INSERT audit_log    │
                         │ return 'applied'    │                     │ return 'duplicate'  │
                         └─────────────────────┘                     └─────────────────────┘
```

### Core Components

1. **`StripeSignatureVerifier`** (`src/stripe_idempotency/verifier.py`):
   - Validates `Stripe-Signature` header (`t=<unix_ts>,v1=<hex_hmac>[,v1=...]`).
   - Recomputes HMAC-SHA256 over `${timestamp}.${raw_body}` using a test-mode secret.
   - Prevents timing attacks with `hmac.compare_digest`.
   - Prevents replay attacks by enforcing a configurable timestamp tolerance window (default: 300 seconds).
   - Supports key rotation via multi-signature headers.

2. **`IdempotentLedger`** (`src/stripe_idempotency/ledger.py`):
   - Backed by SQLite with atomic transactions.
   - Guarantees that the same idempotency key arriving twice, redelivered, or out of order produces **exactly ONE ledger entry**.
   - Handles out-of-order event sequence reconciliation: late-arriving superseded events collapse cleanly to duplicate without corrupting the authoritative ledger state.
   - Audits every decision: every single delivery (applied, duplicate, or rejected) is recorded in `audit_log` with `event_id`, `idempotency_key`, `event_type`, `payload_hash` (SHA-256), `received_at`, `first_applied_at`, `outcome`, and `reason`.

3. **`WebhookReceiver`** (`src/stripe_idempotency/receiver.py`):
   - Coordinates signature verification, JSON parsing, error trapping, and ledger persistence.
   - Returns HTTP 200 for duplicates (standard payment webhook contract so upstream delivery acknowledges receipt without creating duplicate transactions).

---

## Quickstart

### Prerequisites
- Python 3.10+
- `pytest` (only dependency; everything else uses Python standard library `hmac`, `hashlib`, `sqlite3`)

### Installation

```bash
git clone https://github.com/Shashank-VK/stripe-webhook-idempotency.git
cd stripe-webhook-idempotency
pip install -r requirements.txt
```

---

## Running Tests

Run the full pytest suite:

```bash
pytest
```

### Verified Test Count
All **36 tests passed** in **0.29s**:
```text
============================== 36 passed in 0.29s ==============================
```

The test suite covers:
- Valid signature accepted
- Invalid/corrupt signature rejected (constant-time verification)
- Tampered payload rejected
- Stale timestamp rejected (replay attack prevention)
- Future timestamp beyond tolerance rejected
- Timestamp tolerance boundary testing (exact 300s window edge)
- Missing `Stripe-Signature` header rejected
- Malformed headers rejected (missing timestamp, missing v1, garbage formatting)
- Multi-signature headers accepted if at least one matches (Stripe key rotation)
- Test-mode secret fallback to `WEBHOOK_SECRET` environment variable
- Duplicate webhook redeliveries collapsing to 1 ledger entry
- Out-of-order event delivery reconciliation
- Missing idempotency key handled safely without crashing
- SQLite `PRIMARY KEY` uniqueness guarantee
- Deterministic SHA-256 payload hashing
- Full auditability across all lifecycle outcomes

---

## Redelivery Storm Simulation

The redelivery storm simulates a high-concurrency burst of 1,000 webhook deliveries against the ledger, containing a chaotic mix of first-time events, duplicates, out-of-order sequences, stale replay attacks, tampered payloads, and missing headers.

### Running the Storm Script

```bash
python3 scripts/redelivery_storm.py --deliveries 1000 --unique-keys 200 --seed 42
```

### Measured Storm Results (Real Run)

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

### Verified Invariants

$$\text{Ledger Entries Created (200)} = \text{Unique Idempotency Keys (200)}$$
$$\text{Created (200)} + \text{Duplicates (600)} + \text{Rejections (200)} = \text{Total Deliveries (1,000)}$$

Every delivery is accounted for, and exactly-once state is preserved with microsecond latency.

---

## Security & Constraints

- **No Real Keys / No Network Calls**: Runs strictly in TEST MODE. Webhook secrets are generated dynamically at runtime using `secrets.token_hex()` and never committed.
- **Timing Safe**: HMAC verification uses `hmac.compare_digest` to prevent timing attacks.
- **Replay Protection**: Webhooks with timestamps older than 300 seconds are rejected before cryptographic payload evaluation.
- **Audit Completeness**: Rejections and duplicate events are persisted in the audit log table, ensuring zero blind spots for financial investigations.

---

## Project Structure

```
stripe-webhook-idempotency/
├── pyproject.toml              # Project configuration & pytest paths
├── requirements.txt            # Minimal dependencies (pytest only)
├── PLAN.md                     # Locked scope and verify gates
├── BUILD_BRIEF.txt             # Interview bar specification
├── README.md                   # System documentation & measured metrics
├── RESULTS.md                  # Verifiable command outputs from real runs
├── src/
│   ├── stripe_idempotency/     # Core library package
│   │   ├── __init__.py
│   │   ├── exceptions.py       # Custom exception hierarchy
│   │   ├── verifier.py         # HMAC-SHA256 signature verifier
│   │   ├── ledger.py           # SQLite idempotent ledger & audit log
│   │   └── receiver.py         # Integrated webhook receiver
│   ├── webhook_verifier.py     # Top-level convenience re-export
│   ├── ledger.py               # Top-level convenience re-export
│   └── receiver.py             # Top-level convenience re-export
├── tests/
│   ├── conftest.py             # Shared pytest fixtures & test-mode secret
│   ├── test_verifier.py        # Signature & replay defense tests
│   ├── test_ledger.py          # SQLite ledger idempotency & audit tests
│   ├── test_receiver.py        # Integration tests for end-to-end receiver
│   └── test_storm.py           # Automated invariant validation for storm script
└── scripts/
    └── redelivery_storm.py     # Standalone 1,000-delivery simulation script
```

---

## License

MIT License.
