# PLAN.md — stripe-webhook-idempotency

**Working backwards (as the Stripe hiring manager sees it):** a public GitHub repo
`Shashank-VK/stripe-webhook-idempotency` — README explains exactly-once webhook
handling for money movement, `pytest` suite fully green with a recorded count,
a redelivery-storm script that proves duplicate/out-of-order/replayed events
collapse to one ledger entry every time. Test-mode semantics only: no real Stripe
keys, no real money, no network calls to Stripe.

## Scope gate (locked)
- IN: webhook receiver with Stripe-style signature verification (HMAC-SHA256,
  timestamp tolerance, test-mode webhook secret generated locally and passed via
  env — no real keys); idempotency-key store (SQLite, one ledger table) +
  reconciliation logic (duplicate / out-of-order / redelivered events collapse
  to one ledger entry); scenario test suite (duplicate delivery, invalid
  signature, stale timestamp, out-of-order events, replay attack, missing
  idempotency key); redelivery-storm script (N webhook deliveries fired at the
  ledger incl. duplicates + replayed signatures → exactly-once ledger entries,
  with measured counts); README (what it does, how to run, real test count,
  measured storm metrics).
- OUT: real Stripe keys, real money, frontend, DB beyond SQLite, actual Stripe API calls.

## Milestones (uphill first)
1. **Signature verification module** — parse `Stripe-Signature`-style header
   (`t=...,v1=...`), HMAC-SHA256 over `t.payload`, constant-time compare,
   timestamp tolerance check. Riskiest = replay protection semantics.
2. **Idempotent ledger + reconciliation** — SQLite ledger keyed by idempotency key;
   `record_event(event_id, idempotency_key, type, payload)` returns
   applied/duplicate; out-of-order events buffered/reconciled to one entry.
3. **TDD: scenario test suite first, then code** — duplicate delivery,
   invalid signature, tampered payload, stale timestamp (replay), out-of-order
   events, missing idempotency key, malformed header, distinct keys distinct
   entries. All tests must pass from real runs (pytest, count recorded).
4. **Redelivery-storm script** — fire M deliveries (mix of duplicates, replays,
   out-of-order) and assert/print measured ledger entries (exactly-once).
5. **README + push** — README with what/how-to-run/test count/measured metrics;
   create public repo `Shashank-VK/stripe-webhook-idempotency`, push, verify live
   via `gh repo view`.

## Test discipline (TDD)
- Write failing tests first for every behavior in milestone 3, then implement.
- Target: full pytest green; final count recorded in README and RESULTS.md.
- No invented metrics: every number in README/RESULTS comes from a real run.

## Stack
- Python 3.10+, stdlib only (hmac, hashlib, sqlite3, http.server optional for a
  receiver demo) + pytest. Keep deps minimal (pytest only) so the repo installs
  with one command.

## Verify gates (from playbook, all must pass)
- [ ] pytest fully green, count recorded
- [ ] Storm script demonstrates exactly-once ledger entries (measured numbers)
- [ ] Pushed to GitHub, `gh repo view Shashank-VK/stripe-webhook-idempotency` live
- [ ] README: what it does, how to run, test count, storm metrics
- [ ] No secrets (test-mode secret generated locally in tests, never committed as
      a real credential; no API keys anywhere)
- [ ] No invented metrics — every claim measured from a real run

## Debug rule
On failure: 26-systematic-rca root cause → one bounded retry after genuine fix → report.
