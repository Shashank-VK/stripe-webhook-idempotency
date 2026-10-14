#!/usr/bin/env python3
"""Redelivery Storm Simulation Script.

Simulates a high-concurrency webhook storm firing N deliveries at the WebhookReceiver.
The storm includes:
- First-time valid deliveries
- Redeliveries / exact duplicates
- Out-of-order events for existing keys
- Stale timestamp replay attacks
- Tampered payload / invalid signatures
- Missing headers and missing idempotency keys

Measures and prints:
- Total deliveries sent
- Unique idempotency keys
- Ledger entries created
- Duplicates collapsed
- Rejections (with reason breakdown)
- Invariant check: ledger entries == unique idempotency keys
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import secrets
import sys
import time
from typing import Any

# Ensure src/ is on sys.path for direct invocation
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from stripe_idempotency.ledger import IdempotentLedger
from stripe_idempotency.receiver import WebhookReceiver
from stripe_idempotency.verifier import StripeSignatureVerifier, generate_signature


def run_storm(
    total_deliveries: int = 1000,
    unique_keys_count: int = 200,
    seed: int = 42,
    db_path: str = ":memory:",
) -> dict[str, Any]:
    """Execute the redelivery storm against an isolated receiver."""
    random.seed(seed)
    test_secret = f"whsec_storm_{secrets.token_hex(16)}"

    verifier = StripeSignatureVerifier(secret=test_secret, tolerance=300)
    ledger = IdempotentLedger(db_path=db_path)
    receiver = WebhookReceiver(verifier=verifier, ledger=ledger)

    base_time = 1700000000.0

    # 1. Generate unique idempotency keys
    keys = [f"idem_key_{i:04d}_{secrets.token_hex(4)}" for i in range(unique_keys_count)]

    # Plan the storm composition:
    # - Each of the unique_keys_count keys MUST be delivered at least once.
    # - Duplicates / redeliveries / out-of-order events
    # - Rejections (replays, bad sigs, missing headers, missing keys)
    rejection_target = int(total_deliveries * 0.20)  # 20% rejections
    valid_deliveries_target = total_deliveries - rejection_target
    duplicate_target = valid_deliveries_target - unique_keys_count

    if duplicate_target < 0:
        raise ValueError(
            f"total_deliveries ({total_deliveries}) too small for unique_keys_count ({unique_keys_count})"
        )

    deliveries: list[dict[str, Any]] = []

    # Category A: First-time valid events for all unique keys
    for key in keys:
        payload = {
            "id": f"evt_valid_{key}",
            "type": "payment_intent.succeeded",
            "idempotency_key": key,
            "sequence": 1,
            "data": {"amount": random.randint(1000, 50000), "currency": "usd"},
        }
        raw_body = json.dumps(payload, separators=(",", ":"))
        sig = generate_signature(raw_body, test_secret, timestamp=int(base_time))
        deliveries.append({
            "type": "initial_valid",
            "body": raw_body,
            "sig": sig,
            "time": base_time,
            "key": key,
        })

    # Category B: Duplicates and out-of-order events for existing keys
    for _ in range(duplicate_target):
        key = random.choice(keys)
        is_out_of_order = random.random() < 0.3  # 30% of duplicates simulate out-of-order sequence
        seq = 1 if not is_out_of_order else (2 if random.random() < 0.5 else 0)
        payload = {
            "id": f"evt_dup_{secrets.token_hex(4)}",
            "type": "payment_intent.succeeded" if seq >= 1 else "payment_intent.created",
            "idempotency_key": key,
            "sequence": seq,
            "data": {"amount": 2500, "currency": "usd"},
        }
        raw_body = json.dumps(payload, separators=(",", ":"))
        # Fresh timestamp within tolerance
        event_time = base_time + random.randint(1, 100)
        sig = generate_signature(raw_body, test_secret, timestamp=int(event_time))
        deliveries.append({
            "type": "duplicate" if seq <= 1 else "out_of_order",
            "body": raw_body,
            "sig": sig,
            "time": event_time,
            "key": key,
        })

    # Category C: Rejections (replay attacks, invalid signatures, missing headers, missing keys)
    rejection_types = ["replay_attack", "bad_signature", "missing_header", "missing_key"]
    for i in range(rejection_target):
        cat = rejection_types[i % len(rejection_types)]
        key = random.choice(keys)

        if cat == "replay_attack":
            # Valid signature, but timestamp is 1 hour stale (> 300s tolerance)
            payload = {"id": f"evt_replay_{i}", "type": "payment_intent.succeeded", "idempotency_key": key}
            raw_body = json.dumps(payload, separators=(",", ":"))
            stale_time = base_time - 3600
            sig = generate_signature(raw_body, test_secret, timestamp=int(stale_time))
            deliveries.append({
                "type": "replay_attack",
                "body": raw_body,
                "sig": sig,
                "time": base_time,
            })

        elif cat == "bad_signature":
            payload = {"id": f"evt_bad_{i}", "type": "payment_intent.succeeded", "idempotency_key": key}
            raw_body = json.dumps(payload, separators=(",", ":"))
            bad_sig = f"t={int(base_time)},v1=0000000000000000000000000000000000000000000000000000000000000000"
            deliveries.append({
                "type": "bad_signature",
                "body": raw_body,
                "sig": bad_sig,
                "time": base_time,
            })

        elif cat == "missing_header":
            payload = {"id": f"evt_nohdr_{i}", "type": "payment_intent.succeeded", "idempotency_key": key}
            raw_body = json.dumps(payload, separators=(",", ":"))
            deliveries.append({
                "type": "missing_header",
                "body": raw_body,
                "sig": None,
                "time": base_time,
            })

        elif cat == "missing_key":
            # Valid signature, but payload missing idempotency key
            payload = {"id": f"evt_nokey_{i}", "type": "payment_intent.succeeded", "data": {"amount": 100}}
            raw_body = json.dumps(payload, separators=(",", ":"))
            sig = generate_signature(raw_body, test_secret, timestamp=int(base_time))
            deliveries.append({
                "type": "missing_key",
                "body": raw_body,
                "sig": sig,
                "time": base_time,
            })

    # Shuffle deliveries to simulate chaotic arrival order in production
    random.shuffle(deliveries)

    # 2. Fire storm
    start_wall = time.perf_counter()
    outcomes = {"applied": 0, "duplicate": 0, "rejected": 0}
    rejection_reasons: dict[str, int] = {}

    for delivery in deliveries:
        res = receiver.handle_webhook(
            raw_body=delivery["body"],
            sig_header=delivery["sig"],
            current_time=delivery["time"],
        )
        outcomes[res.outcome] = outcomes.get(res.outcome, 0) + 1
        if res.outcome == "rejected":
            reason = res.reason or "unknown"
            rejection_reasons[reason] = rejection_reasons.get(reason, 0) + 1

    duration = time.perf_counter() - start_wall

    ledger_entries_created = ledger.count_entries()
    audit_stats = ledger.get_audit_stats()

    invariant_passed = (ledger_entries_created == unique_keys_count)
    balance_passed = (
        outcomes["applied"] + outcomes["duplicate"] + outcomes["rejected"] == total_deliveries
    )

    return {
        "total_deliveries": total_deliveries,
        "unique_keys": unique_keys_count,
        "ledger_entries_created": ledger_entries_created,
        "duplicates_collapsed": outcomes["duplicate"],
        "rejections": outcomes["rejected"],
        "rejection_breakdown": rejection_reasons,
        "duration_sec": duration,
        "throughput_per_sec": total_deliveries / duration if duration > 0 else 0,
        "invariant_passed": invariant_passed,
        "balance_passed": balance_passed,
        "audit_stats": audit_stats,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Stripe Webhook Redelivery Storm Simulation")
    parser.add_argument("--deliveries", type=int, default=1000, help="Total webhook deliveries to fire")
    parser.add_argument("--unique-keys", type=int, default=200, help="Number of distinct idempotency keys")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for repeatability")
    parser.add_argument("--db", type=str, default=":memory:", help="SQLite database path")
    args = parser.parse_args()

    print("=" * 72)
    print("  STRIPE WEBHOOK REDELIVERY STORM SIMULATION")
    print("=" * 72)
    print(f"  Total deliveries scheduled: {args.deliveries}")
    print(f"  Target unique keys:         {args.unique_keys}")
    print(f"  Random seed:                {args.seed}")
    print(f"  Database:                   {args.db}")
    print("-" * 72)

    results = run_storm(
        total_deliveries=args.deliveries,
        unique_keys_count=args.unique_keys,
        seed=args.seed,
        db_path=args.db,
    )

    print("\n[MEASURED RESULTS]")
    print(f"  Total Deliveries Sent:      {results['total_deliveries']:,}")
    print(f"  Unique Idempotency Keys:    {results['unique_keys']:,}")
    print(f"  Ledger Entries Created:     {results['ledger_entries_created']:,}")
    print(f"  Duplicates Collapsed:       {results['duplicates_collapsed']:,}")
    print(f"  Rejections:                 {results['rejections']:,}")
    print(f"    - Stale replay attacks:   {results['rejection_breakdown'].get('stale_timestamp', 0):,}")
    print(f"    - Bad/tampered signature: {results['rejection_breakdown'].get('invalid_signature', 0):,}")
    print(f"    - Missing signature:      {results['rejection_breakdown'].get('missing_header', 0):,}")
    print(f"    - Missing idempotency key:{results['rejection_breakdown'].get('missing_idempotency_key', 0):,}")
    print(f"  Duration:                   {results['duration_sec'] * 1000:.2f} ms ({results['throughput_per_sec']:,.0f} req/s)")
    print("-" * 72)

    print("\n[INVARIANT VERIFICATION]")
    inv_status = "PASSED" if results["invariant_passed"] else "FAILED"
    print(
        f"  Invariant [ledger entries ({results['ledger_entries_created']}) == unique keys ({results['unique_keys']})]: {inv_status}"
    )

    bal_sum = results["ledger_entries_created"] + results["duplicates_collapsed"] + results["rejections"]
    bal_status = "PASSED" if results["balance_passed"] else "FAILED"
    print(
        f"  Balance [entries ({results['ledger_entries_created']}) + dups ({results['duplicates_collapsed']}) + rejects ({results['rejections']}) == {bal_sum} / {results['total_deliveries']}]: {bal_status}"
    )
    print("=" * 72)

    if not (results["invariant_passed"] and results["balance_passed"]):
        sys.exit(1)


if __name__ == "__main__":
    main()
