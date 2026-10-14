from scripts.redelivery_storm import run_storm


def test_redelivery_storm_simulation_invariants():
    """Verify that the redelivery storm simulation guarantees exactly-once ledger entries."""
    results = run_storm(total_deliveries=200, unique_keys_count=40, seed=99)
    assert results["invariant_passed"] is True
    assert results["balance_passed"] is True
    assert results["ledger_entries_created"] == 40
    assert results["total_deliveries"] == 200
    assert results["ledger_entries_created"] + results["duplicates_collapsed"] + results["rejections"] == 200
