import os
import time
import pytest
from stripe_idempotency.verifier import StripeSignatureVerifier, generate_signature
from stripe_idempotency.exceptions import (
    MissingHeaderError,
    MalformedHeaderError,
    StaleTimestampError,
    InvalidSignatureError,
)


def test_valid_signature_accepted(verifier: StripeSignatureVerifier, webhook_secret: str, sample_raw_body: str):
    """Test that a freshly signed payload with a valid signature is accepted."""
    now = int(time.time())
    header = generate_signature(sample_raw_body, webhook_secret, timestamp=now)
    assert verifier.verify(sample_raw_body, header, current_time=now) is True


def test_invalid_signature_rejected(verifier: StripeSignatureVerifier, sample_raw_body: str):
    """Test that a header with a bogus signature fails verification."""
    now = int(time.time())
    bad_header = f"t={now},v1=badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad"
    with pytest.raises(InvalidSignatureError, match="No matching v1 signature"):
        verifier.verify(sample_raw_body, bad_header, current_time=now)


def test_tampered_payload_rejected(verifier: StripeSignatureVerifier, webhook_secret: str, sample_raw_body: str):
    """Test that modifying even one character in the payload causes verification to fail."""
    now = int(time.time())
    valid_header = generate_signature(sample_raw_body, webhook_secret, timestamp=now)
    tampered_body = sample_raw_body.replace("2000", "9999")

    with pytest.raises(InvalidSignatureError):
        verifier.verify(tampered_body, valid_header, current_time=now)


def test_stale_timestamp_rejected_as_replay(verifier: StripeSignatureVerifier, webhook_secret: str, sample_raw_body: str):
    """Test that an event signed beyond the tolerance window is rejected."""
    now = 1700000000
    stale_ts = now - 301  # Tolerance is 300s
    header = generate_signature(sample_raw_body, webhook_secret, timestamp=stale_ts)

    with pytest.raises(StaleTimestampError, match="outside tolerance window"):
        verifier.verify(sample_raw_body, header, current_time=now)


def test_future_timestamp_beyond_tolerance_rejected(verifier: StripeSignatureVerifier, webhook_secret: str, sample_raw_body: str):
    """Test that an event with a clock-skewed future timestamp beyond tolerance is rejected."""
    now = 1700000000
    future_ts = now + 301
    header = generate_signature(sample_raw_body, webhook_secret, timestamp=future_ts)

    with pytest.raises(StaleTimestampError, match="outside tolerance window"):
        verifier.verify(sample_raw_body, header, current_time=now)


def test_timestamp_at_tolerance_boundary_accepted(verifier: StripeSignatureVerifier, webhook_secret: str, sample_raw_body: str):
    """Test that timestamps exactly at the boundary window (300s) are accepted."""
    now = 1700000000
    edge_ts = now - 300
    header = generate_signature(sample_raw_body, webhook_secret, timestamp=edge_ts)
    assert verifier.verify(sample_raw_body, header, current_time=now) is True


def test_missing_header_rejected(verifier: StripeSignatureVerifier, sample_raw_body: str):
    """Test that missing or empty signature headers are rejected with MissingHeaderError."""
    with pytest.raises(MissingHeaderError, match="Missing Stripe-Signature"):
        verifier.verify(sample_raw_body, None)

    with pytest.raises(MissingHeaderError, match="Missing Stripe-Signature"):
        verifier.verify(sample_raw_body, "")

    with pytest.raises(MissingHeaderError, match="Missing Stripe-Signature"):
        verifier.verify(sample_raw_body, "   ")


@pytest.mark.parametrize(
    "malformed_header",
    [
        "t=not_a_number,v1=abcdef",
        "t=1700000000",  # missing v1
        "v1=abcdef",      # missing t
        "garbage_header_without_keys",
        "t=1700000000,v2=abcdef",  # missing v1 scheme
        "=,=,",
    ],
)
def test_malformed_header_rejected(verifier: StripeSignatureVerifier, sample_raw_body: str, malformed_header: str):
    """Test that improperly formatted headers are cleanly rejected."""
    with pytest.raises(MalformedHeaderError):
        verifier.verify(sample_raw_body, malformed_header)


def test_multiple_v1_signatures_accepted_if_one_matches(verifier: StripeSignatureVerifier, webhook_secret: str, sample_raw_body: str):
    """Test Stripe's signature rotation scheme where header has multiple v1 signatures."""
    now = int(time.time())
    valid_sig = generate_signature(sample_raw_body, webhook_secret, timestamp=now).split("v1=")[1]
    header = f"t={now},v1=deadbeef1234,v1={valid_sig},v1=cafebabe5678"
    assert verifier.verify(sample_raw_body, header, current_time=now) is True


def test_replay_attack_with_old_timestamp_and_valid_sig_rejected(
    verifier: StripeSignatureVerifier, webhook_secret: str, sample_raw_body: str
):
    """Test that re-sending an authentic yesterday webhook is stopped dead by the replay check."""
    now = int(time.time())
    yesterday_ts = now - 86400  # 24 hours old
    valid_historical_header = generate_signature(sample_raw_body, webhook_secret, timestamp=yesterday_ts)

    with pytest.raises(StaleTimestampError):
        verifier.verify(sample_raw_body, valid_historical_header, current_time=now)


def test_verifier_reads_secret_from_env_var(monkeypatch, sample_raw_body: str):
    """Test that StripeSignatureVerifier reads WEBHOOK_SECRET from the environment if not passed."""
    env_secret = "whsec_test_env_configured_9999"
    monkeypatch.setenv("WEBHOOK_SECRET", env_secret)

    auto_verifier = StripeSignatureVerifier()
    now = int(time.time())
    header = generate_signature(sample_raw_body, env_secret, timestamp=now)
    assert auto_verifier.verify(sample_raw_body, header, current_time=now) is True


def test_verifier_missing_secret_raises_value_error(monkeypatch):
    """Test that instantiating StripeSignatureVerifier without secret or env var raises ValueError."""
    monkeypatch.delenv("WEBHOOK_SECRET", raising=False)
    with pytest.raises(ValueError, match="Webhook secret must be provided"):
        StripeSignatureVerifier()
