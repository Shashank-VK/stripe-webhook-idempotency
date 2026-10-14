"""Stripe-style webhook signature verification module (Test Mode).

Implements HMAC-SHA256 signature verification over '<timestamp>.<raw_body>'
using constant-time comparison and timestamp tolerance checks to prevent replay attacks.
"""

from __future__ import annotations

import hmac
import hashlib
import os
import time
from typing import Union

from stripe_idempotency.exceptions import (
    MissingHeaderError,
    MalformedHeaderError,
    StaleTimestampError,
    InvalidSignatureError,
)


def generate_signature(
    payload: Union[bytes, str],
    secret: str,
    timestamp: int | None = None,
) -> str:
    """Helper to generate a Stripe-Signature style header for tests and simulation.

    Header format: t=<unix_ts>,v1=<hex_hmac>
    Signed payload: <unix_ts>.<raw_body>
    """
    ts = int(time.time()) if timestamp is None else int(timestamp)
    payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload
    signed_payload = f"{ts}.".encode("utf-8") + payload_bytes
    signature = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return f"t={ts},v1={signature}"


class StripeSignatureVerifier:
    """Verifies Stripe-Signature webhook headers with HMAC-SHA256 and replay protection."""

    def __init__(self, secret: str | None = None, tolerance: int = 300) -> None:
        """Initialize verifier with a secret and tolerance in seconds.

        If secret is not provided, reads from WEBHOOK_SECRET env var.
        Raises ValueError if no secret is available.
        """
        self.secret = secret or os.environ.get("WEBHOOK_SECRET")
        if not self.secret or not self.secret.strip():
            raise ValueError(
                "Webhook secret must be provided or set in the WEBHOOK_SECRET environment variable."
            )
        self.tolerance = tolerance

    def parse_header(self, sig_header: str | None) -> tuple[int, list[str]]:
        """Parse Stripe-Signature header into timestamp and list of v1 signatures.

        Format: 't=1492774577,v1=5257a869e7ecebeda32affa62cd492311b2d...[,v1=...]'
        """
        if sig_header is None or not str(sig_header).strip():
            raise MissingHeaderError("Missing Stripe-Signature header.")

        elements = sig_header.strip().split(",")
        timestamp: int | None = None
        v1_signatures: list[str] = []

        for element in elements:
            if "=" not in element:
                continue
            key, val = element.split("=", 1)
            key = key.strip()
            val = val.strip()

            if key == "t":
                try:
                    timestamp = int(val)
                except ValueError:
                    raise MalformedHeaderError(f"Malformed timestamp value: '{val}'.")
            elif key == "v1":
                if val:
                    v1_signatures.append(val)

        if timestamp is None:
            raise MalformedHeaderError("Missing 't' timestamp field in Stripe-Signature header.")
        if not v1_signatures:
            raise MalformedHeaderError("Missing 'v1' signature field in Stripe-Signature header.")

        return timestamp, v1_signatures

    def compute_signature(self, timestamp: int, payload: Union[bytes, str]) -> str:
        """Compute the expected HMAC-SHA256 signature for the given timestamp and payload."""
        payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload
        signed_payload = f"{timestamp}.".encode("utf-8") + payload_bytes
        return hmac.new(self.secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()

    def verify(
        self,
        payload: Union[bytes, str],
        sig_header: str | None,
        current_time: float | None = None,
    ) -> bool:
        """Verify the payload against the Stripe-Signature header.

        Checks:
        1. Header existence and formatting.
        2. Timestamp freshness against tolerance window (abs(current_time - ts) <= tolerance).
        3. Constant-time signature comparison against computed HMAC-SHA256.

        Raises:
            MissingHeaderError: If header is absent or empty.
            MalformedHeaderError: If header cannot be parsed.
            StaleTimestampError: If timestamp is outside tolerance.
            InvalidSignatureError: If signature does not match.

        Returns:
            True if verification succeeds.
        """
        timestamp, signatures = self.parse_header(sig_header)

        now = time.time() if current_time is None else current_time
        if self.tolerance > 0 and abs(now - timestamp) > self.tolerance:
            raise StaleTimestampError(
                f"Timestamp {timestamp} is outside tolerance window of {self.tolerance}s (now={int(now)})."
            )

        expected_sig = self.compute_signature(timestamp, payload)

        # Constant-time comparison against any matching v1 signature
        matched = any(hmac.compare_digest(expected_sig, sig) for sig in signatures)
        if not matched:
            raise InvalidSignatureError("No matching v1 signature found for payload.")

        return True
