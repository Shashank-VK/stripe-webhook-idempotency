"""Idempotent ledger backed by SQLite with full auditability and reconciliation logic.

Every decision (applied, duplicate, rejected) is recorded in an audit trail.
The ledger guarantees that the same idempotency key arriving twice, redelivered,
or out-of-order produces exactly ONE ledger entry.
"""

from __future__ import annotations

import enum
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Union


class RecordResult(str, enum.Enum):
    """Result of an event recording operation."""
    APPLIED = "applied"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"

    def __str__(self) -> str:
        return self.value

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            return self.value == other
        return super().__eq__(other)


class IdempotentLedger:
    """SQLite-backed idempotent ledger for financial and webhook event processing."""

    def __init__(self, db_path: str = ":memory:") -> None:
        """Initialize the ledger with SQLite database at db_path."""
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        """Create tables for ledger entries and audit logging."""
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ledger_entries (
                    idempotency_key TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    received_at TEXT NOT NULL,
                    first_applied_at TEXT NOT NULL,
                    outcome TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT,
                    idempotency_key TEXT,
                    event_type TEXT,
                    payload_hash TEXT,
                    received_at TEXT NOT NULL,
                    first_applied_at TEXT,
                    outcome TEXT NOT NULL,
                    reason TEXT
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_idem ON audit_log (idempotency_key)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_recv ON audit_log (received_at)"
            )

    @staticmethod
    def _compute_hash(payload: Union[dict, str, bytes]) -> str:
        """Compute deterministic SHA-256 hex digest of payload."""
        if isinstance(payload, bytes):
            payload_bytes = payload
        elif isinstance(payload, str):
            payload_bytes = payload.encode("utf-8")
        elif isinstance(payload, dict):
            payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            payload_bytes = payload_str.encode("utf-8")
        else:
            payload_bytes = str(payload).encode("utf-8")
        return hashlib.sha256(payload_bytes).hexdigest()

    def record_rejection(
        self,
        reason: str,
        event_id: str | None = None,
        idempotency_key: str | None = None,
        event_type: str | None = None,
        payload_hash: str | None = None,
        received_at: str | None = None,
    ) -> RecordResult:
        """Audit-log a rejected webhook (e.g. signature verification failure or malformed payload)."""
        now_iso = received_at or datetime.now(timezone.utc).isoformat()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO audit_log (
                    event_id, idempotency_key, event_type, payload_hash,
                    received_at, first_applied_at, outcome, reason
                ) VALUES (?, ?, ?, ?, ?, NULL, ?, ?)
                """,
                (
                    event_id,
                    idempotency_key,
                    event_type,
                    payload_hash,
                    now_iso,
                    RecordResult.REJECTED.value,
                    reason,
                ),
            )
        return RecordResult.REJECTED

    def record_event(
        self,
        event_id: str | None,
        idempotency_key: str | None,
        event_type: str | None,
        payload: Union[dict, str, bytes],
        received_at: str | None = None,
        sequence: int | None = None,
    ) -> RecordResult:
        """Record an event idempotently into the ledger.

        Returns:
            RecordResult.APPLIED ("applied") if new entry was created.
            RecordResult.DUPLICATE ("duplicate") if key already exists or out-of-order event reconciled.
            RecordResult.REJECTED ("rejected") if key is missing.
        """
        now_iso = received_at or datetime.now(timezone.utc).isoformat()

        # Missing idempotency key check
        if idempotency_key is None or not str(idempotency_key).strip():
            payload_hash = self._compute_hash(payload) if payload is not None else None
            return self.record_rejection(
                reason="missing_idempotency_key",
                event_id=event_id,
                idempotency_key=None,
                event_type=event_type,
                payload_hash=payload_hash,
                received_at=now_iso,
            )

        clean_key = str(idempotency_key).strip()
        payload_hash = self._compute_hash(payload)
        payload_str = json.dumps(payload, sort_keys=True) if isinstance(payload, dict) else str(payload)
        incoming_seq = sequence if sequence is not None else 1

        with self._conn:
            # Check existing entry
            cursor = self._conn.execute(
                """
                SELECT event_id, event_type, payload_hash, version, first_applied_at
                FROM ledger_entries
                WHERE idempotency_key = ?
                """,
                (clean_key,),
            )
            existing = cursor.fetchone()

            if existing is None:
                # First time seeing this idempotency key -> create entry
                self._conn.execute(
                    """
                    INSERT INTO ledger_entries (
                        idempotency_key, event_id, event_type, payload_hash,
                        payload, status, version, received_at, first_applied_at, outcome
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        clean_key,
                        event_id or "",
                        event_type or "",
                        payload_hash,
                        payload_str,
                        "applied",
                        incoming_seq,
                        now_iso,
                        now_iso,
                        RecordResult.APPLIED.value,
                    ),
                )
                self._conn.execute(
                    """
                    INSERT INTO audit_log (
                        event_id, idempotency_key, event_type, payload_hash,
                        received_at, first_applied_at, outcome, reason
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        event_id,
                        clean_key,
                        event_type,
                        payload_hash,
                        now_iso,
                        now_iso,
                        RecordResult.APPLIED.value,
                    ),
                )
                return RecordResult.APPLIED

            # Key already exists: reconcile duplicate or out-of-order event
            existing_first_applied = existing["first_applied_at"]
            existing_version = existing["version"]

            # Out-of-order reconciliation:
            # If explicit sequence provided and incoming_seq > existing_version,
            # we reconcile the entry to the newer state, but it still remains ONE ledger entry!
            if sequence is not None and incoming_seq > existing_version:
                self._conn.execute(
                    """
                    UPDATE ledger_entries
                    SET event_id = ?, event_type = ?, payload_hash = ?,
                        payload = ?, version = ?, received_at = ?
                    WHERE idempotency_key = ?
                    """,
                    (
                        event_id or "",
                        event_type or "",
                        payload_hash,
                        payload_str,
                        incoming_seq,
                        now_iso,
                        clean_key,
                    ),
                )
                self._conn.execute(
                    """
                    INSERT INTO audit_log (
                        event_id, idempotency_key, event_type, payload_hash,
                        received_at, first_applied_at, outcome, reason
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        clean_key,
                        event_type,
                        payload_hash,
                        now_iso,
                        existing_first_applied,
                        RecordResult.DUPLICATE.value,
                        "reconciled_newer_sequence",
                    ),
                )
                return RecordResult.DUPLICATE

            # Otherwise, incoming event is either a redelivery, exact duplicate,
            # or an out-of-order older event (incoming_seq <= existing_version).
            reason = "out_of_order_superseded" if sequence is not None and incoming_seq < existing_version else "duplicate_delivery"
            self._conn.execute(
                """
                INSERT INTO audit_log (
                    event_id, idempotency_key, event_type, payload_hash,
                    received_at, first_applied_at, outcome, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    clean_key,
                    event_type,
                    payload_hash,
                    now_iso,
                    existing_first_applied,
                    RecordResult.DUPLICATE.value,
                    reason,
                ),
            )
            return RecordResult.DUPLICATE

    def get_entry(self, idempotency_key: str) -> dict[str, Any] | None:
        """Fetch a single ledger entry by its idempotency key."""
        cursor = self._conn.execute(
            """
            SELECT idempotency_key, event_id, event_type, payload_hash,
                   payload, status, version, received_at, first_applied_at, outcome
            FROM ledger_entries
            WHERE idempotency_key = ?
            """,
            (idempotency_key,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_entries(self) -> list[dict[str, Any]]:
        """Fetch all ledger entries."""
        cursor = self._conn.execute(
            """
            SELECT idempotency_key, event_id, event_type, payload_hash,
                   payload, status, version, received_at, first_applied_at, outcome
            FROM ledger_entries
            ORDER BY first_applied_at ASC
            """
        )
        return [dict(row) for row in cursor.fetchall()]

    def count_entries(self) -> int:
        """Return the count of unique ledger entries."""
        cursor = self._conn.execute("SELECT COUNT(*) FROM ledger_entries")
        return cursor.fetchone()[0]

    def get_audit_log(self, idempotency_key: str | None = None) -> list[dict[str, Any]]:
        """Fetch audit log records, optionally filtered by idempotency_key."""
        if idempotency_key is not None:
            cursor = self._conn.execute(
                """
                SELECT audit_id, event_id, idempotency_key, event_type,
                       payload_hash, received_at, first_applied_at, outcome, reason
                FROM audit_log
                WHERE idempotency_key = ?
                ORDER BY audit_id ASC
                """,
                (idempotency_key,),
            )
        else:
            cursor = self._conn.execute(
                """
                SELECT audit_id, event_id, idempotency_key, event_type,
                       payload_hash, received_at, first_applied_at, outcome, reason
                FROM audit_log
                ORDER BY audit_id ASC
                """
            )
        return [dict(row) for row in cursor.fetchall()]

    def get_audit_stats(self) -> dict[str, int]:
        """Return summary counts of audit log outcomes."""
        cursor = self._conn.execute(
            "SELECT outcome, COUNT(*) FROM audit_log GROUP BY outcome"
        )
        counts = {row[0]: row[1] for row in cursor.fetchall()}
        return {
            "applied": counts.get(RecordResult.APPLIED.value, 0),
            "duplicate": counts.get(RecordResult.DUPLICATE.value, 0),
            "rejected": counts.get(RecordResult.REJECTED.value, 0),
            "total": sum(counts.values()),
        }
