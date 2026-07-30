"""Finding triage mutations for the Codex Security workbench."""

from __future__ import annotations

import argparse
import sqlite3
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class TriageDependencies:
    now: Callable[[], str]
    optional_text: Callable[..., str | None]
    require_close_reason: Callable[[str | None, str | None], None]
    require_occurrence: Callable[[sqlite3.Connection, str], sqlite3.Row]
    require_scan: Callable[[sqlite3.Connection, str], sqlite3.Row]
    remediation_claim_is_active: Callable[[sqlite3.Row], bool]
    require_remediation_checkout_unchanged: Callable[..., None]
    scan_context: Callable[..., dict[str, Any]]


def _latest_remediation(
    connection: sqlite3.Connection, occurrence_id: str
) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT *
        FROM finding_remediation_attempts
        WHERE occurrence_id = ?
        ORDER BY created_at DESC, rowid DESC
        LIMIT 1
        """,
        (occurrence_id,),
    ).fetchone()


def _verify_close(
    connection: sqlite3.Connection,
    occurrence: sqlite3.Row,
    close_reason: str,
    dependencies: TriageDependencies,
) -> None:
    remediation = _latest_remediation(connection, occurrence["id"])
    pending = remediation is not None and remediation["pending_action"] is not None
    released_failure = (
        remediation is not None
        and remediation["state"] == "failed"
        and not dependencies.remediation_claim_is_active(remediation)
    )
    if pending and not released_failure:
        raise SystemExit(
            "Wait for the pending remediation operation to finish before closing this finding."
        )
    if close_reason != "already_fixed" or remediation is None:
        return
    if remediation["state"] != "verified":
        return
    scan = dependencies.require_scan(connection, occurrence["scan_id"])
    dependencies.require_remediation_checkout_unchanged(
        scan, remediation, require_applied_content=True
    )


def _record_decision(
    connection: sqlite3.Connection,
    occurrence_id: str,
    status: str,
    close_reason: str | None,
    note: str | None,
    timestamp: str,
) -> None:
    previous = connection.execute(
        "SELECT status, close_reason, note FROM finding_triage WHERE occurrence_id = ?",
        (occurrence_id,),
    ).fetchone()
    values = (status, close_reason, note)
    if previous is not None and tuple(previous) == values:
        return
    connection.execute(
        """
        INSERT INTO finding_decisions (
            id, occurrence_id, status, close_reason, note, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (str(uuid.uuid4()), occurrence_id, *values, timestamp),
    )


def _upsert_triage(
    connection: sqlite3.Connection,
    occurrence_id: str,
    status: str,
    close_reason: str | None,
    note: str | None,
    timestamp: str,
) -> None:
    connection.execute(
        """
        INSERT INTO finding_triage (occurrence_id, status, close_reason, note, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(occurrence_id) DO UPDATE SET
            status = excluded.status,
            close_reason = excluded.close_reason,
            note = excluded.note,
            updated_at = excluded.updated_at
        """,
        (occurrence_id, status, close_reason, note, timestamp),
    )


def set_finding_triage(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    dependencies: TriageDependencies,
) -> dict[str, Any]:
    close_reason = args.close_reason
    if args.status == "open" and close_reason is not None:
        raise SystemExit("An open finding cannot keep a close reason.")
    if args.status == "closed" and close_reason is None:
        raise SystemExit("Choose why this finding is being closed.")
    note = dependencies.optional_text(args.note, maximum=2400)
    dependencies.require_close_reason(close_reason, note)
    connection.execute("BEGIN IMMEDIATE")
    try:
        timestamp = dependencies.now()
        occurrence = dependencies.require_occurrence(connection, args.occurrence_id)
        if args.status == "closed":
            _verify_close(connection, occurrence, close_reason, dependencies)
        _record_decision(
            connection, occurrence["id"], args.status, close_reason, note, timestamp
        )
        _upsert_triage(
            connection, occurrence["id"], args.status, close_reason, note, timestamp
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return dependencies.scan_context(connection, occurrence["scan_id"])
