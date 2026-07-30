"""Remediation host-request lease delivery for the workbench."""

from __future__ import annotations

import argparse
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from workbench_constants import DELIVERED_ACTION_LEASE_SECONDS


@dataclass(frozen=True)
class DeliveryDependencies:
    now: Callable[[], str]
    require_uuid: Callable[[str, str], str]
    require_occurrence: Callable[[sqlite3.Connection, str], sqlite3.Row]
    require_finding_open: Callable[[sqlite3.Connection, str], None]
    stale_claim_before: Callable[..., str]
    scan_context: Callable[..., dict[str, Any]]


def _pending_request(
    connection: sqlite3.Connection,
    request_id: str,
    occurrence: sqlite3.Row,
) -> sqlite3.Row:
    current = connection.execute(
        "SELECT * FROM finding_remediation_attempts WHERE request_id = ?",
        (request_id,),
    ).fetchone()
    if current is None or current["occurrence_id"] != occurrence["id"]:
        raise SystemExit("Codex Security finding remediation request not found.")
    if current["pending_action"] is None:
        raise SystemExit("This remediation attempt does not have a pending host request.")
    return current


def _replace_delivered_claim(
    connection: sqlite3.Connection,
    current: sqlite3.Row,
    occurrence_id: str,
    action_token: str,
    timestamp: str,
    stale_before: str,
) -> sqlite3.Cursor:
    return connection.execute(
        """
        UPDATE finding_remediation_attempts
        SET pending_action_claimed_at = ?, pending_action_claim_token = ?,
            pending_action_delivered_at = NULL, updated_at = ?
        WHERE request_id = ? AND occurrence_id = ? AND pending_action IS NOT NULL
            AND pending_action_claim_token = ? AND pending_action_delivered_at <= ?
        """,
        (
            timestamp, action_token, timestamp, current["request_id"], occurrence_id,
            current["pending_action_claim_token"], stale_before,
        ),
    )


def _replace_open_claim(
    connection: sqlite3.Connection,
    current: sqlite3.Row,
    occurrence_id: str,
    action_token: str,
    timestamp: str,
    stale_before: str,
) -> sqlite3.Cursor:
    return connection.execute(
        """
        UPDATE finding_remediation_attempts
        SET pending_action_claimed_at = ?, pending_action_claim_token = ?,
            pending_action_delivered_at = NULL, updated_at = ?
        WHERE request_id = ? AND occurrence_id = ? AND pending_action IS NOT NULL
            AND (
                pending_action_claim_token IS NULL
                OR pending_action_claimed_at IS NULL
                OR pending_action_claimed_at <= ?
            )
        """,
        (
            timestamp, action_token, timestamp, current["request_id"], occurrence_id,
            stale_before,
        ),
    )


def _claim_pending(
    connection: sqlite3.Connection,
    current: sqlite3.Row,
    occurrence_id: str,
    action_token: str,
    timestamp: str,
    dependencies: DeliveryDependencies,
) -> None:
    if current["pending_action_delivered_at"] is not None:
        updated = _replace_delivered_claim(
            connection, current, occurrence_id, action_token, timestamp,
            dependencies.stale_claim_before(DELIVERED_ACTION_LEASE_SECONDS),
        )
        unavailable = "This remediation worker is still within its execution lease. Retry later."
    else:
        updated = _replace_open_claim(
            connection, current, occurrence_id, action_token, timestamp,
            dependencies.stale_claim_before(),
        )
        unavailable = (
            "This remediation host request is still owned by another panel. "
            "Retry after its lease expires."
        )
    if updated.rowcount != 1:
        raise SystemExit(unavailable)


def claim_finding_remediation_resend(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    dependencies: DeliveryDependencies,
) -> dict[str, Any]:
    request_id = dependencies.require_uuid(args.request_id, "request-id")
    action_token = dependencies.require_uuid(args.action_token, "action-token")
    connection.execute("BEGIN IMMEDIATE")
    try:
        occurrence = dependencies.require_occurrence(connection, args.occurrence_id)
        dependencies.require_finding_open(connection, occurrence["id"])
        current = _pending_request(connection, request_id, occurrence)
        if current["pending_action_claim_token"] != action_token:
            _claim_pending(
                connection, current, occurrence["id"], action_token,
                dependencies.now(), dependencies,
            )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    result = dependencies.scan_context(connection, occurrence["scan_id"])
    result["actionToken"] = action_token
    return result


def mark_finding_remediation_delivered(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    dependencies: DeliveryDependencies,
) -> dict[str, Any]:
    request_id = dependencies.require_uuid(args.request_id, "request-id")
    action_token = dependencies.require_uuid(args.action_token, "action-token")
    timestamp = dependencies.now()
    with connection:
        occurrence = dependencies.require_occurrence(connection, args.occurrence_id)
        updated = connection.execute(
            """
            UPDATE finding_remediation_attempts
            SET pending_action_delivered_at = ?, updated_at = ?
            WHERE request_id = ? AND occurrence_id = ? AND pending_action IS NOT NULL
                AND pending_action_claim_token = ?
            """,
            (timestamp, timestamp, request_id, occurrence["id"], action_token),
        )
        if updated.rowcount != 1:
            raise SystemExit(
                "This remediation host request is no longer owned by this action token."
            )
    return dependencies.scan_context(connection, occurrence["scan_id"])


def release_finding_remediation_claim(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    dependencies: DeliveryDependencies,
) -> dict[str, Any]:
    request_id = dependencies.require_uuid(args.request_id, "request-id")
    action_token = dependencies.require_uuid(args.action_token, "action-token")
    timestamp = dependencies.now()
    with connection:
        occurrence = dependencies.require_occurrence(connection, args.occurrence_id)
        connection.execute(
            """
            UPDATE finding_remediation_attempts
            SET pending_action_claimed_at = NULL, pending_action_claim_token = NULL,
                pending_action_delivered_at = NULL, updated_at = ?
            WHERE request_id = ? AND occurrence_id = ? AND pending_action IS NOT NULL
                AND pending_action_claim_token = ?
            """,
            (timestamp, request_id, occurrence["id"], action_token),
        )
    return dependencies.scan_context(connection, occurrence["scan_id"])
