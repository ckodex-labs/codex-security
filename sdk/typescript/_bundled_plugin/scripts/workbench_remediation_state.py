"""Remediation request and state mutations for the workbench."""

from __future__ import annotations

import argparse
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class StateDependencies:
    now: Callable[[], str]
    optional_text: Callable[..., str | None]
    require_uuid: Callable[[str, str], str]
    require_occurrence: Callable[[sqlite3.Connection, str], sqlite3.Row]
    require_finding_open: Callable[[sqlite3.Connection, str], None]
    require_scan: Callable[[sqlite3.Connection, str], sqlite3.Row]
    remediation_claim_is_active: Callable[[sqlite3.Row], bool]
    remediation_checkout_snapshot: Callable[..., tuple[str, str | None]]
    require_matching_patch_digest: Callable[[sqlite3.Row, str, str], None]
    require_remediation_checkout_unchanged: Callable[..., None]
    require_remediation_transition: Callable[[str, str], None]
    require_pending_remediation_action: Callable[[sqlite3.Row, str], None]
    require_scan_relative_file: Callable[[sqlite3.Row, str], str]
    require_sha256_digest: Callable[[str, str], str]
    require_reviewed_patch_applied: Callable[[sqlite3.Row, sqlite3.Row, str], str | None]
    scan_context: Callable[..., dict[str, Any]]


@dataclass(frozen=True)
class UpdateValues:
    patch_path: str | None
    patch_digest: str | None
    applied_content_digest: str | None
    summary: str | None
    verification_summary: str | None


def _request(
    connection: sqlite3.Connection,
    request_id: str,
    occurrence_id: str,
) -> sqlite3.Row | None:
    current = connection.execute(
        "SELECT * FROM finding_remediation_attempts WHERE request_id = ?",
        (request_id,),
    ).fetchone()
    if current is not None and current["occurrence_id"] != occurrence_id:
        raise SystemExit("This remediation request belongs to a different finding.")
    return current


def _latest_attempt(
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


def _retire_latest(
    connection: sqlite3.Connection,
    latest: sqlite3.Row | None,
    timestamp: str,
    dependencies: StateDependencies,
) -> None:
    if latest is None:
        return
    active = latest["pending_action"] is not None or latest["state"] in {
        "requested", "verifying",
    }
    if active and (
        latest["state"] != "failed"
        or dependencies.remediation_claim_is_active(latest)
    ):
        raise SystemExit(
            "Finish or retry the active remediation operation before regenerating."
        )
    if latest["state"] == "failed" and latest["pending_action"] is not None:
        connection.execute(
            """
            UPDATE finding_remediation_attempts
            SET pending_action = NULL, pending_action_claimed_at = NULL,
                pending_action_claim_token = NULL,
                pending_action_delivered_at = NULL, updated_at = ?
            WHERE request_id = ?
            """,
            (timestamp, latest["request_id"]),
        )
    if latest["state"] in {"generated", "applied"}:
        connection.execute(
            """
            UPDATE finding_remediation_attempts
            SET state = 'superseded', version = version + 1,
                pending_action = NULL, pending_action_claimed_at = NULL,
                pending_action_claim_token = NULL,
                pending_action_delivered_at = NULL, updated_at = ?
            WHERE request_id = ?
            """,
            (timestamp, latest["request_id"]),
        )


def _insert_request(
    connection: sqlite3.Connection,
    request_id: str,
    occurrence_id: str,
    action_token: str,
    base_revision: str,
    base_content_digest: str | None,
    timestamp: str,
) -> None:
    connection.execute(
        """
        INSERT INTO finding_remediation_attempts (
            request_id, occurrence_id, state, version, base_revision,
            base_content_digest, pending_action, pending_action_claimed_at,
            pending_action_claim_token, created_at, updated_at
        ) VALUES (?, ?, 'requested', 1, ?, ?, 'generate', ?, ?, ?, ?)
        """,
        (
            request_id, occurrence_id, base_revision, base_content_digest,
            timestamp, action_token, timestamp, timestamp,
        ),
    )


def request_finding_remediation(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    dependencies: StateDependencies,
) -> dict[str, Any]:
    request_id = dependencies.require_uuid(args.request_id, "request-id")
    action_token = dependencies.require_uuid(args.action_token, "action-token")
    try:
        occurrence = dependencies.require_occurrence(connection, args.occurrence_id)
        dependencies.require_finding_open(connection, occurrence["id"])
        scan = dependencies.require_scan(connection, occurrence["scan_id"])
        if _request(connection, request_id, occurrence["id"]) is not None:
            return dependencies.scan_context(connection, occurrence["scan_id"])
        base = dependencies.remediation_checkout_snapshot(scan)
        connection.execute("BEGIN IMMEDIATE")
        occurrence = dependencies.require_occurrence(connection, args.occurrence_id)
        dependencies.require_finding_open(connection, occurrence["id"])
        if _request(connection, request_id, occurrence["id"]) is not None:
            connection.commit()
            return dependencies.scan_context(connection, occurrence["scan_id"])
        timestamp = dependencies.now()
        _retire_latest(
            connection, _latest_attempt(connection, occurrence["id"]),
            timestamp, dependencies,
        )
        _insert_request(
            connection, request_id, occurrence["id"], action_token, *base, timestamp
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return dependencies.scan_context(connection, occurrence["scan_id"])


def _action_request(
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
    return current


def _validate_action(
    current: sqlite3.Row,
    scan: sqlite3.Row,
    args: argparse.Namespace,
    action_token: str,
    dependencies: StateDependencies,
) -> bool:
    if current["pending_action"] is not None:
        if (
            current["pending_action"] == args.action
            and current["pending_action_claim_token"] == action_token
        ):
            return False
        raise SystemExit("Another remediation operation is already pending.")
    if current["version"] != args.expected_version:
        raise SystemExit("This remediation request changed. Refresh it before recording an update.")
    required_state = {"apply": "generated", "verify": "applied"}[args.action]
    if current["state"] != required_state:
        raise SystemExit(
            f"Finding remediation cannot request {args.action} from {current['state']}."
        )
    if current["patch_path"] is None or current["patch_digest"] is None:
        raise SystemExit(
            "Generated remediation states require a scan-local patch path and digest."
        )
    dependencies.require_matching_patch_digest(
        scan, current["patch_path"], current["patch_digest"]
    )
    dependencies.require_remediation_checkout_unchanged(
        scan, current, require_base_content=args.action == "apply",
        require_applied_content=args.action == "verify",
    )
    return True


def _queue_action(
    connection: sqlite3.Connection,
    occurrence_id: str,
    request_id: str,
    action_token: str,
    args: argparse.Namespace,
    timestamp: str,
) -> None:
    updated = connection.execute(
        """
        UPDATE finding_remediation_attempts
        SET pending_action = ?, pending_action_claimed_at = ?,
            pending_action_claim_token = ?, pending_action_delivered_at = NULL,
            version = version + 1, updated_at = ?
        WHERE request_id = ? AND occurrence_id = ? AND version = ? AND pending_action IS NULL
        """,
        (
            args.action, timestamp, action_token, timestamp, request_id,
            occurrence_id, args.expected_version,
        ),
    )
    if updated.rowcount != 1:
        raise SystemExit("This remediation request changed. Refresh it before recording an update.")


def request_finding_remediation_action(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    dependencies: StateDependencies,
) -> dict[str, Any]:
    request_id = dependencies.require_uuid(args.request_id, "request-id")
    action_token = dependencies.require_uuid(args.action_token, "action-token")
    try:
        occurrence = dependencies.require_occurrence(connection, args.occurrence_id)
        dependencies.require_finding_open(connection, occurrence["id"])
        scan = dependencies.require_scan(connection, occurrence["scan_id"])
        current = _action_request(connection, request_id, occurrence)
        if not _validate_action(current, scan, args, action_token, dependencies):
            connection.commit()
            return dependencies.scan_context(connection, occurrence["scan_id"])
        connection.execute("BEGIN IMMEDIATE")
        occurrence = dependencies.require_occurrence(connection, args.occurrence_id)
        dependencies.require_finding_open(connection, occurrence["id"])
        _queue_action(
            connection, occurrence["id"], request_id, action_token, args,
            dependencies.now(),
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return dependencies.scan_context(connection, occurrence["scan_id"])


def _patch_values(
    scan: sqlite3.Row,
    current: sqlite3.Row,
    args: argparse.Namespace,
    dependencies: StateDependencies,
) -> tuple[str | None, str | None]:
    patch_path = current["patch_path"]
    if args.patch_path is not None:
        requested = dependencies.require_scan_relative_file(scan, args.patch_path)
        if patch_path is not None and requested != patch_path:
            raise SystemExit("A remediation attempt cannot replace its reviewed patch path.")
        patch_path = requested
    patch_digest = current["patch_digest"]
    if args.patch_digest is not None:
        requested = dependencies.require_sha256_digest(args.patch_digest, "patch-digest")
        if patch_digest is not None and requested != patch_digest:
            raise SystemExit("A remediation attempt cannot replace its reviewed patch digest.")
        patch_digest = requested
    return patch_path, patch_digest


def _validate_update(
    scan: sqlite3.Row,
    current: sqlite3.Row,
    args: argparse.Namespace,
    summary: str | None,
    verification: str | None,
    dependencies: StateDependencies,
) -> UpdateValues:
    patch_path, patch_digest = _patch_values(scan, current, args, dependencies)
    base_revision = dependencies.optional_text(args.base_revision, maximum=512)
    if args.state in {"generated", "applied", "verifying", "verified"}:
        if patch_path is None or patch_digest is None:
            raise SystemExit(
                "Generated remediation states require a scan-local patch path and digest."
            )
        dependencies.require_matching_patch_digest(scan, patch_path, patch_digest)
    if args.state == "generated":
        dependencies.require_remediation_checkout_unchanged(
            scan, current, require_base_content=True
        )
    _validate_applied_state(scan, current, args, base_revision, dependencies)
    if args.state == "verified" and verification is None:
        raise SystemExit("Verified remediation requires a verification summary.")
    applied = current["applied_content_digest"]
    if args.state == "applied":
        applied = dependencies.require_reviewed_patch_applied(scan, current, patch_path)
    return UpdateValues(patch_path, patch_digest, applied, summary, verification)


def _validate_applied_state(
    scan: sqlite3.Row,
    current: sqlite3.Row,
    args: argparse.Namespace,
    base_revision: str | None,
    dependencies: StateDependencies,
) -> None:
    if args.state not in {"applied", "verifying", "verified"}:
        return
    if base_revision != current["base_revision"]:
        raise SystemExit(
            "The remediation base revision changed. Regenerate the patch before applying it."
        )
    if args.state in {"verifying", "verified"}:
        dependencies.require_remediation_checkout_unchanged(
            scan, current, require_applied_content=True
        )


def _write_update(
    connection: sqlite3.Connection,
    occurrence_id: str,
    request_id: str,
    action_token: str,
    current: sqlite3.Row,
    args: argparse.Namespace,
    values: UpdateValues,
    timestamp: str,
) -> None:
    replace_failure = current["state"] == "failed" and args.state != "failed"
    updated = connection.execute(
        """
        UPDATE finding_remediation_attempts
        SET state = ?, version = version + 1, patch_path = ?, patch_digest = ?,
            applied_content_digest = ?,
            pending_action = CASE WHEN ? IN ('verifying', 'failed') THEN pending_action ELSE NULL END,
            pending_action_claimed_at = CASE WHEN ? = 'verifying' THEN pending_action_claimed_at ELSE NULL END,
            pending_action_claim_token = CASE WHEN ? = 'verifying' THEN pending_action_claim_token ELSE NULL END,
            pending_action_delivered_at = CASE WHEN ? = 'verifying' THEN pending_action_delivered_at ELSE NULL END,
            summary = CASE WHEN ? THEN ? ELSE COALESCE(?, summary) END,
            verification_summary = COALESCE(?, verification_summary), updated_at = ?
        WHERE request_id = ? AND occurrence_id = ? AND version = ?
            AND pending_action_claim_token = ?
        """,
        (
            args.state, values.patch_path, values.patch_digest,
            values.applied_content_digest, args.state, args.state, args.state, args.state,
            replace_failure, values.summary, values.summary, values.verification_summary,
            timestamp, request_id, occurrence_id, args.expected_version, action_token,
        ),
    )
    if updated.rowcount != 1:
        raise SystemExit("This remediation request changed. Refresh it before recording an update.")


def set_finding_remediation(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    dependencies: StateDependencies,
) -> dict[str, Any]:
    request_id = dependencies.require_uuid(args.request_id, "request-id")
    action_token = dependencies.require_uuid(args.action_token, "action-token")
    summary = dependencies.optional_text(args.summary, maximum=2400)
    verification = dependencies.optional_text(args.verification_summary, maximum=2400)
    try:
        occurrence = dependencies.require_occurrence(connection, args.occurrence_id)
        dependencies.require_finding_open(connection, occurrence["id"])
        scan = dependencies.require_scan(connection, occurrence["scan_id"])
        current = _action_request(connection, request_id, occurrence)
        if current["version"] != args.expected_version:
            raise SystemExit("This remediation request changed. Refresh it before recording an update.")
        if current["pending_action_claim_token"] is None:
            raise SystemExit(
                "This remediation attempt does not have an owned pending host request."
            )
        if current["pending_action_claim_token"] != action_token:
            raise SystemExit("This remediation host request is owned by a different action token.")
        dependencies.require_remediation_transition(current["state"], args.state)
        dependencies.require_pending_remediation_action(current, args.state)
        values = _validate_update(
            scan, current, args, summary, verification, dependencies
        )
        connection.execute("BEGIN IMMEDIATE")
        occurrence = dependencies.require_occurrence(connection, args.occurrence_id)
        dependencies.require_finding_open(connection, occurrence["id"])
        _write_update(
            connection, occurrence["id"], request_id, action_token, current,
            args, values, dependencies.now(),
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return dependencies.scan_context(connection, occurrence["scan_id"])
