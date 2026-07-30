"""Append-only CKODEX governance evidence persistence."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
import tempfile
from argparse import Namespace
from typing import Any, Callable

from workbench_governance_validation import canonical, record_id, sha256, validate_record


def _response(row: sqlite3.Row, created: bool) -> dict[str, Any]:
    return {
        "created": created,
        "governanceEvidence": {
            "recordId": row["record_id"],
            "scanId": row["scan_id"],
            "kind": row["evidence_kind"],
            "actionId": row["action_id"],
            "mediaType": row["media_type"],
            "digest": row["payload_digest"],
            "contextCertificateDigest": row["context_certificate_digest"],
            "retention": row["retention"],
            "createdAt": row["created_at"],
            "evidence": json.loads(row["payload_json"]),
        },
    }


def append_governance_evidence(
    connection: sqlite3.Connection,
    args: Namespace,
    *,
    require_scan: Callable[[sqlite3.Connection, str], sqlite3.Row],
    now: Callable[[], str],
) -> dict[str, Any]:
    require_scan(connection, args.scan_id)
    created_at = now()
    record, media_type, payload_json, payload_digest = validate_record(
        args.record_json, created_at
    )
    certificate = record["action"]["context"]["certificate"]
    certificate_digest = sha256(canonical(certificate))
    identity = (args.scan_id, record["recordId"])
    connection.execute("BEGIN IMMEDIATE")
    try:
        existing = _find_evidence(connection, identity)
        if existing is not None:
            if existing["payload_digest"] != payload_digest:
                raise SystemExit("Governance evidence identity is immutable.")
            connection.commit()
            return _response(existing, False)
        _insert_evidence(
            connection, args.scan_id, record, media_type, payload_json,
            payload_digest, certificate_digest, created_at,
        )
        _insert_signed_envelope(connection, args.scan_id, record, created_at)
        row = _find_evidence(connection, identity)
        connection.commit()
        return _response(row, True)
    except BaseException:
        connection.rollback()
        raise


def _find_evidence(
    connection: sqlite3.Connection, identity: tuple[str, str]
) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT * FROM governance_evidence WHERE scan_id = ? AND record_id = ?",
        identity,
    ).fetchone()


def _insert_evidence(
    connection: sqlite3.Connection,
    scan_id: str,
    record: dict[str, Any],
    media_type: str,
    payload_json: str,
    payload_digest: str,
    certificate_digest: str,
    created_at: str,
) -> None:
    connection.execute(
        """
        INSERT INTO governance_evidence (
            record_id, scan_id, evidence_kind, action_id, media_type,
            payload_json, payload_digest, context_certificate_digest,
            retention, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record["recordId"], scan_id, record["kind"], record["action"]["id"],
            media_type, payload_json, payload_digest, certificate_digest,
            record["action"]["data"]["retention"], created_at,
        ),
    )


def _insert_signed_envelope(
    connection: sqlite3.Connection,
    scan_id: str,
    record: dict[str, Any],
    created_at: str,
) -> None:
    envelope = record.get("signedEnvelope")
    if envelope is None:
        return
    connection.execute(
        """
        INSERT INTO signed_governance_envelopes (
            scan_id, record_id, payload_digest, signature_bundle_digest,
            proof_mode, envelope_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            record["recordId"],
            envelope["payloadDigest"],
            envelope["signatureBundleDigest"],
            envelope["proofMode"],
            canonical(envelope),
            created_at,
        ),
    )


def get_governance_evidence(
    connection: sqlite3.Connection,
    args: Namespace,
    *,
    require_scan: Callable[[sqlite3.Connection, str], sqlite3.Row],
) -> dict[str, Any]:
    require_scan(connection, args.scan_id)
    evidence_id = record_id(args.record_id, "record-id")
    row = _find_evidence(connection, (args.scan_id, evidence_id))
    if row is None:
        raise SystemExit("Governance evidence was not found for this scan.")
    return _response(row, False)


def _manifest_digest(scan: sqlite3.Row) -> str:
    value = scan["seal_manifest_digest"]
    if (
        scan["status"] != "complete"
        or not isinstance(value, str)
        or re.fullmatch(r"sha256:[a-f0-9]{64}", value) is None
    ):
        raise SystemExit("Promotion evidence requires a completed sealed scan.")
    return value


def verify_promotion_evidence(
    connection: sqlite3.Connection,
    args: Namespace,
    *,
    require_scan: Callable[[sqlite3.Connection, str], sqlite3.Row],
) -> dict[str, Any]:
    scan = require_scan(connection, args.scan_id)
    manifest_digest = _manifest_digest(scan)
    evidence_id = record_id(args.record_id, "record-id")
    row = _find_evidence(connection, (args.scan_id, evidence_id))
    if row is None:
        raise SystemExit("Governance evidence was not found for this scan.")
    evidence = json.loads(row["payload_json"])
    action = evidence["action"]
    bpl = evidence.get("bpl")
    if not action["evidence"]["backPropRequired"] or bpl is None:
        raise SystemExit("Promotion evidence requires a promotion-critical BPL.")
    if bpl["promotionRef"] != args.promotion_ref:
        raise SystemExit("Promotion reference does not match the bound BPL.")
    manifest_ref = f"scan-manifest:{manifest_digest}"
    if manifest_ref not in bpl["artifactRefs"]:
        raise SystemExit("BPL does not bind the recorded sealed manifest digest.")
    envelope = evidence.get("signedEnvelope")
    if envelope is None:
        raise SystemExit("Promotion evidence requires a signed envelope.")
    if envelope["payload"]["manifestDigest"] != manifest_digest:
        raise SystemExit("Signed envelope does not bind the sealed manifest.")
    _verify_signed_envelope(envelope)
    return {
        "promotionEvidence": {
            "scanId": args.scan_id,
            "recordId": evidence_id,
            "promotionRef": args.promotion_ref,
            "manifestDigest": manifest_digest,
            "evidenceDigest": row["payload_digest"],
            "bplDigest": sha256(canonical(bpl)),
            "signedEnvelopeDigest": envelope["payloadDigest"],
            "proofMode": envelope["proofMode"],
        }
    }


def _verify_signed_envelope(envelope: dict[str, Any]) -> None:
    executable = os.environ.get("CODEX_SECURITY_COSIGN", "cosign")
    if os.path.basename(executable) != executable and not os.path.isabs(executable):
        raise SystemExit("CODEX_SECURITY_COSIGN must be a command or absolute path.")
    with tempfile.TemporaryDirectory(prefix="ckodex-envelope-") as root:
        payload_path = os.path.join(root, "payload.json")
        bundle_path = os.path.join(root, "signature.sigstore.json")
        public_key_path = os.path.join(root, "cosign.pub")
        with open(payload_path, "w", encoding="utf-8") as handle:
            handle.write(canonical(envelope["payload"]))
        with open(bundle_path, "w", encoding="utf-8") as handle:
            handle.write(envelope["signatureBundle"])
        with open(public_key_path, "w", encoding="utf-8") as handle:
            handle.write(envelope["publicKeyPem"])
        try:
            result = subprocess.run(
                [
                    executable, "verify-blob", "--insecure-ignore-tlog",
                    "--bundle", bundle_path, "--key", public_key_path, payload_path,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={"PATH": os.environ.get("PATH", "")},
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SystemExit("Cosign envelope verification failed closed.") from exc
        if result.returncode != 0:
            raise SystemExit("Cosign envelope verification failed closed.")
