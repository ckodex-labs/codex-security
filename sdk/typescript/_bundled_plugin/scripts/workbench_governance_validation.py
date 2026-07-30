"""Strict validation for CKODEX governance evidence."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime
from typing import Any

from workbench_governance_action_validation import validate_action

MAX_RECORD_BYTES = 256 * 1024
TEXT_LIMIT = 4096
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
RECORD_ID = re.compile(r"^(?:model|sandbox):[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
SECRET = re.compile(
    r"(?:\b(?:authorization|api[_ -]?key|token|password|secret)\s*[:=]\s*\S+"
    r"|\bbearer\s+[A-Za-z0-9._~-]{12,}|\bsk-[A-Za-z0-9_-]{12,})",
    re.IGNORECASE,
)
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
KINDS = {
    "model_decision": "application/vnd.ckodex.decision-trace+json",
    "sandbox_execution": "application/vnd.ckodex.sandbox-execution+json",
}


def _object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SystemExit(f"{context}: expected an object.")
    return value


def _keys(
    value: dict[str, Any],
    required: set[str],
    context: str,
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    missing = required - value.keys()
    extra = value.keys() - required - optional
    if missing:
        raise SystemExit(f"{context}: missing fields: {', '.join(sorted(missing))}.")
    if extra:
        raise SystemExit(f"{context}: unknown fields: {', '.join(sorted(extra))}.")


def _text(value: Any, context: str, limit: int = TEXT_LIMIT) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > limit
        or any(ord(character) < 32 for character in value)
    ):
        raise SystemExit(f"{context}: expected bounded non-control text.")
    return value


def _digest(value: Any, context: str) -> str:
    text = _text(value, context, 71)
    if DIGEST.fullmatch(text) is None:
        raise SystemExit(f"{context}: expected a sha256 digest.")
    return text


def _number(value: Any, context: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise SystemExit(f"{context}: expected a finite non-negative number.")
    return value


def _texts(value: Any, context: str, limit: int = 128) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise SystemExit(f"{context}: expected a bounded array.")
    return [_text(item, f"{context}[{index}]") for index, item in enumerate(value)]


def _timestamp(value: Any, context: str) -> str:
    text = _text(value, context, 64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemExit(f"{context}: expected an ISO 8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise SystemExit(f"{context}: timestamp must include a timezone.")
    return text


def _public_key(value: Any) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 8192:
        raise SystemExit("signedEnvelope.publicKeyPem: expected a bounded public key.")
    if any(ord(character) < 32 and character not in "\r\n" for character in value):
        raise SystemExit("signedEnvelope.publicKeyPem: contains control text.")
    if "BEGIN PUBLIC KEY" not in value or "PRIVATE KEY" in value:
        raise SystemExit("signedEnvelope.publicKeyPem: expected a public key.")
    return value


def _reject_sensitive(value: Any, context: str = "record") -> None:
    if isinstance(value, str):
        if SECRET.search(value) is not None or EMAIL.search(value) is not None:
            raise SystemExit(f"{context}: secret or PII-like text is forbidden.")
        return
    if isinstance(value, list):
        _reject_sensitive_items(enumerate(value), context, brackets=True)
        return
    if isinstance(value, dict):
        _reject_sensitive_items(value.items(), context, brackets=False)


def _reject_sensitive_items(
    items: Any, context: str, *, brackets: bool
) -> None:
    for key, item in items:
        if context == "record.signedEnvelope" and key in {
            "publicKeyPem",
            "signatureBundle",
        }:
            continue
        child = f"{context}[{key}]" if brackets else f"{context}.{key}"
        _reject_sensitive(item, child)


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _sha256(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _validate_bpl(value: Any, action: dict[str, Any]) -> dict[str, Any]:
    bpl = _object(value, "bpl")
    _keys(
        bpl,
        {
            "schemaVersion",
            "promotionRef",
            "artifactRefs",
            "skillChain",
            "contextSliceDigest",
            "sourceRefs",
            "actorDecisionRefs",
            "policyPath",
            "createdAt",
        },
        "bpl",
    )
    if bpl["schemaVersion"] != 1:
        raise SystemExit("bpl.schemaVersion: expected 1.")
    for field in ("promotionRef", "policyPath"):
        _text(bpl[field], f"bpl.{field}")
    _timestamp(bpl["createdAt"], "bpl.createdAt")
    for field in ("artifactRefs", "skillChain", "sourceRefs", "actorDecisionRefs"):
        if not _texts(bpl[field], f"bpl.{field}", 256):
            raise SystemExit(f"bpl.{field}: expected at least one reference.")
    _digest(bpl["contextSliceDigest"], "bpl.contextSliceDigest")
    if bpl["contextSliceDigest"] != action["context"]["certificate"]["sliceHash"]:
        raise SystemExit("bpl.contextSliceDigest: does not bind the context certificate.")
    if bpl["policyPath"] != action["policy"]["bundleRef"]:
        raise SystemExit("bpl.policyPath: does not bind the action policy.")
    return bpl


def _validate_signature_material(envelope: dict[str, Any]) -> None:
    _public_key(envelope["publicKeyPem"])
    bundle = _text(envelope["signatureBundle"], "signedEnvelope.signatureBundle", 65536)
    try:
        json.loads(bundle)
    except json.JSONDecodeError as exc:
        raise SystemExit("signedEnvelope.signatureBundle: invalid JSON.") from exc
    _digest(envelope["payloadDigest"], "signedEnvelope.payloadDigest")
    _digest(envelope["signatureBundleDigest"], "signedEnvelope.signatureBundleDigest")
    if envelope["signatureBundleDigest"] != _sha256(bundle):
        raise SystemExit("signedEnvelope.signatureBundleDigest: mismatch.")


def _validate_envelope_payload(
    envelope: dict[str, Any], record: dict[str, Any]
) -> None:
    payload = _object(envelope["payload"], "signedEnvelope.payload")
    fields = {
        "evidenceDigest", "bplDigest", "manifestDigest", "lockDigest",
        "bundleDigest", "policyDigests", "cvDigests", "sbomDigest",
        "coverageDigest", "provenanceDigest",
    }
    _keys(payload, fields, "signedEnvelope.payload")
    for field in fields - {"policyDigests", "cvDigests"}:
        _digest(payload[field], f"signedEnvelope.payload.{field}")
    for field in ("policyDigests", "cvDigests"):
        values = _texts(payload[field], f"signedEnvelope.payload.{field}", 32)
        for index, item in enumerate(values):
            _digest(item, f"signedEnvelope.payload.{field}[{index}]")
    _text(envelope["verifier"], "signedEnvelope.verifier")
    _timestamp(envelope["signedAt"], "signedEnvelope.signedAt")
    if envelope["payloadDigest"] != _sha256(_canonical(payload)):
        raise SystemExit("signedEnvelope.payloadDigest: mismatch.")
    unsigned = {key: item for key, item in record.items() if key != "signedEnvelope"}
    if payload["evidenceDigest"] != _sha256(_canonical(unsigned)):
        raise SystemExit("signedEnvelope evidence binding does not match.")
    if "bpl" not in record or payload["bplDigest"] != _sha256(_canonical(record["bpl"])):
        raise SystemExit("signedEnvelope BPL binding does not match.")


def _validate_signed_envelope(value: Any, record: dict[str, Any]) -> None:
    envelope = _object(value, "signedEnvelope")
    required = {
        "schemaVersion", "mediaType", "payload", "payloadDigest", "proofMode",
        "publicKeyPem", "signatureBundle", "signatureBundleDigest", "verifier",
        "signedAt",
    }
    _keys(envelope, required, "signedEnvelope")
    if envelope["schemaVersion"] != 1:
        raise SystemExit("signedEnvelope.schemaVersion: expected 1.")
    if envelope["mediaType"] != "application/vnd.ckodex.signed-evidence+json":
        raise SystemExit("signedEnvelope.mediaType: invalid.")
    if envelope["proofMode"] != "offline_key":
        raise SystemExit("signedEnvelope.proofMode: external proof is not accepted here.")
    _validate_signature_material(envelope)
    _validate_envelope_payload(envelope, record)


def _validate_model_trace(payload: dict[str, Any], action: dict[str, Any]) -> None:
    _keys(
        payload,
        {"traceId", "actionId", "policyId", "verdict", "reasons", "timestamp"},
        "receipt.trace",
        {"providerId", "modelId", "transport"},
    )
    for field in ("traceId", "actionId", "policyId"):
        _text(payload[field], f"receipt.trace.{field}")
    if payload["actionId"] != action["id"]:
        raise SystemExit("receipt.trace.actionId: does not bind the action envelope.")
    if payload["verdict"] not in {"allow", "deny"}:
        raise SystemExit("receipt.trace.verdict: invalid gate verdict.")
    if not _texts(payload["reasons"], "receipt.trace.reasons", 128):
        raise SystemExit("receipt.trace.reasons: expected at least one reason.")
    _timestamp(payload["timestamp"], "receipt.trace.timestamp")
    for field in ("providerId", "modelId"):
        if field in payload:
            _text(payload[field], f"receipt.trace.{field}")
    if "transport" in payload and payload["transport"] not in {
        "local_process",
        "local_http",
        "private_http",
        "private_grpc",
        "hosted_api",
    }:
        raise SystemExit("receipt.trace.transport: invalid model transport.")


def _validate_sandbox_execution(payload: dict[str, Any]) -> None:
    _keys(
        payload,
        {
            "executionId",
            "policyId",
            "verdict",
            "reasons",
            "engineId",
            "specDigest",
            "commandDigest",
            "startedAt",
            "completedAt",
            "cleanup",
        },
        "receipt.execution",
        {"result", "error"},
    )
    for field in ("executionId", "policyId", "engineId"):
        _text(payload[field], f"receipt.execution.{field}")
    if payload["verdict"] not in {"allow", "deny"}:
        raise SystemExit("receipt.execution.verdict: invalid gate verdict.")
    if not _texts(payload["reasons"], "receipt.execution.reasons", 128):
        raise SystemExit("receipt.execution.reasons: expected at least one reason.")
    for field in ("specDigest", "commandDigest"):
        _digest(payload[field], f"receipt.execution.{field}")
    started = _timestamp(payload["startedAt"], "receipt.execution.startedAt")
    completed = _timestamp(payload["completedAt"], "receipt.execution.completedAt")
    if datetime.fromisoformat(completed.replace("Z", "+00:00")) < datetime.fromisoformat(
        started.replace("Z", "+00:00")
    ):
        raise SystemExit("receipt.execution.completedAt: must not precede startedAt.")
    if payload["cleanup"] not in {"not_started", "complete", "failed"}:
        raise SystemExit("receipt.execution.cleanup: invalid cleanup state.")
    if "error" in payload:
        _text(payload["error"], "receipt.execution.error")
    if "result" in payload:
        _validate_sandbox_result(payload["result"])


def _validate_sandbox_result(value: Any) -> None:
    result = _object(value, "receipt.execution.result")
    fields = {
        "exitCode",
        "termination",
        "durationMillis",
        "stdoutDigest",
        "stderrDigest",
        "outputDigest",
    }
    _keys(result, fields, "receipt.execution.result")
    if isinstance(result["exitCode"], bool) or not isinstance(result["exitCode"], int):
        raise SystemExit("receipt.execution.result.exitCode: expected an integer.")
    if result["termination"] not in {"exited", "canceled", "timed_out"}:
        raise SystemExit("receipt.execution.result.termination: invalid termination.")
    _number(result["durationMillis"], "receipt.execution.result.durationMillis")
    for field in ("stdoutDigest", "stderrDigest", "outputDigest"):
        _digest(result[field], f"receipt.execution.result.{field}")


def _validate_receipt(record: dict[str, Any], action: dict[str, Any]) -> str:
    kind = record["kind"]
    if kind not in KINDS:
        raise SystemExit("kind: unsupported governance evidence kind.")
    receipt = _object(record["receipt"], "receipt")
    _keys(receipt, {"mediaType", "digest"}, "receipt", {"trace", "execution"})
    media_type = _text(receipt["mediaType"], "receipt.mediaType", 256)
    if media_type != KINDS[kind]:
        raise SystemExit("receipt.mediaType: does not match evidence kind.")
    _digest(receipt["digest"], "receipt.digest")
    payload_field = "trace" if kind == "model_decision" else "execution"
    if payload_field not in receipt or len(receipt) != 3:
        raise SystemExit(f"receipt: expected exactly one {payload_field} payload.")
    payload = _object(receipt[payload_field], f"receipt.{payload_field}")
    if kind == "model_decision":
        _validate_model_trace(payload, action)
    else:
        _validate_sandbox_execution(payload)
    source_payload = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    if receipt["digest"] != _sha256(source_payload):
        raise SystemExit("receipt.digest: does not verify the receipt payload.")
    expected_record_id = (
        f"model:{_text(payload.get('traceId'), 'receipt.trace.traceId')}"
        if kind == "model_decision"
        else f"sandbox:{_text(payload.get('executionId'), 'receipt.execution.executionId')}"
    )
    if record["recordId"] != expected_record_id:
        raise SystemExit("recordId: does not bind the receipt identity.")
    return media_type


def validate_record(
    raw: str, current_time: str
) -> tuple[dict[str, Any], str, str, str]:
    if len(raw.encode("utf-8")) > MAX_RECORD_BYTES:
        raise SystemExit("Governance evidence exceeds the 256 KiB limit.")
    try:
        record = json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (json.JSONDecodeError, ValueError) as exc:
        raise SystemExit("Governance evidence must be strict JSON.") from exc
    record = _object(record, "record")
    _keys(
        record,
        {"schemaVersion", "recordId", "kind", "action", "receipt"},
        "record",
        {"bpl", "signedEnvelope"},
    )
    if record["schemaVersion"] != 1:
        raise SystemExit("schemaVersion: expected 1.")
    record_id = _text(record["recordId"], "recordId", 263)
    if RECORD_ID.fullmatch(record_id) is None:
        raise SystemExit("recordId: invalid stable evidence identifier.")
    current = datetime.fromisoformat(
        _timestamp(current_time, "current_time").replace("Z", "+00:00")
    )
    action = validate_action(record["action"], current)
    media_type = _validate_receipt(record, action)
    if action["evidence"]["backPropRequired"]:
        if "bpl" not in record:
            raise SystemExit("Promotion-critical governance evidence requires BPL.")
        if action["data"]["retention"] not in {"regulated", "legal_hold"}:
            raise SystemExit("Promotion-critical governance evidence requires regulated retention.")
    if "bpl" in record:
        _validate_bpl(record["bpl"], action)
    if action["evidence"]["backPropRequired"] and "signedEnvelope" not in record:
        raise SystemExit("Promotion-critical governance evidence requires a signed envelope.")
    if "signedEnvelope" in record:
        _validate_signed_envelope(record["signedEnvelope"], record)
    _reject_sensitive(record)
    canonical = _canonical(record)
    return record, media_type, canonical, _sha256(canonical)


def canonical(value: Any) -> str:
    return _canonical(value)


def sha256(value: str) -> str:
    return _sha256(value)


def record_id(value: Any, context: str) -> str:
    evidence_id = _text(value, context, 263)
    if RECORD_ID.fullmatch(evidence_id) is None:
        raise SystemExit(f"{context}: invalid stable evidence identifier.")
    return evidence_id
