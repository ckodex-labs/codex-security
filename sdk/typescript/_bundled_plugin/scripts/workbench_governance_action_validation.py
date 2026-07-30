"""Validate CKODEX ActionEnvelope trust, context, and lease bindings."""

from __future__ import annotations

import math
import re
from datetime import datetime
from typing import Any

TEXT_LIMIT = 4096
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
ACTOR_KINDS = {"human", "machine", "agent", "service"}
BOUNDARIES = {
    "local",
    "shared",
    "bridge_only",
    "governance_visible",
    "sovereign_restricted",
    "retirement_archive",
}
LEASE_KINDS = {"context", "skill", "capability", "branch", "dependency", "snapshot"}
RETENTION = {"ephemeral", "standard", "regulated", "legal_hold"}


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
    missing = required - value.keys()
    extra = value.keys() - required - (optional or set())
    if missing:
        raise SystemExit(f"{context}: missing fields: {', '.join(sorted(missing))}.")
    if extra:
        raise SystemExit(f"{context}: unknown fields: {', '.join(sorted(extra))}.")


def _text(value: Any, context: str, limit: int = TEXT_LIMIT) -> str:
    invalid = (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > limit
        or any(ord(character) < 32 for character in value)
    )
    if invalid:
        raise SystemExit(f"{context}: expected bounded non-control text.")
    return value


def _digest(value: Any, context: str) -> str:
    text = _text(value, context, 71)
    if DIGEST.fullmatch(text) is None:
        raise SystemExit(f"{context}: expected a sha256 digest.")
    return text


def _number(value: Any, context: str) -> float:
    invalid = (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    )
    if invalid:
        raise SystemExit(f"{context}: expected a finite non-negative number.")
    return value


def _texts(value: Any, context: str, limit: int = 128) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise SystemExit(f"{context}: expected a bounded array.")
    return [_text(item, f"{context}[{index}]") for index, item in enumerate(value)]


def _instant(value: Any, context: str) -> datetime:
    text = _text(value, context, 64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemExit(f"{context}: expected an ISO 8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise SystemExit(f"{context}: timestamp must include a timezone.")
    return parsed


def _validate_actor(value: Any) -> None:
    actor = _object(value, "action.actor")
    _keys(actor, {"kind", "id", "dal"}, "action.actor")
    if actor["kind"] not in ACTOR_KINDS:
        raise SystemExit("action.actor.kind: invalid actor kind.")
    _text(actor["id"], "action.actor.id")
    if isinstance(actor["dal"], bool) or actor["dal"] not in range(5):
        raise SystemExit("action.actor.dal: expected an integer from 0 through 4.")


def _validate_coactors(value: Any) -> None:
    if not isinstance(value, list) or len(value) > 32:
        raise SystemExit("action.coactors: expected a bounded array.")
    for index, item in enumerate(value):
        context = f"action.coactors[{index}]"
        coactor = _object(item, context)
        _keys(coactor, {"kind", "id", "role", "guardrailProfile"}, context)
        if coactor["kind"] not in ACTOR_KINDS:
            raise SystemExit(f"{context}.kind: invalid actor kind.")
        if coactor["role"] not in {"reviewer", "verifier", "observer", "peer"}:
            raise SystemExit(f"{context}.role: invalid role.")
        _text(coactor["id"], f"{context}.id")
        _text(coactor["guardrailProfile"], f"{context}.guardrailProfile")


def _validate_scope(value: Any) -> None:
    scope = _object(value, "action.scope")
    fields = {"tenant", "environment", "workspace", "project", "boundaryClass"}
    _keys(scope, fields, "action.scope")
    for field in ("tenant", "environment", "workspace", "project"):
        _text(scope[field], f"action.scope.{field}")
    if scope["boundaryClass"] not in BOUNDARIES:
        raise SystemExit("action.scope.boundaryClass: invalid boundary class.")


def _validate_intent(value: Any) -> None:
    intent = _object(value, "action.intent")
    _keys(intent, {"statement", "qaIds", "risk", "blastRadius"}, "action.intent")
    _text(intent["statement"], "action.intent.statement")
    _texts(intent["qaIds"], "action.intent.qaIds", 128)
    if intent["risk"] not in {"low", "medium", "high", "critical"}:
        raise SystemExit("action.intent.risk: invalid risk.")
    radii = {"localized", "module", "service", "cross_service", "tenant"}
    if intent["blastRadius"] not in radii:
        raise SystemExit("action.intent.blastRadius: invalid blast radius.")


def _validate_budgets(value: Any) -> None:
    budgets = _object(value, "action.budgets")
    required = {
        "wallClockSeconds", "tokenMax", "egress", "costUsdMax", "fsWrites", "gas"
    }
    _keys(budgets, required, "action.budgets")
    for field in ("wallClockSeconds", "tokenMax", "costUsdMax", "fsWrites"):
        _number(budgets[field], f"action.budgets.{field}")
    if budgets["egress"] not in {"deny", "allow"}:
        raise SystemExit("action.budgets.egress: invalid egress policy.")
    gas = _object(budgets["gas"], "action.budgets.gas")
    fields = {"compute", "context", "tool", "network", "governance", "recovery"}
    _keys(gas, fields, "action.budgets.gas")
    for field in gas:
        _number(gas[field], f"action.budgets.gas.{field}")


def _validate_lease(value: Any, index: int, current: datetime) -> str:
    context = f"action.leases[{index}]"
    lease = _object(value, context)
    fields = {"kind", "ttl", "heartbeatDue", "revocableBy", "scope", "decayFn"}
    _keys(lease, fields, context)
    if lease["kind"] not in LEASE_KINDS:
        raise SystemExit(f"{context}.kind: invalid lease kind.")
    if lease["decayFn"] not in {"linear", "exp", "step"}:
        raise SystemExit(f"{context}.decayFn: invalid decay function.")
    duration = _text(lease["ttl"], f"{context}.ttl")
    if re.fullmatch(r"P(?!$)[A-Z0-9.]+", duration) is None:
        raise SystemExit(f"{context}.ttl: expected an ISO 8601 duration.")
    if _instant(lease["heartbeatDue"], f"{context}.heartbeatDue") <= current:
        raise SystemExit(f"{context}.heartbeatDue: lease heartbeat is overdue.")
    _text(lease["scope"], f"{context}.scope")
    if not _texts(lease["revocableBy"], f"{context}.revocableBy", 32):
        raise SystemExit(f"{context}.revocableBy: expected at least one actor.")
    return lease["kind"]


def _validate_leases(value: Any, current: datetime) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > 64:
        raise SystemExit("action.leases: expected a non-empty bounded array.")
    kinds = {_validate_lease(item, index, current) for index, item in enumerate(value)}
    if "capability" not in kinds:
        raise SystemExit("action.leases: a capability lease is required.")
    return value


def _validate_policy(value: Any) -> None:
    policy = _object(value, "action.policy")
    _keys(policy, {"bundleRef", "traceRequired"}, "action.policy")
    _text(policy["bundleRef"], "action.policy.bundleRef")
    if policy["traceRequired"] is not True:
        raise SystemExit("action.policy.traceRequired: expected true.")


def _validate_evidence(value: Any) -> None:
    evidence = _object(value, "action.evidence")
    fields = {"required", "onFailure", "backPropRequired"}
    _keys(evidence, fields, "action.evidence", {"bplDepth"})
    _texts(evidence["required"], "action.evidence.required", 128)
    if evidence["onFailure"] not in {"halt", "quarantine"}:
        raise SystemExit("action.evidence.onFailure: invalid failure policy.")
    if not isinstance(evidence["backPropRequired"], bool):
        raise SystemExit("action.evidence.backPropRequired: expected a boolean.")
    if "bplDepth" not in evidence:
        return
    depth = evidence["bplDepth"]
    if isinstance(depth, bool) or not isinstance(depth, int) or depth < 1:
        raise SystemExit("action.evidence.bplDepth: expected a positive integer.")


def _validate_data(value: Any) -> None:
    data = _object(value, "action.data")
    _keys(data, {"pii", "secrets", "retention"}, "action.data")
    if data["pii"] != "forbidden" or data["secrets"] != "forbidden":
        raise SystemExit("action.data: PII and secrets must be forbidden.")
    if data["retention"] not in RETENTION:
        raise SystemExit("action.data.retention: invalid retention class.")


def _validate_certificate(value: Any, current: datetime) -> None:
    certificate = _object(value, "action.context.certificate")
    fields = {
        "schemaVersion", "id", "sliceHash", "resolution", "justification",
        "layers", "issuedAt", "expiresAt",
    }
    _keys(certificate, fields, "action.context.certificate")
    if certificate["schemaVersion"] != 1:
        raise SystemExit("action.context.certificate.schemaVersion: expected 1.")
    _text(certificate["id"], "action.context.certificate.id")
    _digest(certificate["sliceHash"], "action.context.certificate.sliceHash")
    profiles = {"minimal", "compact", "standard", "deep", "forensic"}
    if certificate["resolution"] not in profiles:
        raise SystemExit("action.context.certificate.resolution: invalid profile.")
    _text(certificate["justification"], "action.context.certificate.justification")
    _texts(certificate["layers"], "action.context.certificate.layers", 32)
    issued = _instant(certificate["issuedAt"], "action.context.certificate.issuedAt")
    expires = _instant(certificate["expiresAt"], "action.context.certificate.expiresAt")
    if issued > current:
        raise SystemExit("action.context.certificate.issuedAt: cannot be in the future.")
    if expires <= issued:
        raise SystemExit("action.context.certificate.expiresAt: must follow issuedAt.")
    if expires <= current:
        raise SystemExit("action.context.certificate: certificate has expired.")


def _validate_context(value: Any, current: datetime) -> None:
    context = _object(value, "action.context")
    _keys(context, {"certificate"}, "action.context")
    _validate_certificate(context["certificate"], current)


def _validate_verification(value: Any, current: datetime) -> None:
    context = "action.capability.verification"
    verification = _object(value, context)
    fields = {"kind", "signatureDigest", "verifiedAt", "expiresAt", "verifier"}
    _keys(verification, fields, context)
    if verification["kind"] != "cosign":
        raise SystemExit(f"{context}.kind: expected cosign.")
    _digest(verification["signatureDigest"], f"{context}.signatureDigest")
    verified = _instant(verification["verifiedAt"], f"{context}.verifiedAt")
    expires = _instant(verification["expiresAt"], f"{context}.expiresAt")
    if verified > current:
        raise SystemExit(f"{context}.verifiedAt: cannot be in the future.")
    if expires <= verified:
        raise SystemExit(f"{context}.expiresAt: must follow verifiedAt.")
    if expires <= current:
        raise SystemExit(f"{context}: trust record has expired.")
    _text(verification["verifier"], f"{context}.verifier")


def _validate_capability(value: Any, leases: list[dict[str, Any]], current: datetime) -> None:
    capability = _object(value, "action.capability")
    fields = {"schemaVersion", "lockDigest", "bundleRef", "verification"}
    _keys(capability, fields, "action.capability")
    if capability["schemaVersion"] != 1:
        raise SystemExit("action.capability.schemaVersion: expected 1.")
    _digest(capability["lockDigest"], "action.capability.lockDigest")
    _text(capability["bundleRef"], "action.capability.bundleRef")
    _validate_verification(capability["verification"], current)
    scopes = [lease["scope"] for lease in leases if lease["kind"] == "capability"]
    if scopes != [capability["bundleRef"]]:
        raise SystemExit("action.leases: capability lease must bind the lock bundle.")


def validate_action(value: Any, current: datetime) -> dict[str, Any]:
    action = _object(value, "action")
    fields = {
        "schemaVersion", "id", "actor", "coactors", "scope", "intent", "budgets",
        "leases", "policy", "evidence", "data", "context", "capability",
    }
    _keys(action, fields, "action")
    if action["schemaVersion"] != 1:
        raise SystemExit("action.schemaVersion: expected 1.")
    _text(action["id"], "action.id")
    _validate_actor(action["actor"])
    _validate_coactors(action["coactors"])
    _validate_scope(action["scope"])
    _validate_intent(action["intent"])
    _validate_budgets(action["budgets"])
    leases = _validate_leases(action["leases"], current)
    _validate_policy(action["policy"])
    _validate_evidence(action["evidence"])
    _validate_data(action["data"])
    _validate_context(action["context"], current)
    _validate_capability(action["capability"], leases, current)
    return action
