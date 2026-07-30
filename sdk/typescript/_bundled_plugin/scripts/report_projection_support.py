#!/usr/bin/env python3
"""Shared deterministic helpers for report projection."""

from __future__ import annotations

import argparse
import importlib.util
import re
from collections import Counter
from pathlib import Path
from types import ModuleType
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}
REPORTABLE_SEVERITIES = {"critical", "high", "medium", "low"}
DISPOSITION_LABELS = {
    "reported": "Reported",
    "no_issue_found": "No issue found",
    "rejected": "Rejected",
    "not_applicable": "Not applicable",
    "needs_follow_up": "Needs follow-up",
}
WRITEUP_REPORT_PATH_RE = re.compile(r"^findings/([a-z0-9][a-z0-9._-]*)/\1\.md$")


class ReportProjectionError(ValueError):
    """Raised when a canonical scan cannot be projected into a valid report."""


def _load_script(name: str) -> ModuleType:
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"codex_security_{name}", path)
    if spec is None or spec.loader is None:
        raise ReportProjectionError(f"could not load report helper: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _text(value: Any, fallback: str) -> str:
    candidate = value if isinstance(value, str) and value.strip() else fallback
    normalized = " ".join(candidate.split())
    if not normalized:
        return ""
    if re.match(r"^(?:#{1,6}\s|[-*+]\s|>\s|```|\d+\.\s|\|)", normalized):
        normalized = f"Text: {normalized}"
    rendered: list[str] = []
    cursor = 0
    for match in re.finditer(r"(?<!`)`([^`\n]+)`(?!`)", normalized):
        rendered.append(_escape_markdown_text(normalized[cursor : match.start()]))
        rendered.append(f"`{match.group(1)}`")
        cursor = match.end()
    rendered.append(_escape_markdown_text(normalized[cursor:]))
    return "".join(rendered)


def _escape_markdown_text(value: str) -> str:
    return re.sub(r"([\\`*\[\]<>])", r"\\\1", value)


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    normalized: list[str] = []
    for item in value:
        text = _text(item, "")
        if text:
            normalized.append(text)
    return normalized


def _cell(value: Any) -> str:
    return _text(value, "none").replace("|", "\\|").replace("\n", "<br>")


def _link_label(value: Any, fallback: str) -> str:
    return _cell(value) or _cell(fallback)


def _deep_report_id(finding: dict[str, Any]) -> str:
    extensions = finding.get("extensions")
    if isinstance(extensions, dict):
        report_id = extensions.get("reportId")
        if isinstance(report_id, str) and report_id.strip():
            return report_id
        ledger_row_id = extensions.get("ledgerRowId")
        if isinstance(ledger_row_id, str) and ledger_row_id.strip():
            return ledger_row_id
    identity = finding.get("identity")
    if isinstance(identity, dict):
        instance = identity.get("instance")
        if isinstance(instance, str) and instance.strip():
            return instance
    occurrence_id = finding.get("occurrenceId")
    return (
        occurrence_id
        if isinstance(occurrence_id, str) and occurrence_id.strip()
        else "Unidentified report"
    )


def _deep_candidate_id(finding: dict[str, Any]) -> str:
    extensions = finding.get("extensions")
    if isinstance(extensions, dict):
        candidate_id = extensions.get("candidateId")
        if isinstance(candidate_id, str) and candidate_id.strip():
            return candidate_id
    return _deep_report_id(finding)


def _has_deep_child_metadata(finding: dict[str, Any]) -> bool:
    extensions = finding.get("extensions")
    if not isinstance(extensions, dict):
        return False
    return any(
        isinstance(extensions.get(field), str) and extensions[field].strip()
        for field in ("candidateId", "reportId")
    )


def _uses_deep_presentation(coverage: dict[str, Any], findings: list[dict[str, Any]]) -> bool:
    if coverage.get("mode") == "deep_repository":
        return True
    if coverage.get("mode") != "scoped_path":
        return False
    # Scoped deep scans can arrive as scoped_path artifacts. The child ids are
    # the stable deep-scan signal; ordinary scoped scans do not emit them.
    return any(_has_deep_child_metadata(finding) for finding in findings)


def _deep_title_parts(finding: dict[str, Any]) -> tuple[str, str | None]:
    title = finding.get("title")
    if not isinstance(title, str):
        return "Untitled finding", None
    normalized = " ".join(title.split())
    match = re.fullmatch(r"(.+?)\s+\[([^\[\]\n]+)\]", normalized)
    if match is None:
        return normalized, None
    annotation = match.group(2)
    extensions = finding.get("extensions")
    recognized_ids = [_deep_report_id(finding)]
    if isinstance(extensions, dict):
        ledger_row_id = extensions.get("ledgerRowId")
        if isinstance(ledger_row_id, str) and ledger_row_id.strip():
            recognized_ids.append(ledger_row_id)
    if any(
        annotation == report_id or annotation.startswith(f"{report_id};")
        for report_id in recognized_ids
    ):
        return match.group(1), annotation
    return normalized, None


def _deep_finding_title(finding: dict[str, Any]) -> str:
    return _deep_title_parts(finding)[0]


def _deep_finding_groups(
    findings: list[dict[str, Any]], writeup_paths: list[str | None]
) -> list[list[tuple[int, dict[str, Any], str | None]]]:
    groups: dict[str, list[tuple[int, dict[str, Any], str | None]]] = {}
    for number, (finding, report_path) in enumerate(zip(findings, writeup_paths, strict=True), 1):
        groups.setdefault(_deep_candidate_id(finding), []).append((number, finding, report_path))
    return list(groups.values())


def _deep_group_titles(group: list[tuple[int, dict[str, Any], str | None]]) -> str:
    titles: list[str] = []
    for _, finding, _ in group:
        title = _cell(_deep_finding_title(finding))
        if title not in titles:
            titles.append(title)
    return "<br>".join(titles)


def _deep_group_levels(
    group: list[tuple[int, dict[str, Any], str | None]],
    field: str,
    order: dict[str, int],
) -> str:
    levels = {finding[field]["level"] for _, finding, _ in group}
    return "<br>".join(sorted(levels, key=lambda level: order.get(level, len(order))))


def _deep_group_report_labels(
    group: list[tuple[int, dict[str, Any], str | None]],
) -> list[str]:
    report_ids = [_deep_report_id(finding) for _, finding, _ in group]
    report_id_counts = Counter(report_ids)
    labels = [
        (_deep_title_parts(finding)[1] if report_id_counts[report_id] > 1 else report_id)
        or report_id
        for report_id, (_, finding, _) in zip(report_ids, group, strict=True)
    ]
    label_counts = Counter(labels)
    return [
        (
            finding.get("identity", {}).get("instance")
            if label_counts[label] > 1 and isinstance(finding.get("identity"), dict)
            else label
        )
        or _deep_report_id(finding)
        for label, (_, finding, _) in zip(labels, group, strict=True)
    ]


def _deep_group_report_links(group: list[tuple[int, dict[str, Any], str | None]]) -> str:
    labels = _deep_group_report_labels(group)
    return "<br>".join(
        f"[{_link_label(label, 'Unidentified report')}](#finding-{number})"
        for label, (number, _, _) in zip(labels, group, strict=True)
    )


def _deep_group_writeup_links(group: list[tuple[int, dict[str, Any], str | None]]) -> str:
    labels = _deep_group_report_labels(group)
    links: list[str] = []
    for label, (_, _, report_path) in zip(labels, group, strict=True):
        report_id = _link_label(label, "Unidentified report")
        links.append(
            f"[Open {report_id}]({report_path})" if report_path else f"{report_id}: inline below"
        )
    return "<br>".join(links)


def _writeup_report_path(finding: dict[str, Any]) -> str | None:
    writeup = finding.get("writeup")
    if writeup is None:
        return None
    if not isinstance(writeup, dict):
        raise ReportProjectionError("finding writeup must be an object")
    report_path = writeup.get("reportPath")
    if not isinstance(report_path, str) or not WRITEUP_REPORT_PATH_RE.fullmatch(report_path):
        raise ReportProjectionError("finding writeup has an invalid reportPath")
    return report_path


def _hardening_portfolio_path(scan: dict[str, Any]) -> str | None:
    hardening = scan.get("hardening")
    if hardening is None:
        return None
    if not isinstance(hardening, dict):
        raise ReportProjectionError("scan hardening must be an object")
    portfolio_path = hardening.get("portfolioPath")
    if portfolio_path != "hardening/hardening.md":
        raise ReportProjectionError("scan hardening has an invalid portfolioPath")
    return portfolio_path


def _bullets(items: list[str], fallback: str) -> list[str]:
    return [f"- {item}" for item in (items or [fallback])]


def _code_evidence_catalog(finding: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = finding.get("codeEvidence", finding.get("code_evidence", []))
    if not isinstance(raw, list):
        return {}
    return {
        item["id"]: item
        for item in raw
        if isinstance(item, dict)
        and isinstance(item.get("id"), str)
        and isinstance(item.get("code"), str)
        and item["code"].strip()
    }


def _section_code_evidence(
    finding: dict[str, Any], section: dict[str, Any]
) -> list[dict[str, Any]]:
    catalog = _code_evidence_catalog(finding)
    refs = section.get("evidenceRefs", section.get("evidence_refs", []))
    resolved = (
        [catalog[ref] for ref in refs if isinstance(ref, str) and ref in catalog]
        if isinstance(refs, list)
        else []
    )
    embedded = section.get("codeEvidence", section.get("code_evidence", []))
    if isinstance(embedded, list):
        resolved.extend(
            item
            for item in embedded
            if isinstance(item, dict) and isinstance(item.get("code"), str) and item["code"].strip()
        )
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in resolved:
        key = (str(item.get("id", "")), item["code"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _root_cause_code_evidence(
    finding: dict[str, Any], root_cause: dict[str, Any]
) -> list[dict[str, Any]]:
    evidence = _section_code_evidence(finding, root_cause)
    legacy_code = root_cause.get("code")
    if not isinstance(legacy_code, str) or not legacy_code.strip():
        return evidence
    if any(item["code"] == legacy_code for item in evidence):
        return evidence
    root_location = next(
        (
            location
            for location in finding.get("locations", [])
            if isinstance(location, dict) and location.get("role") == "root_control"
        ),
        {},
    )
    return [
        *evidence,
        {
            "code": legacy_code,
            "label": "Broken control",
            "language": root_cause.get("language", ""),
            "location": root_location,
        },
    ]


def _code_evidence_location(item: dict[str, Any]) -> str:
    location = item.get("location")
    if isinstance(location, str):
        return location
    if isinstance(location, dict):
        item = location
    path = item.get("path")
    start = item.get("startLine")
    end = item.get("endLine", start)
    if not isinstance(path, str) or not path:
        return ""
    if not isinstance(start, int):
        return path
    return f"{path}:{start}" if end == start else f"{path}:{start}-{end}"


def _code_fence(code: str) -> str:
    longest_run = max((len(match.group(0)) for match in re.finditer(r"`+", code)), default=0)
    return "`" * max(3, longest_run + 1)


def _code_evidence_lines(evidence: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for index, item in enumerate(evidence):
        label = _text(item.get("label"), f"Code evidence {index + 1}")
        location = _text(_code_evidence_location(item), "")
        explanation = _text(item.get("explanation"), "")
        language = item.get("language") if isinstance(item.get("language"), str) else ""
        language = language if re.fullmatch(r"[A-Za-z0-9_+.-]*", language) else ""
        code = item["code"]
        fence = _code_fence(code)
        heading = f"**{label}**"
        if location:
            heading += f" — `{location}`"
        lines.extend(["", heading])
        if explanation:
            lines.extend(["", explanation])
        lines.extend(["", f"{fence}{language}", code, fence])
    return lines


def _severity_mix(findings: list[dict[str, Any]]) -> str:
    counts = Counter(finding["severity"]["level"] for finding in findings)
    return (
        ", ".join(f"{level}: {counts[level]}" for level in SEVERITY_ORDER if counts[level])
        or "none"
    )


def _confidence_mix(findings: list[dict[str, Any]]) -> str:
    counts = Counter(finding["confidence"]["level"] for finding in findings)
    return (
        ", ".join(
            f"{level}: {counts[level]}" for level in ("high", "medium", "low") if counts[level]
        )
        or "none"
    )


def _locations(finding: dict[str, Any]) -> str:
    rendered = []
    for location in finding["locations"]:
        start = location["startLine"]
        end = location.get("endLine", start)
        suffix = f":{start}" if end == start else f":{start}-{end}"
        rendered.append(f"{location['path']}{suffix}")
    return ", ".join(rendered)


def _finding_sort_key(finding: dict[str, Any]) -> tuple[int, str, str]:
    return (
        SEVERITY_ORDER.get(finding["severity"]["level"], len(SEVERITY_ORDER)),
        finding.get("occurrenceId", ""),
        finding["title"],
    )


def _target_scope_lines(target: dict[str, Any]) -> list[str]:
    lines = [
        f"- Target kind: {_text(target.get('kind'), 'not recorded')}",
        f"- Target ID: {_text(target.get('targetId'), 'not recorded')}",
    ]
    base_revision = _text(target.get("baseRevision"), "")
    head_revision = _text(target.get("headRevision"), "")
    if base_revision or head_revision:
        lines.append(
            f"- Revision range: {base_revision or 'unknown'}...{head_revision or 'unknown'}"
        )
    revision = _text(target.get("revision"), "")
    if revision:
        lines.append(f"- Revision: {revision}")
    snapshot_digest = _text(target.get("snapshotDigest"), "")
    if snapshot_digest:
        lines.append(f"- Snapshot digest: {snapshot_digest}")
    return lines


def _surface_notes(surface: dict[str, Any]) -> str:
    notes = surface.get("notes", "No additional canonical notes were recorded.")
    receipt_refs = surface.get("receiptRefs", [])
    if not isinstance(receipt_refs, list) or not receipt_refs:
        return _cell(notes)
    evidence = ", ".join(item for item in receipt_refs if isinstance(item, str))
    if not evidence:
        return _cell(notes)
    return _cell(f"{notes} Evidence: {evidence}")


