"""Finding-section rendering for the canonical report projection."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Keep direct helper imports valid under Python isolated mode.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from report_projection_support import (
    _bullets,
    _cell,
    _code_evidence_lines,
    _locations,
    _root_cause_code_evidence,
    _section_code_evidence,
    _strings,
    _text,
)

def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _finding_heading(number: int, finding: dict[str, Any]) -> list[str]:
    severity = finding["severity"]
    cwes = ", ".join(finding["taxonomy"]["cwe"]) or "none"
    title = _text(finding["title"], "Untitled finding")
    return [
        f'<a id="finding-{number}"></a>',
        "",
        f"### [{number}] {title}",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Severity | {_cell(severity['level'])} |",
        f"| Confidence | {_cell(finding['confidence']['level'])} |",
        f"| Confidence rationale | {_cell(finding['confidence']['rationale'])} |",
        f"| Category | {_cell(finding['taxonomy']['category'])} |",
        f"| CWE | {_cell(cwes)} |",
        f"| Affected lines | {_cell(_locations(finding))} |",
        "",
        "#### Summary",
        "",
        _text(finding["summary"], "No canonical finding summary was recorded."),
    ]


def _append_validation(
    lines: list[str],
    finding: dict[str, Any],
    validation: dict[str, Any],
    root_cause: dict[str, Any],
) -> None:
    raw_root_cause = finding.get("rootCause")
    validation_summary = _text(
        validation.get("summary"),
        f"{finding['confidence']['rationale']} Validation details were not recorded separately.",
    )
    validation_evidence = _strings(validation.get("evidence"))
    validation_counterevidence = _strings(validation.get("counterEvidence"))
    root_cause_summary = _text(
        raw_root_cause if isinstance(raw_root_cause, str) else root_cause.get("summary"),
        "",
    )
    root_cause_code_evidence = _root_cause_code_evidence(finding, root_cause)
    validation_code_evidence = _section_code_evidence(finding, validation)
    if root_cause_summary or root_cause_code_evidence:
        lines.extend(["", "#### Root Cause", ""])
        if root_cause_summary:
            lines.append(root_cause_summary)
        lines.extend(_code_evidence_lines(root_cause_code_evidence))
    lines.extend(["", "#### Validation", "", validation_summary])
    if validation.get("method"):
        lines.extend(["", f"Validation method: {_text(validation['method'], 'not recorded')}"])
    lines.extend(_code_evidence_lines(validation_code_evidence))
    if validation_evidence:
        lines.extend(["", "Evidence:", *_bullets(validation_evidence, "No evidence recorded.")])
    if validation_counterevidence:
        lines.extend(
            [
                "",
                "Counterevidence and remaining uncertainty:",
                *_bullets(validation_counterevidence, "None recorded."),
            ]
        )


def _append_attack_path(
    lines: list[str],
    finding: dict[str, Any],
    attack_path: dict[str, Any],
) -> None:
    dataflow = _mapping(attack_path.get("dataflow"))
    reachability = _mapping(attack_path.get("reachability"))
    dataflow_summary = _text(
        dataflow.get("summary"),
        f"The canonical finding records the affected path at {_locations(finding)}, but no expanded source-to-sink narrative was recorded.",
    )
    reachability_summary = _text(
        reachability.get("summary"),
        "Reachability was not recorded beyond the canonical finding summary and affected locations.",
    )
    lines.extend(["", "#### Dataflow", "", dataflow_summary])
    for label, key in (("Source", "source"), ("Sink", "sink"), ("Outcome", "outcome")):
        if dataflow.get(key):
            lines.extend(["", f"- **{label}:** {_text(dataflow[key], 'not recorded')}"])
    transformations = _strings(dataflow.get("transformations"))
    if transformations:
        lines.extend(["", "Transformations:", *_bullets(transformations, "None recorded.")])
    lines.extend(_code_evidence_lines(_section_code_evidence(finding, attack_path)))
    lines.extend(["", "#### Reachability", "", reachability_summary])
    for label, key in (
        ("Attacker", "attacker"),
        ("Entry point", "entrypoint"),
        ("Outcome", "outcome"),
    ):
        if reachability.get(key):
            lines.extend(["", f"- **{label}:** {_text(reachability[key], 'not recorded')}"])
    preconditions = _strings(reachability.get("preconditions"))
    if preconditions:
        lines.extend(["", "Preconditions:", *_bullets(preconditions, "None recorded.")])


def _append_remediation(lines: list[str], finding: dict[str, Any]) -> None:
    severity = finding["severity"]
    severity_rationale = _text(
        severity.get("rationale"),
        f"The scan assigned {severity['level']} severity; no separate canonical severity rationale was recorded.",
    )
    severity_change = _text(
        severity.get("changeConditions"),
        "Additional runtime or deployment evidence could raise or lower this severity.",
    )
    lines.extend(
        [
            "",
            "#### Severity",
            "",
            f"**{severity['level'].capitalize()}** — {severity_rationale}",
            "",
            severity_change,
            "",
            "#### Remediation",
            "",
            _text(finding["remediation"], "No canonical remediation was recorded."),
        ]
    )
    remediation_tests = _strings(finding.get("remediationTests"))
    preventive_controls = _strings(finding.get("preventiveControls"))
    if remediation_tests:
        lines.extend(["", "Tests:", *_bullets(remediation_tests, "No tests recorded.")])
    if preventive_controls:
        lines.extend(["", "Preventive controls:", *_bullets(preventive_controls, "None recorded.")])


def _finding_section(number: int, finding: dict[str, Any]) -> list[str]:
    validation = _mapping(finding.get("validation"))
    root_cause = _mapping(finding.get("rootCause"))
    attack_path = _mapping(finding.get("attackPath"))
    lines = _finding_heading(number, finding)
    _append_validation(lines, finding, validation, root_cause)
    _append_attack_path(lines, finding, attack_path)
    _append_remediation(lines, finding)
    return lines


def _linked_finding_section(number: int, finding: dict[str, Any], report_path: str) -> list[str]:
    cwes = ", ".join(finding["taxonomy"]["cwe"]) or "none"
    title = _text(finding["title"], "Untitled finding")
    link = f"[detailed technical write-up]({report_path})"
    lines = [
        f'<a id="finding-{number}"></a>',
        "",
        f"### [{number}] {title}",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Severity | {_cell(finding['severity']['level'])} |",
        f"| Confidence | {_cell(finding['confidence']['level'])} |",
        f"| Confidence rationale | {_cell(finding['confidence']['rationale'])} |",
        f"| Category | {_cell(finding['taxonomy']['category'])} |",
        f"| CWE | {_cell(cwes)} |",
        f"| Affected lines | {_cell(_locations(finding))} |",
    ]
    for heading in ("Summary", "Validation", "Dataflow", "Reachability", "Severity", "Remediation"):
        lines.extend(["", f"#### {heading}", "", f"See the {link}."])
    return lines

