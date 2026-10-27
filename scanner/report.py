"""Turn a list of findings into a report: JSON, a human summary, and an exit code."""
from __future__ import annotations

import json

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "none": 0}
_COLOR = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "none": "\033[32m"}
_RESET = "\033[0m"


def summarize(findings: list) -> dict:
    counts = {"high": 0, "medium": 0, "low": 0, "none": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def to_json(target: str, findings: list, extra: dict | None = None) -> str:
    payload = {
        "target": target,
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
    }
    if extra:
        payload.update(extra)
    return json.dumps(payload, indent=2, ensure_ascii=False)


def to_text(target: str, findings: list, color: bool = True) -> str:
    lines = [f"API Security Scanner — results for {target}", "=" * 60]
    ordered = sorted(findings, key=lambda f: -SEVERITY_ORDER.get(f.severity, 0))
    for f in ordered:
        tag = f.severity.upper()
        if color and f.severity in _COLOR:
            tag = f"{_COLOR[f.severity]}{tag}{_RESET}"
        lines.append(f"[{tag}] {f.title}  ({f.check} · {f.owasp} · confidence: {f.confidence})")
        lines.append(f"    {f.detail}")
        if f.severity != "none":
            lines.append(f"    Fix: {f.fix}")
        for ev in f.evidence:
            lines.append(f"      - {ev}")
        lines.append("")
    c = summarize(findings)
    lines.append("-" * 60)
    lines.append(f"Summary: {c['high']} high, {c['medium']} medium, "
                 f"{c['low']} low, {c['none']} ok")
    return "\n".join(lines)


def exit_code(findings: list, fail_on: str = "high") -> int:
    """0 = pass. 1 = at least one finding at or above fail_on severity."""
    threshold = SEVERITY_ORDER.get(fail_on, 3)
    worst = max((SEVERITY_ORDER.get(f.severity, 0) for f in findings), default=0)
    return 1 if worst >= threshold else 0
