"""Render lockdrift findings as text, JSON, and SARIF reports."""

from __future__ import annotations

import json
from typing import Any, Iterable, List, Optional

try:
    from .diff import Finding
except Exception:  # pragma: no cover
    try:
        from lockdrift.diff import Finding  # type: ignore
    except Exception:
        Finding = None  # type: ignore

_SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2, "note": 3}


def _normalize_findings(findings: Any) -> List[Any]:
    if findings is None:
        return []
    if hasattr(findings, "findings"):
        findings = findings.findings
    if isinstance(findings, dict):
        if "findings" in findings:
            findings = findings["findings"]
        else:
            findings = list(findings.values())
    if isinstance(findings, (list, tuple)):
        return list(findings)
    try:
        return list(findings)
    except Exception:
        return [findings]


def _to_dict(finding: Any) -> dict:
    if hasattr(finding, "to_dict"):
        try:
            return finding.to_dict()
        except Exception:
            pass
    if isinstance(finding, dict):
        return dict(finding)
    result = {}
    for key in ("id", "severity", "kind", "ecosystem", "package", "message", "details", "code", "type", "name"):
        value = getattr(finding, key, None)
        if value is not None:
            result[key] = value
    if "details" not in result:
        result["details"] = {}
    if "id" not in result:
        result["id"] = "FINDING"
    if "severity" not in result:
        result["severity"] = "warning"
    if "kind" not in result:
        result["kind"] = result.get("id", "finding").lower().replace("_", "-")
    if "ecosystem" not in result:
        result["ecosystem"] = "python"
    if "package" not in result:
        result["package"] = result.get("name", "")
    if "message" not in result:
        result["message"] = ""
    return result


def findings_to_dicts(findings: Any) -> List[dict]:
    return [_to_dict(f) for f in _normalize_findings(findings)]


def render_json(findings: Any, indent: int = 2, **_kwargs: Any) -> str:
    """Render findings as a JSON string."""
    data = findings_to_dicts(findings)
    return json.dumps(data, indent=indent, default=str)


def render_text(
    findings: Any,
    title: str = "lockdrift report",
    group_by: str = "severity",
    **_kwargs: Any,
) -> str:
    """Render findings as human-readable terminal text."""
    items = findings_to_dicts(findings)
    if not items:
        return f"{title}: no findings.\n"
    lines = [title, "=" * len(title)]
    # Group by severity.
    groups: dict = {}
    for item in items:
        key = item.get(group_by, item.get("severity", "warning"))
        groups.setdefault(key, []).append(item)
    for severity in sorted(groups, key=lambda x: _SEVERITY_ORDER.get(str(x), 9)):
        lines.append(f"\n[{severity}] ({len(groups[severity])})")
        for item in groups[severity]:
            pkg = item.get("package") or item.get("name") or ""
            eco = item.get("ecosystem", "")
            kind = item.get("kind") or item.get("type") or ""
            fid = item.get("id") or item.get("code") or ""
            msg = item.get("message", "")
            lines.append(f"  - {fid} {pkg} ({eco}/{kind}): {msg}")
    lines.append(f"\nTotal: {len(items)} finding(s).")
    return "\n".join(lines) + "\n"


def render_sarif(
    findings: Any,
    tool_name: str = "lockdrift",
    tool_version: str = "0.1.0",
    **_kwargs: Any,
) -> dict:
    """Render findings as a SARIF 2.1.0 document."""
    items = findings_to_dicts(findings)
    results = []
    rules = {}
    for item in items:
        fid = item.get("id") or "FINDING"
        level = item.get("severity", "warning")
        sarif_level = {"error": "error", "warning": "warning", "info": "note", "note": "note"}.get(level, "warning")
        if fid not in rules:
            rules[fid] = {
                "id": fid,
                "shortDescription": {"text": fid.replace("_", " ").title()},
            }
        results.append(
            {
                "ruleId": fid,
                "level": sarif_level,
                "message": {"text": item.get("message", "")},
                "properties": {
                    "ecosystem": item.get("ecosystem"),
                    "package": item.get("package"),
                    "kind": item.get("kind"),
                },
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def render_sarif_json(findings: Any, indent: int = 2, **kwargs: Any) -> str:
    return json.dumps(render_sarif(findings, **kwargs), indent=indent, default=str)


# Aliases.
def format_json(findings: Any, **kwargs: Any) -> str:
    return render_json(findings, **kwargs)


def format_text(findings: Any, **kwargs: Any) -> str:
    return render_text(findings, **kwargs)


def format_sarif(findings: Any, **kwargs: Any) -> Any:
    return render_sarif(findings, **kwargs)


def as_json(findings: Any, **kwargs: Any) -> str:
    return render_json(findings, **kwargs)


def as_text(findings: Any, **kwargs: Any) -> str:
    return render_text(findings, **kwargs)


def as_sarif(findings: Any, **kwargs: Any) -> Any:
    return render_sarif(findings, **kwargs)


def render(findings: Any, format: str = "text", **kwargs: Any) -> Any:  # noqa: A002
    fmt = format.lower()
    if fmt == "json":
        return render_json(findings, **kwargs)
    if fmt in {"sarif"}:
        return render_sarif(findings, **kwargs)
    return render_text(findings, **kwargs)


def render_report(findings: Any, **kwargs: Any) -> str:
    return render_text(findings, **kwargs)


__all__ = [
    "findings_to_dicts",
    "render_json",
    "render_text",
    "render_sarif",
    "render_sarif_json",
    "format_json",
    "format_text",
    "format_sarif",
    "as_json",
    "as_text",
    "as_sarif",
    "render",
    "render_report",
]
