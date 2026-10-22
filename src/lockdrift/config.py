"""Configuration, ignore rules, baselines, and severity overrides."""

from __future__ import annotations

import fnmatch
import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Finding, Severity


@dataclass(frozen=True)
class LockdriftConfig:
    """Validated lockdrift configuration."""

    root: Path
    ignores: tuple[str, ...] = ()
    severity_overrides: dict[str, str] = field(default_factory=dict)
    baseline: Path | None = None
    config_path: Path | None = None


def find_config(root: Path) -> Path | None:
    """Find a .lockdrift.toml file in *root*."""
    candidate = root / ".lockdrift.toml"
    return candidate if candidate.is_file() else None


def _validate_severity(value: str) -> str:
    try:
        Severity(value)
    except ValueError as exc:
        raise ValueError(f"invalid severity: {value!r}") from exc
    return value


def load_config(root: Path | str) -> LockdriftConfig:
    """Load and validate .lockdrift.toml from *root*."""
    root = Path(root).resolve()
    path = find_config(root)
    data: dict[str, Any] = {}
    if path is not None:
        with path.open("rb") as handle:
            data = tomllib.load(handle)

    ignores = tuple(str(item) for item in data.get("ignore", []))
    raw_overrides = data.get("severity", data.get("severity_overrides", {}))
    overrides: dict[str, str] = {}
    if isinstance(raw_overrides, dict):
        for key, value in raw_overrides.items():
            overrides[str(key)] = _validate_severity(str(value))

    baseline_raw = data.get("baseline")
    baseline = (root / str(baseline_raw)).resolve() if baseline_raw else None
    return LockdriftConfig(
        root=root,
        ignores=ignores,
        severity_overrides=overrides,
        baseline=baseline,
        config_path=path,
    )


def load_baseline(path: Path | str | None) -> set[str]:
    """Load baseline finding identifiers from *path*."""
    if not path:
        return set()
    candidate = Path(path)
    if not candidate.is_file():
        return set()
    try:
        data = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    if isinstance(data, list):
        return {str(item) for item in data}
    if isinstance(data, dict):
        values = data.get("findings", data.get("ids", []))
        if isinstance(values, list):
            return {str(item) for item in values}
    return set()


def is_ignored(config: LockdriftConfig, finding: Finding) -> bool:
    """Return whether *finding* matches an ignore rule."""
    for pattern in config.ignores:
        if (
            fnmatch.fnmatch(finding.finding_id, pattern)
            or fnmatch.fnmatch(finding.package, pattern)
            or fnmatch.fnmatch(finding.code, pattern)
        ):
            return True
    return False


def apply_config(config: LockdriftConfig, findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    """Apply ignore rules and severity overrides to *findings*."""
    result: list[Finding] = []
    for finding in findings:
        if is_ignored(config, finding):
            continue
        override = config.severity_overrides.get(finding.finding_id)
        override = override or config.severity_overrides.get(finding.code)
        if override:
            finding = Finding(
                finding_id=finding.finding_id,
                code=finding.code,
                severity=Severity(override),
                ecosystem=finding.ecosystem,
                dependency_type=finding.dependency_type,
                package=finding.package,
                message=finding.message,
                declared=finding.declared,
                resolved=finding.resolved,
                suggestion=finding.suggestion,
            )
        result.append(finding)
    return tuple(result)


def filter_baseline(
    findings: tuple[Finding, ...], baseline_ids: set[str]
) -> tuple[Finding, ...]:
    """Remove findings already present in a baseline."""
    return tuple(f for f in findings if f.finding_id not in baseline_ids)
