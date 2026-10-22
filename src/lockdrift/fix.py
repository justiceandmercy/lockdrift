"""Safe remediation helpers for lockdrift findings.

This module never modifies project files.  It converts audit findings into
human-readable remediation suggestions, stable commands, and optional patch
previews that can be reviewed before being applied by a developer or CI job.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


@dataclass(frozen=True)
class FixSuggestion:
    """A single safe remediation suggestion.

    Attributes:
        id: Stable machine-readable identifier.
        finding: Identifier of the finding this suggestion addresses.
        code: Finding rule/code, when available.
        severity: Effective severity after configuration overrides.
        ecosystem: Package ecosystem, such as npm, pnpm, yarn, poetry, or pip.
        dependency: Dependency name affected by the finding.
        action: Short action label.
        command: Suggested command to run.  Empty when no safe command exists.
        description: Human-readable explanation of the suggested action.
        files: Files involved in the remediation.
        patch: Optional unified-diff style preview.  Never applied automatically.
        safe: Whether the suggestion is considered safe to run without review.
        automatic: Whether the command is intended for non-interactive automation.
    """

    id: str
    finding: str | None = None
    code: str | None = None
    severity: str = "medium"
    ecosystem: str = "unknown"
    dependency: str = ""
    action: str = "regenerate-lockfile"
    command: str = ""
    description: str = ""
    files: tuple[str, ...] = field(default_factory=tuple)
    patch: str = ""
    safe: bool = True
    automatic: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation."""
        return asdict(self)


# Aliases for callers that prefer different vocabulary.
Fix = FixSuggestion
Remediation = FixSuggestion
RemediationSuggestion = FixSuggestion


_REGENERATION_COMMANDS: dict[str, str] = {
    "npm": "npm install --package-lock-only",
    "pnpm": "pnpm install --lockfile-only",
    "yarn": "yarn install",
    "poetry": "poetry lock",
    "pip": "pip-compile",
    "pip-tools": "pip-compile",
    "python": "pip-compile",
}


def _get(finding: Any, *names: str, default: Any = None) -> Any:
    """Read the first available attribute or mapping key from a finding."""
    if isinstance(finding, Mapping):
        for name in names:
            if name in finding:
                return finding[name]
    for name in names:
        if hasattr(finding, name):
            value = getattr(finding, name)
            if value is not None:
                return value
    return default


def _as_list(value: Any) -> list[Any]:
    """Normalise configuration values to a list."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _config_values(config: Any, *names: str) -> list[Any]:
    """Collect ignored-rule or override values from a configuration object."""
    if config is None:
        return []
    if isinstance(config, Mapping):
        for name in names:
            if name in config:
                return _as_list(config[name])
        return []
    for name in names:
        if hasattr(config, name):
            return _as_list(getattr(config, name))
    return []


def _config_mapping(config: Any, *names: str) -> dict[str, Any]:
    """Collect a mapping-valued configuration section."""
    if config is None:
        return {}
    if isinstance(config, Mapping):
        for name in names:
            if isinstance(config.get(name), Mapping):
                return dict(config[name])
        return {}
    for name in names:
        value = getattr(config, name, None)
        if isinstance(value, Mapping):
            return dict(value)
    return {}


def _slug(value: Any) -> str:
    """Create a stable, filename-friendly identifier fragment."""
    text = str(value or "unknown").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-") or "unknown"


def _infer_ecosystem(finding: Any) -> str:
    """Infer an ecosystem from explicit fields or file paths."""
    explicit = _get(
        finding,
        "ecosystem",
        "package_ecosystem",
        "manager",
        "source",
        default=None,
    )
    if explicit:
        return str(explicit).strip().lower()

    text = " ".join(
        str(value)
        for value in (
            _get(finding, "manifest", "manifest_path", "manifest_file", default=""),
            _get(finding, "lockfile", "lockfile_path", "lock_file", default=""),
            _get(finding, "file", "path", default=""),
        )
        if value
    ).lower()
    if "pnpm" in text:
        return "pnpm"
    if "yarn" in text:
        return "yarn"
    if "poetry" in text:
        return "poetry"
    if "requirements" in text or "pip" in text or "pyproject" in text:
        return "python"
    return "npm"


def _finding_files(finding: Any) -> tuple[str, ...]:
    """Collect relevant file paths from a finding."""
    values: list[str] = []
    for name in (
        "manifest",
        "manifest_path",
        "manifest_file",
        "lockfile",
        "lockfile_path",
        "lock_file",
        "file",
        "path",
    ):
        value = _get(finding, name, default=None)
        if value:
            text = str(value)
            if text not in values:
                values.append(text)
    return tuple(values)


def _patch_preview(finding: Any) -> str:
    """Build a review-only patch preview for a version mismatch.

    The preview is intentionally textual.  It is never written to disk.
    """
    manifest = _get(
        finding,
        "manifest",
        "manifest_path",
        "manifest_file",
        "file",
        default="manifest",
    )
    dependency = _get(
        finding,
        "dependency",
        "package",
        "name",
        "package_name",
        default="dependency",
    )
    declared = _get(
        finding,
        "declared",
        "specifier",
        "constraint",
        "range",
        "declared_version",
        default=None,
    )
    resolved = _get(
        finding,
        "resolved",
        "locked_version",
        "resolved_version",
        "actual",
        "version",
        default=None,
    )
    if not declared or not resolved or str(declared) == str(resolved):
        return ""

    return "\n".join(
        [
            f"--- a/{manifest}",
            f"+++ b/{manifest}",
            "@@",
            f"-{dependency}: {declared}",
            f"+{dependency}: {resolved}",
        ]
    )


def _is_ignored(finding: Any, config: Any) -> bool:
    """Determine whether a finding is suppressed by configuration."""
    ignored = _config_values(
        config,
        "ignored",
        "ignore",
        "ignored_findings",
        "ignored_rules",
        "ignore_rules",
    )
    if not ignored:
        return False

    keys = {
        str(_get(finding, "id", "finding_id", default="")),
        str(_get(finding, "code", "rule", default="")),
        str(_get(finding, "dependency", "package", "name", default="")),
    }
    normalised_ignored = {str(item) for item in ignored}
    return bool(keys & normalised_ignored)


def generate_fixes(
    findings: Iterable[Any],
    *,
    config: Any = None,
    include_patches: bool = False,
    patches: bool | None = None,
) -> list[FixSuggestion]:
    """Generate safe remediation suggestions for audit findings.

    Args:
        findings: Iterable of finding objects or dictionaries.
        config: Optional project configuration containing ignore rules and
            severity overrides.
        include_patches: Whether to include review-only patch previews.
        patches: Backwards-compatible alias for ``include_patches``.

    Returns:
        A list of :class:`FixSuggestion` objects.  No files are modified.
    """
    if patches is not None:
        include_patches = patches

    severity_overrides = _config_mapping(
        config,
        "severity_overrides",
        "severity",
        "severities",
    )
    suggestions: list[FixSuggestion] = []

    for finding in findings or []:
        if _is_ignored(finding, config):
            continue

        ecosystem = _infer_ecosystem(finding)
        code = _get(finding, "code", "rule", "id", "finding_id", default=None)
        finding_id = _get(finding, "id", "finding_id", default=None)
        dependency = str(
            _get(finding, "dependency", "package", "name", "package_name", default="")
        )
        severity = str(
            _get(finding, "severity", default="medium")
        )
        if code is not None and str(code) in severity_overrides:
            severity = str(severity_overrides[str(code)])
        elif finding_id is not None and str(finding_id) in severity_overrides:
            severity = str(severity_overrides[str(finding_id)])

        command = _REGENERATION_COMMANDS.get(ecosystem, "")
        files = _finding_files(finding)
        patch = ""
        code_text = str(code or "")
        if include_patches or any(
            token in code_text.lower()
            for token in ("mismatch", "range", "version", "stale", "broad")
        ):
            patch = _patch_preview(finding)

        description = (
            f"Regenerate the {ecosystem} lockfile from the declared manifest "
            f"to resolve '{code or 'finding'}' for {dependency or 'the affected dependency'}."
        )
        suggestion_id = "fix-{}-{}-{}".format(
            ecosystem,
            _slug(dependency),
            _slug(code or finding_id or "finding"),
        )
        suggestions.append(
            FixSuggestion(
                id=suggestion_id,
                finding=str(finding_id) if finding_id is not None else None,
                code=str(code) if code is not None else None,
                severity=severity,
                ecosystem=ecosystem,
                dependency=dependency,
                action="regenerate-lockfile",
                command=command,
                description=description,
                files=files,
                patch=patch,
                safe=True,
                automatic=False,
            )
        )

    return suggestions


def suggest_fixes(*args: Any, **kwargs: Any) -> list[FixSuggestion]:
    """Alias for :func:`generate_fixes`."""
    return generate_fixes(*args, **kwargs)


def suggest_remediations(*args: Any, **kwargs: Any) -> list[FixSuggestion]:
    """Alias for :func:`generate_fixes`."""
    return generate_fixes(*args, **kwargs)


def remediation_commands(
    findings: Iterable[Any], **kwargs: Any
) -> list[str]:
    """Return only the suggested commands for the supplied findings."""
    commands: list[str] = []
    for suggestion in generate_fixes(findings, **kwargs):
        if suggestion.command and suggestion.command not in commands:
            commands.append(suggestion.command)
    return commands


def fix_commands(findings: Iterable[Any], **kwargs: Any) -> list[str]:
    """Alias for :func:`remediation_commands`."""
    return remediation_commands(findings, **kwargs)


def commands_for_findings(findings: Iterable[Any], **kwargs: Any) -> list[str]:
    """Alias for :func:`remediation_commands`."""
    return remediation_commands(findings, **kwargs)


def generate_patch(finding: Any, **kwargs: Any) -> str:
    """Return a review-only patch preview for one finding."""
    return _patch_preview(finding)


def patch_preview(finding: Any, **kwargs: Any) -> str:
    """Alias for :func:`generate_patch`."""
    return _patch_preview(finding)


def preview_patch(finding: Any, **kwargs: Any) -> str:
    """Alias for :func:`generate_patch`."""
    return _patch_preview(finding)


def render_text(suggestions: Sequence[FixSuggestion]) -> str:
    """Render suggestions as concise human-readable text."""
    lines: list[str] = []
    for suggestion in suggestions:
        lines.append(f"[{suggestion.severity}] {suggestion.id}")
        if suggestion.command:
            lines.append(f"  command: {suggestion.command}")
        if suggestion.description:
            lines.append(f"  {suggestion.description}")
        if suggestion.patch:
            lines.append("  patch preview:")
            for line in suggestion.patch.splitlines():
                lines.append(f"    {line}")
    return "\n".join(lines)


def render_json(suggestions: Sequence[FixSuggestion]) -> str:
    """Render suggestions as stable JSON."""
    return json.dumps(
        [suggestion.to_dict() for suggestion in suggestions],
        indent=2,
        sort_keys=True,
    )


def to_json(suggestions: Sequence[FixSuggestion]) -> str:
    """Alias for :func:`render_json`."""
    return render_json(suggestions)


__all__ = [
    "FixSuggestion",
    "Fix",
    "Remediation",
    "RemediationSuggestion",
    "generate_fixes",
    "suggest_fixes",
    "suggest_remediations",
    "remediation_commands",
    "fix_commands",
    "commands_for_findings",
    "generate_patch",
    "patch_preview",
    "preview_patch",
    "render_text",
    "render_json",
    "to_json",
]
