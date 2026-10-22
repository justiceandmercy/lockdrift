"""Command-line interface for lockdrift."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .config import (
    LockdriftConfig,
    apply_config,
    filter_baseline,
    load_baseline,
    load_config,
)
from .models import Ecosystem, Finding, ScanReport, Severity
from .parsers.npm import (
    parse_package_json,
    parse_package_lock,
    parse_pnpm_lock,
    parse_yarn_lock,
)
from .parsers.python import (
    parse_pip_compile,
    parse_poetry_lock,
    parse_pyproject,
    parse_requirements,
)

_IGNORED_PARTS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


def _ignored(path: Path) -> bool:
    return any(part in _IGNORED_PARTS for part in path.parts)


def _norm(name: str, ecosystem: Ecosystem) -> str:
    if ecosystem is Ecosystem.PYTHON:
        return name.lower().replace("_", "-")
    return name


def _parse_version(value: str) -> tuple[int, ...]:
    cleaned = value.strip().lstrip("v")
    parts: list[int] = []
    for part in cleaned.split("."):
        digits = ""
        for char in part:
            if char.isdigit():
                digits += char
            else:
                break
        parts.append(int(digits) if digits else 0)
    return tuple(parts) if parts else (0,)


def _cmp(op: str, left: str, right: str) -> bool:
    a = _parse_version(left)
    b = _parse_version(right)
    if op in (">=",):
        return b >= a
    if op in ("<=",):
        return b <= a
    if op in (">",):
        return b > a
    if op in ("<",):
        return b < a
    if op in ("==", "=", ""):
        return a == b
    if op in ("!=",):
        return a != b
    return True


def _npm_check(constraint: str, version: str) -> bool:
    constraint = constraint.strip()
    if not constraint or constraint.lower() in {"*", "latest", "x"}:
        return True
    if " " in constraint and (">" in constraint or "<" in constraint):
        return all(_npm_check(part, version) for part in constraint.split())
    if constraint.startswith("^"):
        base = _parse_version(constraint[1:])
        resolved = _parse_version(version)
        if not base or not resolved:
            return True
        if base[0] != 0:
            limit = (base[0] + 1,) + (0,) * (len(base) - 1)
        elif len(base) > 1 and base[1] != 0:
            limit = (0, base[1] + 1) + (0,) * (len(base) - 2)
        else:
            limit = (0, 0, base[2] + 1) if len(base) > 2 else (0, 0, 1)
        return resolved >= base and resolved < limit
    if constraint.startswith("~"):
        base = _parse_version(constraint[1:])
        resolved = _parse_version(version)
        if len(base) >= 2:
            limit = (base[0], base[1] + 1) + (0,) * (len(base) - 2)
        else:
            limit = (base[0] + 1,)
        return resolved >= base and resolved < limit
    for op in (">=", "<=", "==", "!=", "=", ">", "<"):
        if constraint.startswith(op):
            return _cmp(op, constraint[len(op) :].strip(), version)
    if "x" in constraint.lower() or "*" in constraint:
        base = constraint.lower().replace("x", "0").replace("*", "0")
        return _parse_version(version)[: len(_parse_version(base))] == _parse_version(base)
    return _parse_version(constraint) == _parse_version(version)


def _version_ok(constraint: str, version: str, ecosystem: Ecosystem) -> bool:
    constraint = (constraint or "*").strip()
    if ecosystem is Ecosystem.PYTHON:
        try:
            from packaging.specifiers import InvalidSpecifier, SpecifierSet
            from packaging.version import InvalidVersion, Version

            try:
                spec = SpecifierSet(constraint)
                return Version(version) in spec
            except (InvalidSpecifier, InvalidVersion):
                pass
        except Exception:
            pass
    return _npm_check(constraint, version) if ecosystem is Ecosystem.NPM else _cmp("==", constraint, version) if False else True


def _is_broad(constraint: str) -> bool:
    value = (constraint or "").strip().lower()
    return value in {"", "*", "latest", "x"}


def _suggestion(ecosystem: Ecosystem) -> str:
    if ecosystem is Ecosystem.NPM:
        return "Run npm install, pnpm install, or yarn install to regenerate the lockfile."
    return "Run poetry lock or pip-compile to regenerate the lockfile."


def _finding(
    code: str,
    severity: Severity,
    ecosystem: Ecosystem,
    dep_type: Any,
    package: str,
    message: str,
    declared: str | None = None,
    resolved: str | None = None,
) -> Finding:
    return Finding(
        finding_id=f"{ecosystem.value}:{dep_type.value}:{code}:{_norm(package, ecosystem)}",
        code=code,
        severity=severity,
        ecosystem=ecosystem,
        dependency_type=dep_type,
        package=package,
        message=message,
        declared=declared,
        resolved=resolved,
        suggestion=_suggestion(ecosystem),
    )


def _compare(
    manifest_deps: list[Any],
    lock_map: dict[str, Any],
    ecosystem: Ecosystem,
) -> list[Finding]:
    declared: dict[str, Any] = {}
    for dep in manifest_deps:
        declared.setdefault(_norm(dep.name, ecosystem), dep)
    resolved: dict[str, Any] = {}
    for dep in lock_map.values():
        resolved.setdefault(_norm(dep.name, ecosystem), dep)

    findings: list[Finding] = []
    for key, dep in declared.items():
        if key not in resolved:
            findings.append(
                _finding(
                    "missing-in-lock",
                    Severity.ERROR,
                    ecosystem,
                    dep.dep_type,
                    dep.name,
                    f"{dep.name} is declared but missing from the lockfile.",
                    declared=dep.constraint,
                )
            )
            continue
        lock = resolved[key]
        if not _version_ok(dep.constraint, lock.version, ecosystem):
            findings.append(
                _finding(
                    "version-mismatch",
                    Severity.ERROR,
                    ecosystem,
                    dep.dep_type,
                    dep.name,
                    f"{dep.name} resolves to {lock.version}, outside {dep.constraint}.",
                    declared=dep.constraint,
                    resolved=lock.version,
                )
            )
        if _is_broad(dep.constraint):
            findings.append(
                _finding(
                    "broad-constraint",
                    Severity.INFO,
                    ecosystem,
                    dep.dep_type,
                    dep.name,
                    f"{dep.name} uses an overly broad constraint: {dep.constraint}.",
                    declared=dep.constraint,
                    resolved=lock.version,
                )
            )
    for key, lock in resolved.items():
        if key not in declared:
            findings.append(
                _finding(
                    "extra-in-lock",
                    Severity.WARNING,
                    ecosystem,
                    lock.dep_type,
                    lock.name,
                    f"{lock.name} is locked but not declared in the manifest.",
                    resolved=lock.version,
                )
            )
    return findings


def scan_project(root: Path, config: LockdriftConfig) -> ScanReport:
    """Scan *root* and return a report."""
    root = Path(root).resolve()
    manifests: list[Path] = []
    lockfiles: list[Path] = []

    npm_manifest_deps: list[Any] = []
    npm_lock: dict[str, Any] = {}
    python_manifest_deps: list[Any] = []
    python_lock: dict[str, Any] = {}

    for path in sorted(root.rglob("package.json")):
        if _ignored(path):
            continue
        manifests.append(path)
        try:
            npm_manifest_deps.extend(parse_package_json(path))
        except (OSError, ValueError, json.JSONDecodeError):
            pass

    for filename in ("package-lock.json",):
        for path in sorted(root.rglob(filename)):
            if _ignored(path):
                continue
            lockfiles.append(path)
            try:
                npm_lock.update(parse_package_lock(path))
            except (OSError, ValueError, json.JSONDecodeError):
                pass
    for filename in ("pnpm-lock.yaml", "pnpm-lock.yml"):
        for path in sorted(root.rglob(filename)):
            if _ignored(path):
                continue
            lockfiles.append(path)
            try:
                npm_lock.update(parse_pnpm_lock(path))
            except (OSError, ValueError):
                pass
    for filename in ("yarn.lock",):
        for path in sorted(root.rglob(filename)):
            if _ignored(path):
                continue
            lockfiles.append(path)
            try:
                npm_lock.update(parse_yarn_lock(path))
            except (OSError, ValueError):
                pass

    for path in sorted(root.rglob("pyproject.toml")):
        if _ignored(path):
            continue
        manifests.append(path)
        try:
            python_manifest_deps.extend(parse_pyproject(path))
        except (OSError, ValueError, tomllib.TOMLDecodeError):
            pass

    for path in sorted(root.rglob("requirements*.in")):
        if _ignored(path):
            continue
        manifests.append(path)
        try:
            python_manifest_deps.extend(parse_requirements(path))
        except (OSError, ValueError):
            pass
    for path in sorted(root.rglob("requirements*.txt")):
        if _ignored(path):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if "pip-compile" in text.lower() or "autogenerated" in text.lower():
            lockfiles.append(path)
            try:
                python_lock.update(parse_pip_compile(path))
            except (OSError, ValueError):
                pass
        else:
            manifests.append(path)
            try:
                python_manifest_deps.extend(parse_requirements(path))
            except (OSError, ValueError):
                pass

    for path in sorted(root.rglob("poetry.lock")):
        if _ignored(path):
            continue
        lockfiles.append(path)
        try:
            python_lock.update(parse_poetry_lock(path))
        except (OSError, ValueError, tomllib.TOMLDecodeError):
            pass

    findings = []
    findings.extend(_compare(npm_manifest_deps, npm_lock, Ecosystem.NPM))
    findings.extend(_compare(python_manifest_deps, python_lock, Ecosystem.PYTHON))
    findings = list(apply_config(config, tuple(findings)))
    return ScanReport(
        root=root,
        manifests=tuple(manifests),
        lockfiles=tuple(lockfiles),
        findings=tuple(findings),
    )


def _render_human(report: ScanReport) -> None:
    print(
        f"lockdrift: scanned {len(report.manifests)} manifest(s) "
        f"and {len(report.lockfiles)} lockfile(s)"
    )
    if not report.findings:
        print("No findings.")
        return
    for severity in (Severity.ERROR, Severity.WARNING, Severity.INFO):
        group = [finding for finding in report.findings if finding.severity is severity]
        if not group:
            continue
        print(f"\n{severity.value.upper()} ({len(group)})")
        for finding in group:
            print(f"  [{finding.finding_id}] {finding.package}: {finding.message}")
            if finding.declared is not None or finding.resolved is not None:
                print(f"      declared={finding.declared} resolved={finding.resolved}")
            if finding.suggestion:
                print(f"      suggestion: {finding.suggestion}")


_EXPLANATIONS = {
    "missing-in-lock": "A dependency is declared in a manifest but absent from the corresponding lockfile.",
    "extra-in-lock": "A dependency is present in a lockfile but no longer declared in the manifest.",
    "version-mismatch": "The resolved lockfile version does not satisfy the declared version constraint.",
    "broad-constraint": "The declared version constraint is overly broad and may allow unexpected upgrades.",
}


def run_check(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    config_path = Path(args.config).resolve() if getattr(args, "config", None) else None
    config = load_config(root) if config_path is None else load_config(root)
    if config_path is not None:
        # Keep path handling simple and predictable for callers.
        config = LockdriftConfig(
            root=config.root,
            ignores=config.ignores,
            severity_overrides=config.severity_overrides,
            baseline=config.baseline,
            config_path=config_path,
        )
    report = scan_project(root, config)
    baseline_path = Path(args.baseline).resolve() if getattr(args, "baseline", None) else config.baseline
    baseline_ids = load_baseline(baseline_path)
    findings = filter_baseline(report.findings, baseline_ids)
    report = ScanReport(
        root=report.root,
        manifests=report.manifests,
        lockfiles=report.lockfiles,
        findings=findings,
    )

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _render_human(report)

    if getattr(args, "fix", False):
        print("\nSuggested regeneration commands:")
        ecosystems = {finding.ecosystem for finding in report.findings}
        if Ecosystem.NPM in ecosystems:
            print("  npm install")
        if Ecosystem.PYTHON in ecosystems:
            print("  poetry lock")
            print("  pip-compile")
        for finding in report.findings:
            if finding.suggestion:
                print(f"  # {finding.package}: {finding.suggestion}")
    return 1 if report.findings else 0


def run_explain(args: argparse.Namespace) -> int:
    topic = args.topic
    if topic in _EXPLANATIONS:
        print(_EXPLANATIONS[topic])
        return 0
    if ":" in topic:
        code = topic.split(":")[-1]
        # Allow callers to pass either a finding id or a bare code.
        for key, value in _EXPLANATIONS.items():
            if key == code:
                print(value)
                return 0
    print(f"lockdrift: unknown topic: {topic}", file=sys.stderr)
    print("Available topics: " + ", ".join(sorted(_EXPLANATIONS)), file=sys.stderr)
    return 2


def run_init(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    target = root / ".lockdrift.toml"
    if target.exists() and not getattr(args, "force", False):
        print(f"lockdrift: {target} already exists", file=sys.stderr)
        return 1
    template = (
        "# lockdrift configuration\n"
        "ignore = []\n\n"
        "[severity]\n"
        '# missing-in-lock = "warning"\n\n'
        'baseline = ""\n'
    )
    target.write_text(template, encoding="utf-8")
    print(f"Created {target}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lockdrift")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="Audit a project.")
    check.add_argument("path", nargs="?", default=".")
    check.add_argument("--format", choices=("human", "json"), default="human")
    check.add_argument("--config")
    check.add_argument("--baseline")
    check.add_argument("--fix", action="store_true")
    check.set_defaults(func=run_check)

    explain = subparsers.add_parser("explain", help="Explain a finding or code.")
    explain.add_argument("topic")
    explain.set_defaults(func=run_explain)

    init = subparsers.add_parser("init", help="Create a configuration file.")
    init.add_argument("path", nargs="?", default=".")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=run_init)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        print(f"lockdrift: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
