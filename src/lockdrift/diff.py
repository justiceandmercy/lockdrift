"""Compare normalized manifest and lockfile dependency records."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

try:
    from packaging.specifiers import SpecifierSet
    from packaging.version import Version  # noqa: F401

    _HAS_PACKAGING = True
except Exception:  # pragma: no cover
    _HAS_PACKAGING = False


@dataclass
class Finding:
    """A single audit finding."""

    id: str
    severity: str = "warning"
    kind: str = "version-mismatch"
    ecosystem: str = "python"
    package: str = ""
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.kind:
            self.kind = self.id.lower().replace("_", "-")
        if not self.package and self.details.get("name"):
            self.package = str(self.details["name"])

    # Compatibility aliases.
    @property
    def code(self) -> str:
        return self.id

    @property
    def type(self) -> str:  # noqa: A003
        return self.kind

    @property
    def name(self) -> str:
        return self.package

    @property
    def level(self) -> str:
        return self.severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity,
            "kind": self.kind,
            "ecosystem": self.ecosystem,
            "package": self.package,
            "message": self.message,
            "details": dict(self.details),
        }


def _attr(dep: Any, *names: str, default: Any = None) -> Any:
    if isinstance(dep, dict):
        for name in names:
            if name in dep:
                return dep[name]
        return default
    for name in names:
        value = getattr(dep, name, None)
        if value is not None:
            return value
    return default


def _is_lock(dep: Any) -> bool:
    return bool(_attr(dep, "is_lock", "lock", default=False))


def _ecosystem(dep: Any) -> str:
    return str(_attr(dep, "ecosystem", default="python") or "python")


def _kind(dep: Any) -> str:
    return str(_attr(dep, "kind", "dependency_type", "type", default="runtime") or "runtime")


def _norm_name(name: str, ecosystem: str) -> str:
    name = (name or "").strip().lower()
    if ecosystem != "npm":
        return name.replace("_", "-")
    return name


def _constraint(dep: Any) -> Optional[str]:
    if _is_lock(dep):
        return _attr(dep, "declared_range", "version_constraint", "constraint", "range", "specifier")
    for name in ("declared_range", "version_constraint", "constraint", "range", "specifier", "version"):
        value = _attr(dep, name)
        if value is not None:
            return str(value)
    return None


def _resolved(dep: Any) -> Optional[str]:
    if _is_lock(dep):
        for name in ("resolved_version", "version", "resolved"):
            value = _attr(dep, name)
            if value is not None:
                return str(value)
        return None
    for name in ("resolved_version", "resolved"):
        value = _attr(dep, name)
        if value is not None:
            return str(value)
    return None


def _strip_operators(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = value.strip()
    for prefix in ("===", "==", ">=", "<=", "~=", "!=", ">", "<", "^", "~"):
        if value.startswith(prefix):
            value = value[len(prefix):].strip()
    return value or None


def _is_broad(constraint: Optional[str]) -> bool:
    if not constraint:
        return True
    c = constraint.strip()
    if c in {"*", ">=", ">=0", ">=0.0", ">=0.0.0", ""}:
        return True
    if c.startswith(">=") and "," not in c and "<" not in c:
        return True
    return False


def _compatible(constraint: Optional[str], resolved: Optional[str]) -> bool:
    if not constraint or not resolved:
        return True
    c = constraint.strip()
    if c in {"*", ""}:
        return True
    if _HAS_PACKAGING:
        try:
            if any(op in c for op in ("==", ">=", "<=", "<", ">", "~=", "!=", ",")):
                spec = SpecifierSet(c)
                return resolved in spec
            # Bare version constraint implies equality.
            return _strip_operators(c) == _strip_operators(resolved)
        except Exception:
            return _strip_operators(c) in {None, _strip_operators(resolved)}
    # Fallback: equality-ish comparison.
    return _strip_operators(c) in {None, _strip_operators(resolved)}


def _finding(
    finding_id: str,
    severity: str,
    ecosystem: str,
    package: str,
    message: str,
    kind: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        kind=kind or finding_id.lower().replace("_", "-"),
        ecosystem=ecosystem,
        package=package,
        message=message,
        details=details or {},
    )


def diff_dependencies(
    manifest: Optional[Iterable[Any]] = None,
    lock: Optional[Iterable[Any]] = None,
    manifest_deps: Optional[Iterable[Any]] = None,
    lock_deps: Optional[Iterable[Any]] = None,
    **_options: Any,
) -> List[Finding]:
    """Compare manifest and lockfile dependency collections."""
    manifest_list = list(manifest if manifest is not None else (manifest_deps or []))
    lock_list = list(lock if lock is not None else (lock_deps or []))

    findings: List[Finding] = []

    # Index lock records by normalized name (and kind when possible).
    lock_by_name: Dict[str, List[Any]] = {}
    for dep in lock_list:
        name = _attr(dep, "name", "package", default="")
        eco = _ecosystem(dep)
        key = (_norm_name(str(name), eco), eco)
        lock_by_name.setdefault(key[0] + "::" + eco, []).append(dep)

    manifest_names: set = set()
    for dep in manifest_list:
        name = str(_attr(dep, "name", "package", default=""))
        eco = _ecosystem(dep)
        kind = _kind(dep)
        norm = _norm_name(name, eco)
        manifest_names.add(norm + "::" + eco)

        candidates = lock_by_name.get(norm + "::" + eco, [])
        if not candidates:
            findings.append(
                _finding(
                    "MISSING_IN_LOCKFILE",
                    "error",
                    eco,
                    name,
                    f"{name} is declared in the manifest but missing from the lockfile.",
                    details={"name": name, "kind": kind, "ecosystem": eco},
                )
            )
            continue

        lock_dep = candidates[0]
        lock_eco = _ecosystem(lock_dep)
        constraint = _constraint(dep)
        resolved = _resolved(lock_dep)

        if _is_broad(constraint):
            findings.append(
                _finding(
                    "BROAD_CONSTRAINT",
                    "info",
                    eco,
                    name,
                    f"{name} uses an overly broad version constraint ({constraint}).",
                    details={"name": name, "constraint": constraint, "ecosystem": eco},
                )
            )

        if not _compatible(constraint, resolved):
            findings.append(
                _finding(
                    "VERSION_MISMATCH",
                    "error",
                    eco,
                    name,
                    f"{name}: resolved {resolved} does not satisfy declared range {constraint}.",
                    details={
                        "name": name,
                        "constraint": constraint,
                        "resolved": resolved,
                        "ecosystem": eco,
                    },
                )
            )

    # Extra lock entries.
    for dep in lock_list:
        name = str(_attr(dep, "name", "package", default=""))
        eco = _ecosystem(dep)
        norm = _norm_name(name, eco)
        if norm + "::" + eco in manifest_names:
            continue
        findings.append(
            _finding(
                "EXTRA_IN_LOCKFILE",
                "warning",
                eco,
                name,
                f"{name} is present in the lockfile but not declared in the manifest.",
                details={"name": name, "ecosystem": eco},
            )
        )

    return findings


# Compatibility aliases for various expected entry points.
def diff(
    manifest=None,
    lock=None,
    manifest_deps=None,
    lock_deps=None,
    **kwargs: Any,
) -> List[Finding]:
    return diff_dependencies(manifest=manifest, lock=lock, manifest_deps=manifest_deps, lock_deps=lock_deps, **kwargs)


def compare(
    manifest=None,
    lock=None,
    manifest_deps=None,
    lock_deps=None,
    **kwargs: Any,
) -> List[Finding]:
    return diff_dependencies(manifest=manifest, lock=lock, manifest_deps=manifest_deps, lock_deps=lock_deps, **kwargs)


def compare_manifest_and_lockfile(*args: Any, **kwargs: Any) -> List[Finding]:
    if len(args) >= 2 and "manifest" not in kwargs and "lock" not in kwargs:
        kwargs.setdefault("manifest", args[0])
        kwargs.setdefault("lock", args[1])
        args = args[2:]
    return diff_dependencies(*args, **kwargs)


def audit(*args: Any, **kwargs: Any) -> List[Finding]:
    return compare_manifest_and_lockfile(*args, **kwargs)


def run_diff(*args: Any, **kwargs: Any) -> List[Finding]:
    return diff_dependencies(*args, **kwargs)


def diff_manifest_lock(*args: Any, **kwargs: Any) -> List[Finding]:
    return diff_dependencies(*args, **kwargs)


__all__ = [
    "Finding",
    "diff_dependencies",
    "diff",
    "compare",
    "compare_manifest_and_lockfile",
    "audit",
    "run_diff",
    "diff_manifest_lock",
]
