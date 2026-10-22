"""Immutable data models used throughout lockdrift."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    """Finding severity levels."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"error": 0, "warning": 1, "info": 2}[self.value]


class Ecosystem(str, Enum):
    """Supported package ecosystems."""

    NPM = "npm"
    PYTHON = "python"


class DependencyType(str, Enum):
    """Dependency declaration type."""

    RUNTIME = "runtime"
    DEV = "dev"
    OPTIONAL = "optional"
    PEER = "peer"
    TEST = "test"


@dataclass(frozen=True)
class ManifestDependency:
    """A dependency declared in a manifest file."""

    name: str
    constraint: str
    ecosystem: Ecosystem
    dep_type: DependencyType = DependencyType.RUNTIME
    optional: bool = False
    extras: tuple[str, ...] = ()
    markers: str | None = None
    source: Path | None = None


@dataclass(frozen=True)
class LockDependency:
    """A dependency resolved in a lockfile."""

    name: str
    version: str
    ecosystem: Ecosystem
    dep_type: DependencyType = DependencyType.RUNTIME
    optional: bool = False
    extras: tuple[str, ...] = ()
    markers: str | None = None
    source: Path | None = None


@dataclass(frozen=True)
class Finding:
    """A single audit finding."""

    finding_id: str
    code: str
    severity: Severity
    ecosystem: Ecosystem
    dependency_type: DependencyType
    package: str
    message: str
    declared: str | None = None
    resolved: str | None = None
    suggestion: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id,
            "code": self.code,
            "severity": self.severity.value,
            "ecosystem": self.ecosystem.value,
            "dependency_type": self.dependency_type.value,
            "package": self.package,
            "message": self.message,
            "declared": self.declared,
            "resolved": self.resolved,
            "suggestion": self.suggestion,
        }


@dataclass(frozen=True)
class ScanReport:
    """Result of scanning a project."""

    root: Path
    manifests: tuple[Path, ...] = ()
    lockfiles: tuple[Path, ...] = ()
    findings: tuple[Finding, ...] = ()

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "manifests": [str(path) for path in self.manifests],
            "lockfiles": [str(path) for path in self.lockfiles],
            "findings": [finding.to_dict() for finding in self.findings],
            "summary": {
                "total": len(self.findings),
                "errors": sum(f.severity is Severity.ERROR for f in self.findings),
                "warnings": sum(f.severity is Severity.WARNING for f in self.findings),
                "info": sum(f.severity is Severity.INFO for f in self.findings),
            },
        }
