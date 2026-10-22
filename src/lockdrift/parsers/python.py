"""Parsers for Python manifests and lockfiles."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from ..models import DependencyType, Ecosystem, LockDependency, ManifestDependency

_REQUIREMENT_RE = re.compile(
    r"^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?:\[([^\]]*)\])?"
    r"\s*(.*?)"
    r"(?:\s*;\s*(.*))?\s*$"
)


def _norm_name(name: str) -> str:
    return name.lower().replace("_", "-")


def _manifest(
    name: str,
    constraint: str,
    dep_type: DependencyType,
    source: Path,
    optional: bool = False,
    extras: tuple[str, ...] = (),
    markers: str | None = None,
) -> ManifestDependency:
    return ManifestDependency(
        name=name,
        constraint=constraint.strip() or "*",
        ecosystem=Ecosystem.PYTHON,
        dep_type=dep_type,
        optional=optional,
        extras=extras,
        markers=markers,
        source=source,
    )


def _lock(
    name: str,
    version: str,
    dep_type: DependencyType,
    source: Path,
    optional: bool = False,
    extras: tuple[str, ...] = (),
    markers: str | None = None,
) -> LockDependency:
    return LockDependency(
        name=name,
        version=version.strip(),
        ecosystem=Ecosystem.PYTHON,
        dep_type=dep_type,
        optional=optional,
        extras=extras,
        markers=markers,
        source=source,
    )


def _parse_requirement_string(
    value: str,
    source: Path,
    dep_type: DependencyType = DependencyType.RUNTIME,
    optional: bool = False,
    extras: tuple[str, ...] = (),
) -> ManifestDependency | None:
    value = value.strip()
    if not value or value.startswith("#"):
        return None
    match = _REQUIREMENT_RE.match(value)
    if not match:
        return None
    name = match.group(1)
    extras_text = match.group(2)
    constraint = match.group(3).strip()
    markers = match.group(4)
    extras_list = []
    if extras_text:
        extras_list.extend(item.strip() for item in extras_text.split(",") if item.strip())
    extras_list.extend(extras)
    return _manifest(
        name=name,
        constraint=constraint or "*",
        dep_type=dep_type,
        source=source,
        optional=optional,
        extras=tuple(extras_list),
        markers=markers.strip() if markers else None,
    )


def parse_requirements(path: Path | str) -> list[ManifestDependency]:
    """Parse a requirements-style manifest file."""
    path = Path(path)
    result: list[ManifestDependency] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r", "-c", "--")):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        dependency = _parse_requirement_string(line, path)
        if dependency is not None:
            result.append(dependency)
    return result


def _poetry_dependency(
    name: str,
    spec: Any,
    dep_type: DependencyType,
    source: Path,
    optional: bool = False,
) -> ManifestDependency | None:
    if name.lower() == "python":
        return None
    if isinstance(spec, str):
        constraint = spec
        extras: tuple[str, ...] = ()
        markers = None
        is_optional = optional
    elif isinstance(spec, dict):
        constraint = str(spec.get("version", "*"))
        extras = tuple(spec.get("extras", []) or [])
        markers = spec.get("markers")
        is_optional = bool(spec.get("optional", optional))
    else:
        constraint = "*"
        extras = ()
        markers = None
        is_optional = optional
    return _manifest(
        name=name,
        constraint=constraint,
        dep_type=dep_type,
        source=source,
        optional=is_optional,
        extras=extras,
        markers=str(markers) if markers is not None else None,
    )


def parse_pyproject(path: Path | str) -> list[ManifestDependency]:
    """Parse dependencies from pyproject.toml."""
    path = Path(path)
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    result: list[ManifestDependency] = []
    project = data.get("project", {})
    for item in project.get("dependencies", []):
        dependency = _parse_requirement_string(str(item), path)
        if dependency is not None:
            result.append(dependency)
    for group, items in project.get("optional-dependencies", {}).items():
        for item in items or []:
            dependency = _parse_requirement_string(
                str(item), path, optional=True, extras=(str(group),)
            )
            if dependency is not None:
                result.append(dependency)

    poetry = data.get("tool", {}).get("poetry", {})
    for name, spec in poetry.get("dependencies", {}).items():
        dependency = _poetry_dependency(name, spec, DependencyType.RUNTIME, path)
        if dependency is not None:
            result.append(dependency)
    for name, spec in poetry.get("dev-dependencies", {}).items():
        dependency = _poetry_dependency(
            name, spec, DependencyType.DEV, path, optional=True
        )
        if dependency is not None:
            result.append(dependency)
    for group_name, group in poetry.get("group", {}).items():
        dep_type = DependencyType.DEV if group_name in {"dev", "test"} else DependencyType.RUNTIME
        for name, spec in (group.get("dependencies") or {}).items():
            dependency = _poetry_dependency(name, spec, dep_type, path)
            if dependency is not None:
                result.append(dependency)
    return result


def parse_poetry_lock(path: Path | str) -> dict[str, LockDependency]:
    """Parse a poetry.lock file."""
    path = Path(path)
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    result: dict[str, LockDependency] = {}
    for package in data.get("package", []):
        name = package.get("name")
        version = package.get("version")
        if not name or not version:
            continue
        category = package.get("category") or (
            "dev" if package.get("develop") else "main"
        )
        dep_type = (
            DependencyType.DEV
            if str(category).lower() in {"dev", "test"}
            else DependencyType.RUNTIME
        )
        result[_norm_name(str(name))] = _lock(
            name=str(name),
            version=str(version),
            dep_type=dep_type,
            source=path,
            optional=bool(package.get("optional", False)),
            extras=tuple(package.get("extras", []) or []),
        )
    return result


def parse_pip_compile(path: Path | str) -> dict[str, LockDependency]:
    """Parse a pip-compile output file as a lockfile."""
    path = Path(path)
    result: dict[str, LockDependency] = {}
    for dependency in parse_requirements(path):
        match = re.match(r"==+\s*(.+)", dependency.constraint.strip())
        if not match:
            continue
        version = match.group(1).strip()
        result[_norm_name(dependency.name)] = _lock(
            name=dependency.name,
            version=version,
            dep_type=dependency.dep_type,
            source=path,
            optional=dependency.optional,
            extras=dependency.extras,
            markers=dependency.markers,
        )
    return result
