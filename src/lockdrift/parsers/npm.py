"""Parsers for npm manifests and lockfiles."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..models import DependencyType, Ecosystem, LockDependency, ManifestDependency


def _manifest(
    name: str,
    constraint: str,
    dep_type: DependencyType,
    source: Path,
    optional: bool = False,
) -> ManifestDependency:
    return ManifestDependency(
        name=name,
        constraint=str(constraint),
        ecosystem=Ecosystem.NPM,
        dep_type=dep_type,
        optional=optional,
        source=source,
    )


def _lock(
    name: str,
    version: str,
    dep_type: DependencyType,
    source: Path,
    optional: bool = False,
) -> LockDependency:
    return LockDependency(
        name=name,
        version=str(version),
        ecosystem=Ecosystem.NPM,
        dep_type=dep_type,
        optional=optional,
        source=source,
    )


def parse_package_json(path: Path | str) -> list[ManifestDependency]:
    """Parse dependencies from a package.json file."""
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    result: list[ManifestDependency] = []
    sections = (
        ("dependencies", DependencyType.RUNTIME, False),
        ("devDependencies", DependencyType.DEV, False),
        ("optionalDependencies", DependencyType.OPTIONAL, True),
        ("peerDependencies", DependencyType.PEER, False),
    )
    for section, dep_type, optional in sections:
        values = data.get(section, {})
        if isinstance(values, dict):
            for name, constraint in values.items():
                result.append(
                    _manifest(name, str(constraint), dep_type, path, optional=optional)
                )
    return result


def _parse_legacy_dependencies(
    dependencies: dict[str, Any], result: dict[str, LockDependency], path: Path
) -> None:
    for name, info in dependencies.items():
        if not isinstance(info, dict):
            continue
        version = info.get("version")
        if version is not None:
            dep_type = DependencyType.DEV if info.get("dev") else DependencyType.RUNTIME
            result[name] = _lock(
                name,
                str(version),
                dep_type,
                path,
                optional=bool(info.get("optional")),
            )
        nested = info.get("dependencies")
        if isinstance(nested, dict):
            _parse_legacy_dependencies(nested, result, path)


def parse_package_lock(path: Path | str) -> dict[str, LockDependency]:
    """Parse an npm package-lock.json file."""
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    result: dict[str, LockDependency] = {}

    packages = data.get("packages")
    if isinstance(packages, dict):
        for package_path, info in packages.items():
            if not package_path or not isinstance(info, dict):
                continue
            name = package_path.rsplit("node_modules/", 1)[-1]
            if not name or name == package_path:
                continue
            version = info.get("version")
            if version is None:
                continue
            dep_type = DependencyType.DEV if info.get("dev") else DependencyType.RUNTIME
            result[name] = _lock(
                name,
                str(version),
                dep_type,
                path,
                optional=bool(info.get("optional")),
            )

    if not result:
        dependencies = data.get("dependencies")
        if isinstance(dependencies, dict):
            _parse_legacy_dependencies(dependencies, result, path)
    return result


def _split_pnpm_key(key: str) -> tuple[str | None, str | None]:
    key = key.strip().strip("'\"")
    if key.startswith("/"):
        key = key[1:]
    key = key.split("(", 1)[0]
    if key.startswith("@"):
        slash = key.find("/")
        at = key.rfind("@")
        if at > slash:
            return key[:at], key[at + 1 :]
    else:
        at = key.rfind("@")
        if at > 0:
            return key[:at], key[at + 1 :]
    if "/" in key:
        left, right = key.rsplit("/", 1)
        if right and (right[0].isdigit() or right.startswith("v")):
            return left, right
    return None, None


def parse_pnpm_lock(path: Path | str) -> dict[str, LockDependency]:
    """Parse a pnpm-lock.yaml file."""
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    result: dict[str, LockDependency] = {}

    try:
        import yaml

        data = yaml.safe_load(text)
    except Exception:
        data = None

    if isinstance(data, dict):
        packages = data.get("packages")
        if isinstance(packages, dict):
            for key, info in packages.items():
                name, version = _split_pnpm_key(str(key))
                if not name or not version:
                    continue
                dep_type = DependencyType.RUNTIME
                optional = False
                if isinstance(info, dict):
                    if info.get("dev"):
                        dep_type = DependencyType.DEV
                    optional = bool(info.get("optional"))
                result[name] = _lock(name, version, dep_type, path, optional=optional)
        if not result:
            for section in ("dependencies", "devDependencies"):
                values = data.get(section, {})
                if isinstance(values, dict):
                    for name, value in values.items():
                        version = value
                        if isinstance(value, dict):
                            version = value.get("version") or value.get("specifier")
                        if version is not None:
                            dep_type = (
                                DependencyType.DEV
                                if section == "devDependencies"
                                else DependencyType.RUNTIME
                            )
                            result[name] = _lock(name, str(version), dep_type, path)
    else:
        for match in re.finditer(
            r"(?m)^  '?([^:'\n]+?)'?:\s*\n(?:    .*\n)*?    version:\s*['\"]?([^'\"\n]+)",
            text,
        ):
            name, version = _split_pnpm_key(match.group(1))
            if name and version:
                result[name] = _lock(name, version, DependencyType.RUNTIME, path)
    return result


def _yarn_package_name(key: str) -> str | None:
    key = key.strip().strip('"').split(",")[0].strip().strip('"')
    if key.startswith("@"):
        slash = key.find("/")
        at = key.rfind("@")
        if at > slash:
            return key[:at]
    else:
        at = key.find("@")
        if at > 0:
            return key[:at]
    return key or None


def parse_yarn_lock(path: Path | str) -> dict[str, LockDependency]:
    """Parse a yarn.lock file."""
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    result: dict[str, LockDependency] = {}
    for block in re.split(r"\n\n+", text):
        lines = block.strip().splitlines()
        if not lines:
            continue
        version = None
        for line in lines[1:]:
            match = re.match(r"\s*version\s+\"([^\"]+)\"", line)
            if match:
                version = match.group(1)
                break
        if version is None:
            continue
        name = _yarn_package_name(lines[0].rstrip(":"))
        if name:
            result[name] = _lock(name, version, DependencyType.RUNTIME, path)
    return result
