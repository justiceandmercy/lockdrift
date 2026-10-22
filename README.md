# lockdrift

[![CI](https://github.com/justiceandmercy/lockdrift/actions/workflows/ci.yml/badge.svg)](https://github.com/justiceandmercy/lockdrift/actions/workflows/ci.yml)


[![CI](https://github.com/justiceandmercy/lockdrift/actions/workflows/ci.yml/badge.svg)](https://github.com/justiceandmercy/lockdrift/actions/workflows/ci.yml)


Audit dependency manifests and lockfiles for missing, extra, mismatched, and stale resolved versions across npm and Python projects.

`lockdrift` compares what a project declares with what its lockfile resolves. It reports dependencies that are declared but absent from the lockfile, dependencies that are locked but no longer declared, version ranges that cannot be satisfied by the resolved version, and overly broad constraints that hide supply-chain drift.

## Installation

pip install -e .

After installation the `lockdrift` console script is available:

lockdrift --version

## Supported ecosystems

npm:

- `package.json` with `package-lock.json`
- `package.json` with `pnpm-lock.yaml`
- `package.json` with `yarn.lock`

Python:

- `requirements*.txt` declarations with pip-tools compiled requirement files
- `pyproject.toml` (PEP 621 and Poetry tables) with `poetry.lock`
- Optional dependency groups, development dependencies, platform markers, and extras

## Quick start

Run an audit in the current directory:

lockdrift check

Emit machine-readable JSON:

lockdrift check --format json

Explain a finding by its stable identifier:

lockdrift explain LD001

Create a starter configuration file:

lockdrift init

## Configuration

Project-specific behavior is loaded from `.lockdrift.toml` in the project root.

[lockdrift]
baseline = ".lockdrift-baseline.json"
ignore = ["LD012", "LD030"]

[lockdrift.severity]
"npm:example-lib" = "warning"
"python:requests" = "error"

- `ignore` contains stable finding identifiers that should not be reported.
- `severity` overrides the default severity for a package or ecosystem.
- `baseline` points to a file used for gradual adoption in existing repositories.

## Findings

Findings are grouped by severity (`error`, `warning`, `info`), dependency type (`runtime`, `development`, `optional`, `extra`), and package ecosystem (`npm`, `python`). Each finding has a stable machine-readable identifier such as `LD001`.

Common finding classes:

- `LD001` dependency declared in a manifest but missing from the lockfile
- `LD002` dependency present in the lockfile but no longer declared
- `LD003` resolved version does not satisfy the declared range
- `LD004` declared range is broader than the resolved version warrants
- `LD005` stale resolved version after a manifest change

## Autofix suggestions

`lockdrift` never rewrites files automatically. It can print safe regeneration commands:

lockdrift check --fix

Typical suggestions include `npm install --package-lock-only`, `pnpm install --lockfile-only`, `poetry lock`, and `pip-compile`.

## Baseline files

For gradual adoption, write a baseline of current findings and fail only on new ones:

lockdrift check --write-baseline .lockdrift-baseline.json
lockdrift check --baseline .lockdrift-baseline.json

## CI usage

Exit codes are CI-friendly:

- `0` no findings above the configured threshold
- `1` one or more findings above the configured threshold
- `2` usage or configuration error

Example GitHub Actions step:

- name: Audit lockfiles
  run: lockdrift check --format json --fail-on warning

## Development

pytest
ruff check .

The test suite uses only local fixtures and performs no network access.
