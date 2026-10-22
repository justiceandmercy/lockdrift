# Architecture

lockdrift — Audit dependency manifests and lockfiles for missing, extra, mismatched, and stale resolved versions across npm and Python projects.

## Overview

The codebase is organized around a small set of focused modules. Each module owns a
single responsibility and the public surface is kept deliberately small so the tool
stays easy to hack on.

## Module map

| Path | Responsibility |
| ---- | -------------- |
| `src/main.py` | Thin executable entrypoint that imports and runs the CLI application. |
| `src/lockdrift/cli.py` | Defines Click/Typer-style subcommands, argument parsing, output formatting, and process exit codes. |
| `src/lockdrift/config.py` | Loads and validates .lockdrift.toml settings, ignore patterns, baselines, and severity overrides. |
| `src/lockdrift/models.py` | Defines immutable dataclasses for manifests, lockfiles, dependency records, findings, and scan reports. |
| `src/lockdrift/parsers/npm.py` | Parses package.json and npm, pnpm, and Yarn lockfile formats into normalized dependency records. |
| `src/lockdrift/parsers/python.py` | Parses requirements files, pyproject.toml, poetry.lock, and pip-compile outputs into normalized dependency records. |
| `src/lockdrift/diff.py` | Compares normalized manifest and lockfile records to produce missing, extra, and version mismatch findings. |
| `src/lockdrift/report.py` | Renders findings as terminal text, JSON, and SARIF-compatible reports with grouping and severity labels. |
| `src/lockdrift/fix.py` | Generates safe remediation commands and optional patch previews without modifying files automatically. |
| `tests/test_diff.py` | Covers dependency comparison rules, version range checks, and baseline filtering behavior. |
| `tests/test_parsers.py` | Covers npm and Python parser normalization using representative fixture manifests and lockfiles. |
| `tests/test_cli.py` | Exercises subcommand behavior, exit codes, configuration loading, and JSON output contracts. |
| `pyproject.toml` | Declares package metadata, dependencies, console script entrypoint, and test configuration. |
| `README.md` | Documents installation, supported ecosystems, configuration, examples, and CI usage. |

## Key design decisions

- **Zero/low runtime dependencies**: the core works from the standard library so
  installs stay fast and supply-chain risk stays low.
- **Configuration before convention**: behavior is tunable through config files and
  documented CLI flags instead of magic environment variables.
- **Structured output modes**: human-readable text by default, machine-readable JSON
  for automation, and DOT/Mermaid exports where a graph applies.
- **Everything is guarded by tests**: the CI matrix runs the suite on every push.

## Data flow

`CLI entrypoint -> config loading -> per-item scanning/processing -> aggregation ->
reporting (text | JSON | graph)`.

## Testing

Unit tests validate parser normalization and diff findings against fixture projects; CLI tests verify subcommands, exit codes, config and baseline handling, and JSON output shape. Integration tests run lockdrift against small npm and Python sample repositories to ensure end-to-end behavior.

Run them locally with `pytest -q`. CI (`.github/workflows/ci.yml`) executes the
same suite on a version matrix for every push and pull request.
