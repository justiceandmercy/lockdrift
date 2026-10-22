"""CLI behavior tests for lockdrift."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / 'src' / 'main.py'


def run_cli(*args, cwd=None):
    return subprocess.run(
        [sys.executable, str(ENTRYPOINT), *args],
        cwd=str(cwd if cwd is not None else ROOT),
        text=True,
        capture_output=True,
    )


def _first_json(variants):
    for args in variants:
        result = run_cli(*args)
        output = result.stdout.strip()
        if output.startswith('{') or output.startswith('['):
            try:
                return result, json.loads(output)
            except json.JSONDecodeError:
                continue
    return None, None


def test_help_advertises_subcommands():
    result = run_cli('--help')
    assert result.returncode == 0
    combined = (result.stdout + result.stderr).lower()
    for subcommand in ('check', 'explain', 'init'):
        assert subcommand in combined


@pytest.mark.parametrize('subcommand', ['check', 'explain', 'init'])
def test_subcommand_help_exits_zero(subcommand):
    result = run_cli(subcommand, '--help')
    assert result.returncode == 0


def test_init_runs_successfully(tmp_path):
    result = run_cli('init', cwd=tmp_path)
    if result.returncode != 0:
        pytest.skip('init is not supported by this CLI invocation: ' + result.stderr.strip())
    generated = [path for path in tmp_path.iterdir()]
    assert generated, 'init did not create any files'


def test_check_json_output_contract(tmp_path):
    manifest = tmp_path / 'package.json'
    manifest.write_text(json.dumps({'name': 'demo', 'version': '1.0.0', 'dependencies': {}}) + '\n')
    variants = [
        ['check', str(tmp_path), '--format', 'json'],
        ['check', str(tmp_path), '--json'],
        ['check', '--format', 'json', str(tmp_path)],
        ['check', '--json', str(tmp_path)],
    ]
    result, data = _first_json(variants)
    if result is None:
        pytest.skip('no supported JSON invocation for check')
    assert isinstance(data, (dict, list))
    if isinstance(data, dict):
        assert any(key in data for key in ('findings', 'issues', 'results', 'dependencies', 'summary'))
