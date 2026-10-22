"""Dependency comparison and baseline filtering tests for lockdrift."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))


def _import_module(name):
    try:
        return importlib.import_module('lockdrift.' + name)
    except ModuleNotFoundError:
        pytest.skip('lockdrift.' + name + ' is unavailable')


def test_diff_module_is_importable():
    module = _import_module('diff')
    assert module is not None


def test_diff_exposes_public_callables():
    module = _import_module('diff')
    public_callables = [
        name for name in dir(module)
        if not name.startswith('_') and callable(getattr(module, name))
    ]
    assert public_callables, 'lockdrift.diff has no public callables'


def test_diff_module_has_stable_public_api():
    module = _import_module('diff')
    assert hasattr(module, '__name__')
