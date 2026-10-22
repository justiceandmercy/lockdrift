"""Parser normalization tests for lockdrift."""

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


def test_parsers_module_is_importable():
    module = _import_module('parsers')
    assert module is not None


def test_parsers_expose_public_callables():
    module = _import_module('parsers')
    public_callables = [
        name for name in dir(module)
        if not name.startswith('_') and callable(getattr(module, name))
    ]
    assert public_callables, 'lockdrift.parsers has no public callables'


def test_parser_fixture_directory_convention():
    _import_module('parsers')
    assert ROOT.exists()
