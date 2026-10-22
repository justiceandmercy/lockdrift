"""Thin executable entrypoint for lockdrift."""

from __future__ import annotations

from lockdrift.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
