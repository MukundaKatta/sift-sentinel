"""Enable `python -m sift_sentinel` to run the CLI without installation."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
