#!/usr/bin/env python3
"""Convenience launcher: python3 run.py scan <path>"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from clonerdetect.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
