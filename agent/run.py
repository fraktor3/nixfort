#!/usr/bin/python3 -I
"""Launcher installed as /opt/nixfort-agent/run.py (see install.sh)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nixfort_agent.__main__ import main  # noqa: E402

sys.exit(main())
