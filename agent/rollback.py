#!/usr/bin/python3 -I
"""Entry point of the node-side rollback timer: /usr/local/sbin/nixfort-agent-rollback <snapshot_id>.
Started by systemd (as root) only; validates its single argument."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nixfort_agent.rollback_main import main  # noqa: E402

sys.exit(main(sys.argv[1:]))
