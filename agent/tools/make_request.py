#!/usr/bin/env python3
"""Print a valid agent request (for manual testing on the lab).

Example (from nx-controller):
  python3 make_request.py system.collect_facts.v1 | ssh -i secrets/controller_ed25519 nixfort@10.77.0.30
  python3 make_request.py net.tcp_probe.v1 '{"targets":[{"ip":"10.99.0.10","port":80}],"timeout_ms":1000}' \
    | ssh -i secrets/controller_ed25519 nixfort@10.77.0.40
"""

import json
import sys
import uuid

if len(sys.argv) not in (2, 3):
    sys.exit(__doc__)
print(
    json.dumps(
        {
            "protocol": "nixfort.agent/1",
            "request_id": str(uuid.uuid4()),
            "action": sys.argv[1],
            "params": json.loads(sys.argv[2]) if len(sys.argv) == 3 else {},
            "deadline_s": 120,
        }
    )
)
