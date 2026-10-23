"""NIXFORT node agent.

Runs on a managed node as root via SSH forced command. Reads exactly one JSON
request from stdin, executes one allowlisted action, writes one JSON response
to stdout. Standard library only (portability to Astra Linux / Debian).
"""

AGENT_VERSION = "1.2.0"
PROTOCOL = "nixfort.agent/1"
