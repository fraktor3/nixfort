"""Controller side of the node agent protocol (docs/NODE_AGENT_PROTOCOL.md).

The controller validates the action name before sending; the agent validates everything again.
Nothing here builds shell commands: the request is a JSON document written to the SSH channel.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from .transport import SSHTransport, TransportError

PROTOCOL = "nixfort.agent/1"
MAX_RESPONSE = 1024 * 1024

# Mirror of the agent registry. Unknown names are refused here, before any network I/O.
KNOWN_ACTIONS: dict[str, bool] = {  # name -> mutating
    "system.ping.v1": False,
    "system.collect_facts.v1": False,
    "system.collect_listeners.v1": False,
    "ssh.read_effective_config.v1": False,
    "fail2ban.read_status.v1": False,
    "nft.inspect.v1": False,
    "suricata.read_status.v1": False,
    "suricata.read_events.v1": False,
    "net.tcp_probe.v1": False,
    "net.send_ids_test.v1": False,
    "net.ssh_login_attempts.v1": False,
    "mutation.snapshot_status.v1": False,
    # mutating (only the remediation orchestrator, queue "mutation", may call these)
    "pkg.install_security_tool.v1": True,
    "fail2ban.apply_sshd_profile.v1": True,
    "fail2ban.unban.v1": True,
    "ssh.apply_hardening_profile.v1": True,
    "nft.apply_policy.v1": True,
    "suricata.apply_sensor_profile.v1": True,
    "mutation.commit.v1": True,
    "mutation.rollback_now.v1": True,
}

AGENT_STATES = ("OK", "FAILED", "REJECTED", "ERROR")


@dataclass
class AgentResponse:
    action: str
    state: str  # OK | FAILED | REJECTED | ERROR | TRANSPORT_ERROR | PROTOCOL_ERROR
    result: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None
    agent_version: str | None = None
    os_profile: str | None = None
    duration_ms: int | None = None

    @property
    def ok(self) -> bool:
        return self.state == "OK"

    def as_fact(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "result": self.result,
            "error_code": self.error_code,
            "agent_version": self.agent_version,
            "os_profile": self.os_profile,
        }


class AgentClient:
    def __init__(self, transport: SSHTransport):
        self.transport = transport

    def call(self, action: str, params: dict[str, Any] | None = None, deadline_s: int = 60) -> AgentResponse:
        if action not in KNOWN_ACTIONS:
            raise ValueError(f"action not allowed by controller: {action}")
        request_id = str(uuid.uuid4())
        body = json.dumps(
            {
                "protocol": PROTOCOL,
                "request_id": request_id,
                "action": action,
                "params": params or {},
                "deadline_s": int(deadline_s),
            },
            separators=(",", ":"),
        ).encode()
        try:
            raw = self.transport.exchange(body, timeout_s=deadline_s + 15, max_output=MAX_RESPONSE)
        except TransportError as exc:
            return AgentResponse(action=action, state="TRANSPORT_ERROR", error_code=exc.code)
        return parse_response(raw, action, request_id)


def parse_response(raw: bytes, action: str, request_id: str) -> AgentResponse:
    try:
        data = json.loads(raw.decode("utf-8").strip())
    except (UnicodeDecodeError, json.JSONDecodeError):
        return AgentResponse(action=action, state="PROTOCOL_ERROR", error_code="bad_json")
    if not isinstance(data, dict) or data.get("protocol") != PROTOCOL:
        return AgentResponse(action=action, state="PROTOCOL_ERROR", error_code="bad_envelope")
    # A response for another request (or action) is never trusted.
    if data.get("request_id") != request_id or data.get("action") != action:
        return AgentResponse(action=action, state="PROTOCOL_ERROR", error_code="response_mismatch")
    state = data.get("state")
    if state not in AGENT_STATES:
        return AgentResponse(action=action, state="PROTOCOL_ERROR", error_code="bad_state")
    result = data.get("result") if isinstance(data.get("result"), dict) else {}
    return AgentResponse(
        action=action,
        state=state,
        result=result,
        error_code=data.get("error_code") if isinstance(data.get("error_code"), str) else None,
        agent_version=str(data.get("agent_version"))[:20] if data.get("agent_version") else None,
        os_profile=str(data.get("os_profile"))[:20] if data.get("os_profile") else None,
        duration_ms=data.get("duration_ms") if isinstance(data.get("duration_ms"), int) else None,
    )


def client_for(node) -> AgentClient:
    """Agent client for a node with a confirmed host key. Raises TransportError otherwise."""
    from django.conf import settings

    hk = node.confirmed_hostkey
    if hk is None:
        raise TransportError("host_key_not_confirmed")
    return AgentClient(
        SSHTransport(
            host=node.mgmt_ip,
            port=node.ssh_port,
            username="nixfort",
            key_path=settings.NIXFORT_CONTROLLER_KEY_PATH,
            host_key_type=hk.key_type,
            host_key_b64=hk.public_key,
        )
    )
