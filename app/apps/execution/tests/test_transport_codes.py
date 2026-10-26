"""S-002: a wrong SSH port looked like «unreachable». Refused and unreachable are now different codes."""

import socket

import pytest

from apps.execution.transport import TRANSPORT_HINTS, TransportError, fetch_host_key


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_closed_port_is_connection_refused():
    with pytest.raises(TransportError) as e:
        fetch_host_key("127.0.0.1", _free_port(), timeout=2)
    assert e.value.code == "connection_refused"
    assert "порт SSH закрыт" in TRANSPORT_HINTS["connection_refused"]


def test_paramiko_connect_to_closed_port_is_connection_refused(tmp_path):
    """S-007 on the lab: Paramiko wraps the refusal in NoValidConnectionsError -> was reported as unreachable."""
    from apps.execution.transport import SSHTransport

    kp = tmp_path / "k"
    import subprocess

    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(kp)], check=True)
    host_pub = (tmp_path / "k.pub").read_text().split()
    t = SSHTransport(host="127.0.0.1", port=_free_port(), username="nixfort", key_path=str(kp),
                     host_key_type=host_pub[0], host_key_b64=host_pub[1], connect_timeout=3)  # fmt: skip
    with pytest.raises(TransportError) as e:
        t.exchange(b"{}", timeout_s=5, max_output=1000)
    assert e.value.code == "connection_refused"
