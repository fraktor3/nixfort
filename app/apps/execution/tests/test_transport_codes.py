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
