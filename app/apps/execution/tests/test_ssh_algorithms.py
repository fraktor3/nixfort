"""SHA-1 SSH signatures are refused (paramiko CVE-2026-44405), while RSA and Ed25519 node keys keep working:
a real handshake against an in-process SSH server for each key type."""

import socket
import threading

import paramiko
import pytest

from apps.execution.transport import DISABLED_ALGORITHMS, SSHTransport


class _Server(paramiko.ServerInterface):
    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "publickey"


def _serve(host_key, done, server_disabled=None):
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)

    def run():
        conn, _ = ls.accept()
        t = paramiko.Transport(conn, disabled_algorithms=server_disabled)
        t.add_server_key(host_key)
        try:
            t.start_server(server=_Server())
            done.wait(5)
        except (paramiko.SSHException, EOFError):
            pass
        finally:
            t.close()
            ls.close()

    threading.Thread(target=run, daemon=True).start()
    return ls.getsockname()[1]


def test_sha1_algorithms_are_disabled():
    assert "ssh-rsa" in DISABLED_ALGORITHMS["keys"] and "ssh-rsa" in DISABLED_ALGORITHMS["pubkeys"]
    assert "ssh-dss" in DISABLED_ALGORITHMS["keys"]


@pytest.mark.parametrize("make_key,expected", [
    (lambda: paramiko.RSAKey.generate(2048), {"rsa-sha2-512", "rsa-sha2-256"}),
    (lambda: paramiko.Ed25519Key.from_private_key_file(_ed25519_file()), {"ssh-ed25519"}),
])  # fmt: skip
def test_transport_connects_without_sha1(make_key, expected):
    host_key = make_key()
    key_path = _ed25519_file()  # the controller key
    done = threading.Event()
    port = _serve(host_key, done)
    tr = SSHTransport(host="127.0.0.1", port=port, username="nixfort", key_path=key_path,
                      host_key_type=host_key.get_name(), host_key_b64=host_key.get_base64(), connect_timeout=5)  # fmt: skip
    try:
        client = tr._client()
        assert client.get_transport().host_key_type in expected
        client.close()
    finally:
        done.set()


def test_server_offering_only_sha1_is_refused():
    """A node that can sign only with ssh-rsa (SHA-1) is not accepted, even with the right key."""
    from apps.execution.transport import TransportError

    host_key = paramiko.RSAKey.generate(2048)
    done = threading.Event()
    port = _serve(host_key, done, server_disabled={"keys": ["rsa-sha2-512", "rsa-sha2-256"]})
    tr = SSHTransport(host="127.0.0.1", port=port, username="nixfort", key_path=_ed25519_file(),
                      host_key_type="ssh-rsa", host_key_b64=host_key.get_base64(), connect_timeout=5)  # fmt: skip
    try:
        with pytest.raises(TransportError):
            tr._client()
    finally:
        done.set()


def _ed25519_file():
    """paramiko cannot generate Ed25519 keys itself: take one from ssh-keygen once per test run."""
    import shutil
    import subprocess  # noqa: S404
    import tempfile
    from pathlib import Path

    keygen = shutil.which("ssh-keygen")
    if not keygen:
        pytest.skip("ssh-keygen not available")
    path = Path(tempfile.mkdtemp()) / "k"
    subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(path)], check=True)  # noqa: S603
    return str(path)
