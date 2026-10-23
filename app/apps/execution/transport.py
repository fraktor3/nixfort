"""SSH transport to the node agent (Paramiko). Host keys are NEVER auto-accepted (SECURITY T3)."""

from __future__ import annotations

import base64
import socket
import time
from dataclasses import dataclass

import paramiko


class TransportError(Exception):
    """code: safe identifier shown to users and stored in jobs."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass
class SSHTransport:
    host: str
    port: int
    username: str
    key_path: str
    host_key_type: str
    host_key_b64: str
    connect_timeout: float = 10.0

    def _client(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            key = paramiko.PKey.from_type_string(self.host_key_type, base64.b64decode(self.host_key_b64))
        except Exception as exc:  # noqa: BLE001
            raise TransportError("bad_stored_host_key") from exc
        name = self.host if self.port == 22 else f"[{self.host}]:{self.port}"
        client.get_host_keys().add(name, self.host_key_type, key)
        try:
            pkey = paramiko.Ed25519Key.from_private_key_file(self.key_path)
        except (OSError, paramiko.SSHException) as exc:
            raise TransportError("controller_key_unavailable") from exc
        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                pkey=pkey,
                allow_agent=False,
                look_for_keys=False,
                timeout=self.connect_timeout,
                banner_timeout=self.connect_timeout,
                auth_timeout=self.connect_timeout,
            )
        except paramiko.BadHostKeyException as exc:
            raise TransportError("host_key_mismatch") from exc
        except paramiko.SSHException as exc:
            # RejectPolicy raises SSHException for an unknown key; authentication errors also land here.
            if isinstance(exc, paramiko.AuthenticationException):
                raise TransportError("auth_failed") from exc
            raise TransportError("ssh_error") from exc
        except TimeoutError as exc:
            raise TransportError("timeout") from exc
        except OSError as exc:
            raise TransportError("unreachable") from exc
        return client

    def exchange(self, payload: bytes, timeout_s: float, max_output: int) -> bytes:
        """Open a session (the forced command starts the agent), send payload, read the reply."""
        client = self._client()
        try:
            chan = client.get_transport().open_session(timeout=self.connect_timeout)
            chan.settimeout(timeout_s)
            chan.exec_command("nixfort-agent")  # ignored by the forced command, kept for logs
            chan.sendall(payload)
            chan.shutdown_write()
            out = bytearray()
            end = time.monotonic() + timeout_s
            while True:
                if time.monotonic() > end:
                    raise TransportError("timeout")
                try:
                    chunk = chan.recv(65536)
                except TimeoutError as exc:
                    raise TransportError("timeout") from exc
                if not chunk:
                    break
                out += chunk
                if len(out) > max_output:
                    raise TransportError("response_too_large")
            return bytes(out)
        except paramiko.SSHException as exc:
            raise TransportError("ssh_error") from exc
        finally:
            client.close()


def fetch_host_key(host: str, port: int, timeout: float = 10.0) -> tuple[str, str]:
    """Read the server host key WITHOUT authenticating. The result is only a candidate:
    an administrator must compare the fingerprint obtained through a trusted channel."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        raise TransportError("unreachable") from exc
    t = paramiko.Transport(sock)
    try:
        t.get_security_options().key_types = ["ssh-ed25519"]  # we pin ed25519 host keys
        t.start_client(timeout=timeout)
        key = t.get_remote_server_key()
        return key.get_name(), key.get_base64()
    except paramiko.SSHException as exc:
        raise TransportError("ssh_error") from exc
    finally:
        t.close()
