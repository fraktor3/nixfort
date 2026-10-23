"""Real SSH -> forced command -> agent round trip.

Runs only when NIXFORT_IT_SSH_PORT is set (a local sshd with the agent installed, see
docs/TESTING.md). On the lab, S-003 runs the same flow against nx-server.
"""

import os
import subprocess

import pytest
from django.utils import timezone

pytestmark = [pytest.mark.integration, pytest.mark.django_db(transaction=True)]

PORT = os.environ.get("NIXFORT_IT_SSH_PORT")
KEY = os.environ.get("NIXFORT_IT_KEY", "/tmp/it/ck")
skip = pytest.mark.skipif(not PORT, reason="NIXFORT_IT_SSH_PORT not set")


@pytest.fixture
def local_node(settings, admin):
    from apps.inventory.models import Node, Project

    settings.NIXFORT_CONTROLLER_KEY_PATH = KEY
    p = Project.objects.create(name="IT", cidrs=["127.0.0.0/8"], controller_ip="127.0.0.1")
    return Node.objects.create(
        project=p,
        name="local",
        mgmt_ip="127.0.0.1",
        ssh_port=int(PORT or 22),
        roles=["server", "gateway"],
        expected_tcp_ports=[int(PORT or 22)],
    )


@skip
def test_fetch_confirm_inventory_audit(local_node, admin):
    from apps.execution import services
    from apps.execution.models import JobState, JobType
    from apps.inventory.services import confirm_hostkey

    project = local_node.project
    job = services.create_job(JobType.FETCH_HOSTKEY, project, admin, node=local_node)
    job.refresh_from_db()
    assert job.state == JobState.SUCCEEDED, job.result
    real = subprocess.run(
        ["ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub"], capture_output=True, text=True, check=True
    ).stdout.split()[1]
    local_node.refresh_from_db()
    assert local_node.hostkey.fingerprint_sha256 == real  # what the admin compares on the node
    confirm_hostkey(local_node, admin)

    job = services.create_job(JobType.INVENTORY, project, admin, node=local_node)
    job.refresh_from_db()
    snap = local_node.snapshots.first()
    assert snap is not None and snap.facts["system"]["state"] == "OK", snap.facts if snap else job.result
    assert snap.facts["ssh"]["state"] == "OK"

    job = services.create_job(JobType.AUDIT, project, admin)
    job.refresh_from_db()
    assert job.audit_run.results.count() == 21


@skip
def test_wrong_host_key_is_rejected(local_node, admin):
    from apps.execution.agent_client import client_for
    from apps.inventory.models import HostKey

    HostKey.objects.create(
        node=local_node,
        key_type="ssh-ed25519",
        public_key="AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        fingerprint_sha256="SHA256:fake",
        confirmed_by=admin,
        confirmed_at=timezone.now(),
    )
    local_node.refresh_from_db()
    resp = client_for(local_node).call("system.ping.v1")
    assert resp.state == "TRANSPORT_ERROR" and resp.error_code in ("host_key_mismatch", "ssh_error")
