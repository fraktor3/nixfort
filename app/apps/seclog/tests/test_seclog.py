"""Security-log summary: aggregates SSH auth failures + Fail2ban bans (agent) and IDS alerts (DB)."""

import pytest
from django.urls import reverse
from django.utils import timezone

from apps.execution.agent_client import AgentResponse
from apps.execution.models import Job, JobState, JobType
from apps.ids.models import IdsEvent
from apps.inventory.models import HostKey
from apps.seclog import services
from apps.seclog.models import SecuritySummary

pytestmark = pytest.mark.django_db(transaction=True)


class Server:
    def __init__(self, reachable=True):
        self.reachable = reachable

    def call(self, action, params=None, deadline_s=60):
        if not self.reachable:
            return AgentResponse(action=action, state="TRANSPORT_ERROR", error_code="timeout")
        if action == "system.read_auth_failures.v1":
            return AgentResponse(
                action=action,
                state="OK",
                result={
                    "total": 9,
                    "window_hours": params["hours"],
                    "by_source": [{"ip": "10.88.0.10", "count": 7}, {"ip": "10.88.0.11", "count": 2}],
                    "by_user": [{"value": "root", "count": 5}, {"value": "admin", "count": 4}],
                },
            )
        if action == "fail2ban.read_status.v1":
            return AgentResponse(
                action=action,
                state="OK",
                result={
                    "service": "active",
                    "sshd": {"enabled": True, "banned_ips": ["10.88.0.10"], "currently_banned": 1, "total_banned": 3},
                },
            )
        raise AssertionError(action)


@pytest.fixture
def server(project, lab_nodes, admin):
    n = lab_nodes["server"]
    HostKey.objects.create(node=n, key_type="ssh-ed25519", public_key="AAAA", fingerprint_sha256="x",
                           confirmed_by=admin, confirmed_at=timezone.now())  # fmt: skip
    return n


def test_summary_aggregates(client_as, admin, operator, project, server, monkeypatch):
    IdsEvent.objects.create(project=project, node=server, ts=timezone.now(), event_type="alert",
                            signature_id=9000003, signature="NIXFORT SSH brute force", src_ip="10.88.0.10")  # fmt: skip
    monkeypatch.setattr(services, "client_for", lambda node: Server())
    r = client_as(operator).post(reverse("seclog:refresh", args=[project.id]))
    assert r.status_code == 302
    job = Job.objects.get(type=JobType.SECURITY_LOGS)
    assert job.state == JobState.SUCCEEDED
    s = SecuritySummary.objects.get()
    row = next(x for x in s.data["servers"] if x["node"] == "nx-server")
    assert row["auth"]["total"] == 9 and row["fail2ban"]["banned_ips"] == ["10.88.0.10"]
    assert s.data["ids"]["alerts"] == 1
    page = client_as(operator).get(reverse("seclog:seclog", args=[project.id])).content.decode()
    assert "Неудачные входы SSH" in page and "10.88.0.10" in page and "SSH brute force" in page


def test_unreachable_server_noted(client_as, operator, project, server, monkeypatch):
    monkeypatch.setattr(services, "client_for", lambda node: Server(reachable=False))
    client_as(operator).post(reverse("seclog:refresh", args=[project.id]))
    s = SecuritySummary.objects.get()
    assert s.data["servers"][0]["reachable"] is False


def test_viewer_cannot_refresh(client_as, viewer, project, server):
    assert client_as(viewer).post(reverse("seclog:refresh", args=[project.id])).status_code == 403
    assert client_as(viewer).get(reverse("seclog:seclog", args=[project.id])).status_code == 200
