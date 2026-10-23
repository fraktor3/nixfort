import base64

import pytest
from django.core.exceptions import ValidationError
from django.urls import reverse

from apps.core.models import Action, AuditEvent
from apps.core.rbac import Role
from apps.inventory import validators as v
from apps.inventory.models import HostKey, Node

pytestmark = pytest.mark.django_db

INJECTIONS = ["; rm -rf /", "$(id)", "`id`", "a|b", "a\nb", "../..", "10.0.0.1;id", "10.0.0.1/33", "\x00"]


@pytest.mark.parametrize("bad", INJECTIONS + ["8.8.8.0/24", "0.0.0.0/0", "10.0.0.1/24"])
def test_network_validator_rejects(bad):
    with pytest.raises(ValidationError):
        v.parse_network(bad)


@pytest.mark.parametrize("bad", INJECTIONS + ["256.1.1.1", "::1", ""])
def test_ipv4_validator_rejects(bad):
    with pytest.raises(ValidationError):
        v.parse_ipv4(bad)


@pytest.mark.parametrize("bad", INJECTIONS + ["", "x" * 65, "имя"])
def test_name_validator_rejects(bad):
    with pytest.raises(ValidationError):
        v.validate_name(bad)


def test_ports():
    assert v.parse_ports("22, 80 80;443") == [22, 80, 443]
    for bad in ("0", "65536", "22;id", "-1", "8o"):
        with pytest.raises(ValidationError):
            v.parse_ports(bad)


def _key(kt=b"ssh-ed25519"):
    blob = len(kt).to_bytes(4, "big") + kt + (32).to_bytes(4, "big") + b"\x01" * 32
    return base64.b64encode(blob).decode()


def test_hostkey_parse_and_fingerprint():
    import hashlib

    b64 = _key()
    kt, blob, fp = v.parse_hostkey_line(f"ssh-ed25519 {b64} root@nx-server")
    expected = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(b64)).digest()).decode().rstrip("=")
    assert (kt, fp) == ("ssh-ed25519", expected)
    with pytest.raises(ValidationError):
        v.parse_hostkey_line(f"ssh-ed25519 {_key(b'ssh-rsa')}")  # declared type != content
    for bad in ("", "ssh-dss AAAA", "ssh-ed25519 !!!", "ssh-ed25519"):
        with pytest.raises(ValidationError):
            v.parse_hostkey_line(bad)


def test_node_ip_must_be_inside_project(project):
    n = Node(project=project, name="out", mgmt_ip="192.168.1.5", roles=["server"])
    with pytest.raises(ValidationError):
        n.full_clean()


def test_ids_sensor_requires_interface(project):
    n = Node(project=project, name="ids", mgmt_ip="10.77.0.50", roles=["ids_sensor"])
    with pytest.raises(ValidationError):
        n.full_clean()


def test_project_create_via_form(client_as, operator):
    c = client_as(operator)
    r = c.post(
        reverse("inventory:project_create"),
        {"name": "Стенд", "description": "", "cidrs": "10.77.0.0/24, 10.88.0.0/24", "controller_ip": "10.77.0.10"},
    )
    assert r.status_code == 302
    assert AuditEvent.objects.filter(action=Action.PROJECT_CREATED).exists()


@pytest.mark.parametrize("cidrs", ["10.77.0.0/24; id", "8.8.8.0/24", "10.77.0.5/24", ""])
def test_project_form_rejects(client_as, operator, cidrs):
    r = client_as(operator).post(
        reverse("inventory:project_create"), {"name": "X", "cidrs": cidrs, "controller_ip": "10.77.0.10"}
    )
    assert r.status_code == 200  # form re-rendered with errors


def test_node_create_and_injection(client_as, operator, project):
    c = client_as(operator)
    url = reverse("inventory:node_create", args=[project.id])
    ok = c.post(
        url,
        {
            "name": "srv1",
            "mgmt_ip": "10.77.0.31",
            "ssh_port": 22,
            "expected_os": "ubuntu-24.04",
            "roles": ["server"],
            "data_ips": "10.99.0.11",
            "expected_tcp_ports": "22,80",
            "ids_interface": "",
        },
    )
    assert ok.status_code == 302
    n = Node.objects.get(name="srv1")
    assert n.data_ips == ["10.99.0.11"] and n.expected_tcp_ports == [22, 80] and n.status == "KEY_PENDING"
    for field, value in [
        ("name", "a;b"),
        ("mgmt_ip", "10.77.0.32;id"),
        ("data_ips", "$(id)"),
        ("expected_tcp_ports", "22;reboot"),
        ("ids_interface", "eth0;id"),
    ]:
        data = {
            "name": "srv2",
            "mgmt_ip": "10.77.0.32",
            "ssh_port": 22,
            "expected_os": "ubuntu-24.04",
            "roles": ["server", "ids_sensor"],
            "data_ips": "",
            "expected_tcp_ports": "",
            "ids_interface": "enp0s9",
        }
        data[field] = value
        assert c.post(url, data).status_code == 200, field
    assert not Node.objects.filter(name="srv2").exists()


def test_hostkey_confirm_only_admin(client_as, operator, admin, lab_nodes, project):
    node = lab_nodes["server"]
    c = client_as(operator)
    c.post(reverse("inventory:hostkey_set", args=[project.id, node.id]), {"public_key": f"ssh-ed25519 {_key()}"})
    assert HostKey.objects.filter(node=node, confirmed_at__isnull=True).exists()
    r = c.post(reverse("inventory:hostkey_confirm", args=[project.id, node.id]))
    assert r.status_code == 403
    client_as(admin).post(reverse("inventory:hostkey_confirm", args=[project.id, node.id]))
    node.refresh_from_db()
    assert node.status == "READY" and node.confirmed_hostkey is not None


def test_hostkey_change_resets_confirmation(client_as, admin, lab_nodes, project):
    node = lab_nodes["server"]
    c = client_as(admin)
    c.post(reverse("inventory:hostkey_set", args=[project.id, node.id]), {"public_key": f"ssh-ed25519 {_key()}"})
    c.post(reverse("inventory:hostkey_confirm", args=[project.id, node.id]))
    other = base64.b64encode(
        len(b"ssh-ed25519").to_bytes(4, "big") + b"ssh-ed25519" + b"\x00\x00\x00\x20" + b"\x02" * 32
    ).decode()
    c.post(reverse("inventory:hostkey_set", args=[project.id, node.id]), {"public_key": f"ssh-ed25519 {other}"})
    node.refresh_from_db()
    assert node.status == "KEY_PENDING" and node.confirmed_hostkey is None


def test_idor_other_project_is_404(client_as, make_user, project, other_project, lab_nodes):
    u = make_user("scoped", Role.ADMIN, project=other_project)
    c = client_as(u)
    node = lab_nodes["server"]
    for url in [
        reverse("inventory:project_detail", args=[project.id]),
        reverse("inventory:project_edit", args=[project.id]),
        reverse("inventory:node_detail", args=[project.id, node.id]),
        reverse("inventory:node_edit", args=[project.id, node.id]),
        reverse("policy:overview", args=[project.id]),
        reverse("execution:job_list", args=[project.id]),
    ]:
        assert c.get(url).status_code == 404, url
    # node of project A addressed through project B's URL
    assert c.get(reverse("inventory:node_detail", args=[other_project.id, node.id])).status_code == 404


def test_viewer_cannot_edit(client_as, viewer, project):
    c = client_as(viewer)
    assert c.get(reverse("inventory:project_detail", args=[project.id])).status_code == 200
    assert c.get(reverse("inventory:project_edit", args=[project.id])).status_code == 403
    assert c.get(reverse("inventory:node_create", args=[project.id])).status_code == 403


def test_archived_project_is_read_only(client_as, admin, project):
    c = client_as(admin)
    c.post(reverse("inventory:project_archive", args=[project.id]))
    assert c.get(reverse("inventory:project_detail", args=[project.id])).status_code == 200
    assert c.get(reverse("inventory:node_create", args=[project.id])).status_code == 403
