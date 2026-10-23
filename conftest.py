"""Shared pytest fixtures for controller tests."""

import pytest


@pytest.fixture
def make_user(db):
    from django.contrib.auth import get_user_model

    from apps.accounts.models import RoleAssignment

    def _make(username, role=None, project=None, password="Very-Strong-Pass-123"):  # noqa: S107
        user = get_user_model().objects.create_user(username=username, password=password)
        if role:
            RoleAssignment.objects.create(user=user, role=role, project=project)
        return user

    return _make


@pytest.fixture
def project(db):
    from apps.inventory.models import Project

    p = Project(name="Лаборатория", cidrs=["10.77.0.0/24", "10.88.0.0/24", "10.99.0.0/24"], controller_ip="10.77.0.10")
    p.full_clean()
    p.save()
    return p


@pytest.fixture
def other_project(db):
    from apps.inventory.models import Project

    return Project.objects.create(name="Чужой", cidrs=["192.168.50.0/24"], controller_ip="192.168.50.10")


@pytest.fixture
def lab_nodes(project):
    from apps.inventory.models import Node

    def mk(name, mgmt, data, roles, **kw):
        n = Node(project=project, name=name, mgmt_ip=mgmt, data_ips=data, roles=roles, **kw)
        n.full_clean()
        n.save()
        return n

    return {
        "gateway": mk(
            "nx-gateway",
            "10.77.0.20",
            ["10.88.0.1", "10.99.0.1"],
            ["gateway", "ids_sensor"],
            ids_interface="enp0s9",
            expected_tcp_ports=[22],
        ),
        "server": mk("nx-server", "10.77.0.30", ["10.99.0.10"], ["server"], expected_tcp_ports=[22, 80]),
        "client": mk("nx-client", "10.77.0.40", ["10.88.0.10"], ["test_client"], expected_tcp_ports=[22]),
    }


@pytest.fixture
def admin(make_user):
    from apps.core.rbac import Role

    return make_user("admin", Role.ADMIN)


@pytest.fixture
def operator(make_user):
    from apps.core.rbac import Role

    return make_user("operator", Role.OPERATOR)


@pytest.fixture
def viewer(make_user):
    from apps.core.rbac import Role

    return make_user("viewer", Role.VIEWER)


@pytest.fixture
def client_as(client):
    def _login(user):
        client.force_login(user, backend="django.contrib.auth.backends.ModelBackend")
        return client

    return _login
