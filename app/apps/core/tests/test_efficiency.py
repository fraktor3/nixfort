"""Request-level efficiency: permissions are read once per request, pages stay within a query budget."""

import pytest
from django.urls import reverse

from apps.accounts.models import RoleAssignment
from apps.core.rbac import Perm, has_perm, roles_of


@pytest.mark.django_db
def test_roles_cache_lives_only_for_one_request(client_as, viewer, project):
    c = client_as(viewer)
    url = reverse("inventory:project_detail", args=[project.id])
    assert c.get(url).status_code == 200
    RoleAssignment.objects.filter(user=viewer).delete()
    assert c.get(url).status_code == 404  # the next request reads the roles again


@pytest.mark.django_db
def test_roles_cache_is_used_when_present(viewer, project, django_assert_num_queries):
    viewer._request_roles = {}
    assert has_perm(viewer, Perm.VIEW_PROJECT, project)
    with django_assert_num_queries(0):
        assert has_perm(viewer, Perm.VIEW_PROJECT, project)
        assert not has_perm(viewer, Perm.RUN_JOBS, project)
    del viewer._request_roles
    assert roles_of(viewer, project)  # without a request cache every call reads the database


@pytest.mark.django_db
def test_project_overview_query_budget(client_as, admin, project, lab_nodes, django_assert_max_num_queries):
    c = client_as(admin)
    c.get(reverse("core:dashboard"))  # warm the session
    with django_assert_max_num_queries(30):
        assert c.get(reverse("inventory:project_detail", args=[project.id])).status_code == 200
