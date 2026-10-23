import pytest
from django.core.exceptions import ValidationError
from django.urls import reverse

from apps.policy import services
from apps.policy.models import Flow, FlowPolicyVersion

pytestmark = pytest.mark.django_db


def flow(pv, nodes, **kw):
    data = dict(
        name="web",
        src_cidr="10.88.0.0/24",
        dst_node=nodes["server"],
        dst_ip="10.99.0.10",
        port=80,
        action="ALLOW",
        critical=True,
        probe_from=nodes["client"],
    )
    data.update(kw)
    f = Flow(policy_version=pv, **data)
    f.full_clean()
    f.save()
    return f


def test_lab_policy_and_activation(project, lab_nodes, admin):
    draft = services.get_or_create_draft(project, admin)
    flow(draft, lab_nodes)
    flow(draft, lab_nodes, name="extra", port=8080, action="DENY", critical=False)
    flow(draft, lab_nodes, name="ssh", port=22, action="DENY", critical=False)
    assert services.find_conflicts(draft) == []
    services.activate(draft, admin)
    assert FlowPolicyVersion.objects.get(project=project, status="ACTIVE").version == 1
    # New draft copies flows of the active version
    d2 = services.get_or_create_draft(project, admin)
    assert d2.version == 2 and d2.flows.count() == 3
    services.activate(d2, admin)
    assert FlowPolicyVersion.objects.filter(project=project, status="ACTIVE").count() == 1
    assert FlowPolicyVersion.objects.get(version=1).status == "SUPERSEDED"


def test_contradiction_blocks_activation(project, lab_nodes, admin):
    d = services.get_or_create_draft(project, admin)
    flow(d, lab_nodes)
    flow(d, lab_nodes, src_cidr="10.88.0.10", action="DENY")
    kinds = [c.kind for c in services.find_conflicts(d)]
    assert kinds == ["contradiction"]
    with pytest.raises(services.PolicyError):
        services.activate(d, admin)


def test_flow_validation(project, lab_nodes, admin):
    d = services.get_or_create_draft(project, admin)
    with pytest.raises(ValidationError):
        flow(d, lab_nodes, dst_ip="10.99.0.99")  # not an IP of dst node
    with pytest.raises(ValidationError):
        flow(d, lab_nodes, probe_from=lab_nodes["server"])  # not a test client
    with pytest.raises(ValidationError):
        flow(d, lab_nodes, src_cidr="10.77.0.0/24")  # probe node has no IP inside source -> unreliable test
    with pytest.raises(ValidationError):
        flow(d, lab_nodes, src_cidr="10.88.0.0/24;id")


def test_operator_cannot_activate(client_as, operator, project, lab_nodes):
    c = client_as(operator)
    c.post(reverse("policy:draft_create", args=[project.id]))
    r = c.post(reverse("policy:activate", args=[project.id]))
    assert r.status_code == 403


def test_flow_form_view(client_as, operator, project, lab_nodes):
    c = client_as(operator)
    r = c.post(
        reverse("policy:flow_create", args=[project.id]),
        {
            "name": "web",
            "src_cidr": "10.88.0.0/24",
            "dst_node": lab_nodes["server"].id,
            "dst_ip": "10.99.0.10",
            "port": 80,
            "action": "ALLOW",
            "critical": "on",
            "probe_from": lab_nodes["client"].id,
        },
    )
    assert r.status_code == 302
    assert Flow.objects.count() == 1
