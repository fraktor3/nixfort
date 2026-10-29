"""Form of one policy flow."""

from django import forms

from apps.inventory.models import Node

from .models import Flow


class FlowForm(forms.ModelForm):
    class Meta:
        model = Flow
        fields = ["name", "src_cidr", "dst_node", "dst_ip", "port", "action", "critical", "probe_from"]

    def __init__(self, *args, project, policy_version, **kwargs):
        super().__init__(*args, **kwargs)
        self.instance.policy_version = policy_version
        nodes = Node.objects.filter(project=project, is_active=True)
        self.fields["dst_node"].queryset = nodes
        clients = [n.id for n in nodes if n.has_role("test_client")]
        self.fields["probe_from"].queryset = nodes.filter(id__in=clients)
        self.fields["src_cidr"].help_text = "Например 10.88.0.0/24 или 10.88.0.10"
