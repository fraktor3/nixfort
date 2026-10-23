"""Forms. List-valued model fields (JSON) are edited as text; the form field has the SAME name as
the model field so that model-level validation errors are shown next to the right input."""

from django import forms
from django.core.exceptions import ValidationError

from . import validators as v
from .models import Node, Project


class ProjectForm(forms.ModelForm):
    cidrs = forms.CharField(
        label="Подсети (через запятую или пробел)",
        max_length=500,
        help_text="Например: 10.77.0.0/24, 10.88.0.0/24, 10.99.0.0/24",
    )

    class Meta:
        model = Project
        fields = ["name", "description", "cidrs", "controller_ip"]
        widgets = {"description": forms.Textarea(attrs={"rows": 3})}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.initial["cidrs"] = ", ".join(self.instance.cidrs)

    def clean_name(self):
        name = self.cleaned_data["name"].strip()
        if not name or any(ord(c) < 32 for c in name):
            raise ValidationError("Некорректное название.")
        return name

    def clean_cidrs(self):
        items = v.split_list(self.cleaned_data["cidrs"])
        if not 1 <= len(items) <= 16:
            raise ValidationError("Укажите от 1 до 16 подсетей.")
        return [v.parse_network(i) for i in items]


ROLE_LABELS = {
    "gateway": "Шлюз (nftables)",
    "server": "Сервер (SSH, Fail2ban)",
    "ids_sensor": "Датчик IDS (Suricata)",
    "test_client": "Тестовый клиент (пробы соединений)",
}


class NodeForm(forms.ModelForm):
    data_ips = forms.CharField(label="Рабочие IP (через запятую)", required=False, max_length=200)
    roles = forms.MultipleChoiceField(
        label="Роли",
        choices=[(r, ROLE_LABELS[r]) for r in v.NODE_ROLES],
        widget=forms.CheckboxSelectMultiple(attrs={"class": "form-check-input"}),
    )
    expected_tcp_ports = forms.CharField(label="Ожидаемые TCP-порты (через запятую)", required=False, max_length=400)

    class Meta:
        model = Node
        fields = [
            "name",
            "mgmt_ip",
            "data_ips",
            "ssh_port",
            "roles",
            "expected_os",
            "expected_tcp_ports",
            "ids_interface",
        ]

    def __init__(self, *args, project=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.project = project or getattr(self.instance, "project", None)
        self.instance.project = self.project
        if self.instance.pk:
            self.initial["data_ips"] = ", ".join(self.instance.data_ips)
            self.initial["expected_tcp_ports"] = ", ".join(str(p) for p in self.instance.expected_tcp_ports)

    def clean_data_ips(self):
        items = v.split_list(self.cleaned_data["data_ips"])
        if len(items) > 8:
            raise ValidationError("Не больше 8 адресов.")
        return [v.parse_ipv4(i) for i in items]

    def clean_roles(self):
        return list(self.cleaned_data["roles"])

    def clean_expected_tcp_ports(self):
        return v.parse_ports(self.cleaned_data["expected_tcp_ports"])

    def clean(self):
        data = super().clean()
        mgmt = data.get("mgmt_ip")
        if mgmt and self.project:
            dup = Node.objects.filter(project=self.project, mgmt_ip=mgmt).exclude(pk=self.instance.pk)
            if dup.exists():
                self.add_error("mgmt_ip", "Этот адрес уже у другого узла проекта.")
        return data


class HostKeyForm(forms.Form):
    public_key = forms.CharField(
        label="Открытый ключ узла",
        max_length=2000,
        widget=forms.Textarea(attrs={"rows": 3}),
        help_text="Строка из /etc/ssh/ssh_host_ed25519_key.pub на узле (получена доверенным способом).",
    )

    def clean_public_key(self):
        key_type, blob, fp = v.parse_hostkey_line(self.cleaned_data["public_key"])
        return {"key_type": key_type, "public_key": blob, "fingerprint_sha256": fp}
