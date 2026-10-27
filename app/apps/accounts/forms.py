from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

from apps.core.rbac import Role
from apps.inventory.models import Project

USERNAME_RE = r"^[A-Za-z0-9._-]{3,64}$"


class UserCreateForm(forms.Form):
    username = forms.RegexField(regex=USERNAME_RE, label="Логин", max_length=64)
    password1 = forms.CharField(label="Пароль", widget=forms.PasswordInput, strip=False)
    password2 = forms.CharField(label="Пароль ещё раз", widget=forms.PasswordInput, strip=False)
    role = forms.ChoiceField(label="Роль", choices=Role.choices)
    project = forms.ModelChoiceField(
        label="Проект (если не выбран, роль действует во всех проектах)", queryset=Project.objects.all(), required=False
    )

    def clean_username(self):
        u = self.cleaned_data["username"]
        if get_user_model().objects.filter(username__iexact=u).exists():
            raise forms.ValidationError("Логин занят.")
        return u

    def clean(self):
        data = super().clean()
        p1, p2 = data.get("password1"), data.get("password2")
        if p1 and p1 != p2:
            self.add_error("password2", "Пароли не совпадают.")
        elif p1:
            try:
                validate_password(p1, get_user_model()(username=data.get("username", "")))
            except forms.ValidationError as exc:
                self.add_error("password1", exc)
        return data


class RoleAssignForm(forms.Form):
    role = forms.ChoiceField(label="Роль", choices=Role.choices)
    project = forms.ModelChoiceField(
        label="Проект (если не выбран, во всех проектах)", queryset=Project.objects.all(), required=False
    )
