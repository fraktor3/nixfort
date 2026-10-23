from django.conf import settings
from django.db import models

from apps.core.models import BaseModel
from apps.core.rbac import Role


class RoleAssignment(BaseModel):
    """Role of a user, either global (project is NULL) or inside one project."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="role_assignments")
    role = models.CharField(max_length=10, choices=Role.choices)
    project = models.ForeignKey("inventory.Project", null=True, blank=True, on_delete=models.CASCADE)
    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "project"], name="uniq_role_per_user_project"),
            models.UniqueConstraint(
                fields=["user"], condition=models.Q(project__isnull=True), name="uniq_global_role_per_user"
            ),
        ]

    def __str__(self) -> str:
        scope = self.project.name if self.project_id else "глобально"
        return f"{self.user} — {self.get_role_display()} ({scope})"
