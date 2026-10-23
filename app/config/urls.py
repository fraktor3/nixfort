from django.urls import include, path

urlpatterns = [
    path("", include("apps.core.urls")),
    path("accounts/", include("apps.accounts.urls")),
    path("projects/", include("apps.inventory.urls")),
    path("", include("apps.policy.urls")),
    path("", include("apps.execution.urls")),
    path("", include("apps.checks.urls")),
    path("", include("apps.remediation.urls")),
]
