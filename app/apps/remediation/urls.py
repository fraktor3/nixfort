"""URLs of the remediation pages."""

from django.urls import path

from . import views

app_name = "remediation"
urlpatterns = [
    path("projects/<uuid:project_id>/plans/", views.plan_list, name="plan_list"),
    path("projects/<uuid:project_id>/audit/<uuid:run_id>/plan/", views.plan_create, name="plan_create"),
    path("projects/<uuid:project_id>/plans/<uuid:plan_id>/", views.plan_detail, name="plan_detail"),
    path("projects/<uuid:project_id>/plans/<uuid:plan_id>/approve/", views.plan_approve, name="plan_approve"),
    path("projects/<uuid:project_id>/plans/<uuid:plan_id>/reject/", views.plan_reject, name="plan_reject"),
]
