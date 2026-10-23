from django.urls import path

from . import views

app_name = "policy"
urlpatterns = [
    path("projects/<uuid:project_id>/policy/", views.policy_overview, name="overview"),
    path("projects/<uuid:project_id>/policy/draft/", views.draft_create, name="draft_create"),
    path("projects/<uuid:project_id>/policy/flows/new/", views.flow_edit, name="flow_create"),
    path("projects/<uuid:project_id>/policy/flows/<uuid:flow_id>/", views.flow_edit, name="flow_edit"),
    path("projects/<uuid:project_id>/policy/flows/<uuid:flow_id>/delete/", views.flow_delete, name="flow_delete"),
    path("projects/<uuid:project_id>/policy/activate/", views.activate, name="activate"),
]
