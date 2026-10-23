from django.urls import path

from . import views

app_name = "inventory"
urlpatterns = [
    path("", views.project_list, name="project_list"),
    path("new/", views.project_create, name="project_create"),
    path("<uuid:project_id>/", views.project_detail, name="project_detail"),
    path("<uuid:project_id>/edit/", views.project_edit, name="project_edit"),
    path("<uuid:project_id>/archive/", views.project_archive, name="project_archive"),
    path("<uuid:project_id>/nodes/new/", views.node_create, name="node_create"),
    path("<uuid:project_id>/nodes/<uuid:node_id>/", views.node_detail, name="node_detail"),
    path("<uuid:project_id>/nodes/<uuid:node_id>/edit/", views.node_edit, name="node_edit"),
    path("<uuid:project_id>/nodes/<uuid:node_id>/deactivate/", views.node_deactivate, name="node_deactivate"),
    path("<uuid:project_id>/nodes/<uuid:node_id>/hostkey/", views.hostkey_set, name="hostkey_set"),
    path("<uuid:project_id>/nodes/<uuid:node_id>/hostkey/confirm/", views.hostkey_confirm, name="hostkey_confirm"),
    path("<uuid:project_id>/inventory/", views.inventory_run, name="inventory_run"),
    path("<uuid:project_id>/nodes/<uuid:node_id>/inventory/", views.inventory_run, name="node_inventory_run"),
    path("<uuid:project_id>/nodes/<uuid:node_id>/hostkey/fetch/", views.hostkey_fetch, name="hostkey_fetch"),
    path("<uuid:project_id>/scans/", views.portscan_list, name="portscan_list"),
    path("<uuid:project_id>/scans/run/", views.portscan_run, name="portscan_run"),
]
