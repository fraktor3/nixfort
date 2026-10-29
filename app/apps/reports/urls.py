"""URLs of the report pages and downloads."""

from django.urls import path

from . import views

app_name = "reports"
urlpatterns = [
    path("projects/<uuid:project_id>/reports/", views.report_list, name="list"),
    path("projects/<uuid:project_id>/reports/new/", views.report_create, name="create"),
    path("projects/<uuid:project_id>/reports/<uuid:report_id>/", views.report_detail, name="detail"),
    path(
        "projects/<uuid:project_id>/reports/<uuid:report_id>/download/<str:fmt>/",
        views.report_download,
        name="download",
    ),
]
