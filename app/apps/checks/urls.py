from django.urls import path

from . import views

app_name = "checks"
urlpatterns = [
    path("projects/<uuid:project_id>/audit/", views.run_list, name="run_list"),
    path("projects/<uuid:project_id>/audit/start/", views.run_start, name="run_start"),
    path("projects/<uuid:project_id>/audit/<uuid:run_id>/", views.run_detail, name="run_detail"),
    path(
        "projects/<uuid:project_id>/audit/<uuid:run_id>/results/<uuid:result_id>/",
        views.result_detail,
        name="result_detail",
    ),
]
