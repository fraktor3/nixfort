"""URLs of the job pages."""

from django.urls import path

from . import views

app_name = "execution"
urlpatterns = [
    path("projects/<uuid:project_id>/jobs/", views.job_list, name="job_list"),
    path("projects/<uuid:project_id>/jobs/<uuid:job_id>/", views.job_detail, name="job_detail"),
    path("projects/<uuid:project_id>/jobs/noop/", views.noop_create, name="noop_create"),
]
