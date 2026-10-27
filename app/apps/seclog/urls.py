from django.urls import path

from . import views

app_name = "seclog"
urlpatterns = [
    path("projects/<uuid:project_id>/seclog/", views.seclog, name="seclog"),
    path("projects/<uuid:project_id>/seclog/refresh/", views.refresh, name="refresh"),
]
