from django.urls import path

from . import views

app_name = "ids"
urlpatterns = [
    path("projects/<uuid:project_id>/ids/", views.sensor, name="sensor"),
    path("projects/<uuid:project_id>/ids/fetch/", views.fetch, name="fetch"),
    path("projects/<uuid:project_id>/protection/", views.protection, name="protection"),
    path("projects/<uuid:project_id>/protection/run/<str:scenario>/", views.protection_run, name="protection_run"),
    path("projects/<uuid:project_id>/protection/<uuid:test_id>/", views.protection_detail, name="protection_detail"),
]
