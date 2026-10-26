from django.urls import path

from . import views

app_name = "pcap"
urlpatterns = [
    path("projects/<uuid:project_id>/pcap/", views.pcap_list, name="list"),
    path("projects/<uuid:project_id>/pcap/capture/", views.capture_start, name="capture"),
    path("projects/<uuid:project_id>/pcap/upload/", views.upload, name="upload"),
    path("projects/<uuid:project_id>/pcap/<uuid:pcap_id>/", views.pcap_detail, name="detail"),
    path("projects/<uuid:project_id>/pcap/<uuid:pcap_id>/download/", views.download, name="download"),
]
