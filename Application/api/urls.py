from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.urls import path, include
from django.views.generic.base import RedirectView
from . import views
from .views import NmapScanView

urlpatterns =[
     path('', NmapScanView.as_view(), name='nmap'),
     path('create-target/<str:ipaddress>/', views.call_create_target, name='ipaddress'),
     path('create-task/', views.call_create_task, name='task'),
     path('start-scan/', views.call_start_scan, name='scan'),
     path('get-report/', views.get_report, name='report'),
]

