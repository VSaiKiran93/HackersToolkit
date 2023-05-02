from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.urls import path, include
from django.views.generic.base import RedirectView
from . import views
from .views import NmapScanView

urlpatterns =[
     path('', NmapScanView.as_view(), name='nmap'),
     path('clean-sensor/', views.clean, name='clean'),
     path('create-target/<str:ipaddress>/', views.call_create_target, name='ipaddress'),
     path('create-task/<str:ipaddress>/<str:target_id>/', views.call_create_task, name='task'),
     path('start-scan/<str:task_id>/', views.call_start_scan, name='scan'),
     path('get-report/<str:report_id>/', views.get_report, name='report'),
]

