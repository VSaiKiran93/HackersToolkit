from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.urls import path, include
from django.views.generic.base import RedirectView
from .views import NmapScanView, vulnerability_scan

urlpatterns =[
     path('', NmapScanView.as_view(), name='nmap'),
     path('openvas-scan/<str:ip_address>/', vulnerability_scan, name='vulnerability_scan'),
]

