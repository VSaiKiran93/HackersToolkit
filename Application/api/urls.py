from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.urls import path, include
from django.views.generic.base import RedirectView
from .views import NmapScanView

urlpatterns =[
     path('nmap-scan/', NmapScanView.as_view(), name='nmap'),
]

