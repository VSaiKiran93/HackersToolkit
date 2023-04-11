from django.urls import path, include
#from django.views.generic.base import RedirectView
from .views import NmapScanView 

urlpatterns =[
     #path('', index, name='index'),
     path('nmap-scan/', NmapScanView.as_view(), name='nmap'),
]

