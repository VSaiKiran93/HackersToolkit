from django.urls import path, include
from django.views.generic.base import RedirectView
from .views import NmapScanView, test_nmap_middleware
from .middleware import NmapMiddleware

urlpatterns =[
     path('test/', test_nmap_middleware, name='test'),
     path('nmap-scan/', NmapScanView.as_view(), name='nmap'),
     #path('', NmapScanView.as_view(), name='nmap-scan-api'),
     #path('favicon.ico', favicon_view),
]

middleware_classes = [
    NmapMiddleware,
]
