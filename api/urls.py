from django.urls import path, include
from django.views.generic.base import RedirectView
from .views import NmapScanView
#from .middleware import NmapMiddleware

urlpatterns =[
     #path('test/', test_nmap_middleware, name='test'),
     path('nmap-scan/', NmapScanView.as_view(), name='nmap'),
     #path('', NmapScanView.as_view(), name='nmap-scan-api'),
]

#middleware_classes = [
 #   NmapMiddleware,
#]
