from django.urls import path, include
from django.views.generic.base import RedirectView
from .views import NmapScanView

#favicon_view = RedirectView.as_view(url='/static/favicon.ico', permanent=True),

urlpatterns =[
     #path('command_output/<str:target_ip>/', views.execute_command),
     # path('nmap-scan', NmapScanView.as_view()),
     path('', NmapScanView.as_view(), name='nmap-scan-api'),
     #path('favicon.ico', favicon_view),
]
