from django.urls import path
from .views import NmapScanView

urlpatterns =[
     #path('command_output/<str:target_ip>/', views.execute_command),
     path('api/nmap-scan/', NmapScanView.as_view(), name='nmap-scan-api'),
]
