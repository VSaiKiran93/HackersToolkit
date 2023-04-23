from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.urls import path, include
from django.views.generic.base import RedirectView
from .views import NmapScanView, nikto_scan, shodan_vuln_scan
from . import views

urlpatterns =[
     path('', NmapScanView.as_view(), name='nmap'),
     path('nikto/', nikto_scan, name='nikto'),
     path('shodan/', shodan_vuln_scan, name='shodan_vuln_scan'),
     path('owasp-zap/', views.zap_scan, name='owasp-zap'),
     path('new_session/', views.new_session),
     path('spider_url/', views.spider_url),
     path('spider_status/', views.spider_status),
     path('scan_url/', views.scan_url),
     path('scan_status/', views.scan_status),
     path('generate_report/', views.generate_report),
     #path('openvas-scan/<str:ip_address>/', vulnerability_scan, name='vulnerability_scan'),
]

