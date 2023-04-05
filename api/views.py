from rest_framework.views import APIView
from rest_framework.response import Response
import subprocess
import re
#Create your views here
#from django.conf import settings
#from rest_framework.parsers import JSONParser

#from .middleware import NmapMiddleware


class NmapScanView(APIView):
    def post(self, request):
        ip = request.data['ip']
        scan_type = request.data['scan_type']
        #port_range = request.data['port_range']
        if scan_type == 'Quick Scan':
            cmd = f'nmap -T4 -F {ip}'
        elif scan_type == 'Full Scan':
            cmd = f'sudo nmap -T4 -A -v {ip}'
        elif scan_type == 'TCP Syn Scan' or 'Stealth Scan':
            cmd = f'sudo nmap -sS {ip}'
        elif scan_type == 'Intense Scan':
            cmd = f'sudo nmap -T4 -A -v -Pn {ip}'
        elif scan_type == 'Intense Scan with UDP':
            cmd = f'sudo nmap -sS -sU -T4 -A -v {ip}'
        elif scan_type == 'Top-Ports':
            cmd = f'sudo nmap -T4 -A -v --top-ports 100 {ip}'
        elif scan_type == 'Version':
            cmd = f'sudo nmap -sV -T4 -O -F --version-light {ip}'
        elif scan_type == 'OS-Detection':
            cmd = f'sudo nmap -O {ip}'
        elif scan_type == 'ping-scan':
            cmd = f'sudo nmap -sn {ip}'
        else:
            return Response({'error': f'Scan type "{scan_type}" not supported.'}, status=400)

        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            output = result.stdout
        else:
            output = result.stderr

        # Parse Nmap output and categorize results by host and service
        host_results = {}
        lines = output.split('\n')
        current_host = None
        for line in lines:
            if 'Nmap scan report for' in line:
                current_host = line.split(' ')[4]
                if current_host not in host_results:
                    host_results[current_host] = {}
            elif 'tcp' in line and 'open' in line:
                port = line.split('/')[0]
                service = line.split()[2]
                if service not in host_results[current_host]:
                    host_results[current_host][service] = []
                host_results[current_host][service].append(port)


    # Generate detailed report
        report = []
        for host, services in host_results.items():
            host_report = {'host': host, 'services': []}
            for service, ports in services.items():
                service_report = {'name': service, 'ports': ports}
                host_report['services'].append(service_report)
            report.append(host_report)
        
        return Response({'scan_type': scan_type, 'scan_results': report})
