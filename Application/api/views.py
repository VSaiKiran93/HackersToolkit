from django.shortcuts import render
from django.views.generic import TemplateView
from rest_framework.views import APIView
from rest_framework.response import Response
import subprocess
from django.http import HttpResponse
from django.template import loader


# Create your views here
class NmapScanView(TemplateView):
    template_name = 'index.html'

    #def get(self, request):
        #return render(request, self.template_name)

    def post(self, request):
        print("payload....",request)
        ip = request.ip
        scan_type = request.scan_type
        print("API hit :"+ip+"  "+scan_type)

        #choose the scan type
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

        #execute the command in linux kernel using subprocess module
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        output = result.stdout

        # Format output as JSON
        if result.returncode == 0:
            output = result.stdout
            output_list = output.split('\n')
        else:
            output_list = ['An error occurred while scanning.']

        template = loader.get_template(self.template_nmae)
        context = {'output_list': output_list} 
        return HttpResponse(template.render(context, request))

