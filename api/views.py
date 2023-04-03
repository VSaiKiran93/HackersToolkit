from django.shortcuts import render
from django.views import View
#from rest_framework.views import APIView
from django.http import JsonResponse
from django.http import HttpResponse
#from rest_framework import status
#from rest_framework.response import Response
import subprocess
from .serializers import NmapScanSerializer
from django.views.decorators.csrf import csrf_exempt
from .middleware import NmapMiddleware
from django.utils.decorators import method_decorator

#Create your views here

#@csrf_exempt
#def execute_command(request, target_ip):
#    result = subprocess.check_output(['sudo','nmap','-sS', target_ip])
#    return HttpResponse(result.decode('utf-8'))

def test_nmap_middleware(request):
    scan_type = 'ping'
    port_range = '1-9000'
    ip_address = 'localhost'

    middleware = NmapMiddleware(get_response=None)
    middleware.process_view(request=request, view_func=None, view_args=None, view_kwargs=None)

    if hasattr(request, 'nmap_output'):
        output = request.nmap_output
    else:
        output = 'Nmap Scan Failed'


    return JsonResponse({'output': output}, status=200)

class NmapScanView(View):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.middleware = NmapMiddleware(get_response=None)

    # Allow CSRF exemption for the post request method
    # Method decorator function is provided by Django's library to apply a decorator to class method
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    #Get method to render the HTML template on GET request
    def get(self, request):
        return render(request, 'index.html')

    #Post method to handle form submission for input parameters
    def post(self, request, format=None):
        serializer = NmapScanSerializer(data=request.POST)

        #give the input parameters using request
        if serializer.is_valid():
            ip_address = serializer.validated_data['ip_address']
            port_range = serializer.validated_data['port_range']
            scan_type = serializer.validated_data['scan_type']

            # Mapping of scan types to nmap commands
            commands = {
                'Intense scan': 'nmap -T4 -A -v',
                'Intense scan with UDP': 'nmap -sS -sU -T4 -A -v',
                'Intense scan, all TCP ports': 'nmap -p 1-65535 -T4 -A -v',
                'Intense scan, no ping': 'nmap -T4 -A -v -Pn',
                'Ping scan': 'nmap -sn',
                'Quick scan': 'nmap -T4 -F',
                'Quick scan plus': 'nmap -sV -T4 -O -F --version-light',
                'Quick traceroute': 'nmap -sn --traceroute',
                'Regular scan': 'nmap',
                'Slow comprehensive scan': 'nmap -sS -sU -T4 -A -v -PE -PS80,443 -PA3389 -PP -PU40125 -PY'
            }

            if scan_type in commands:
                cmd = commands[scan_type].split()
                cmd += ['-p', port_range, ip_address]
                output = self.middleware.execute(cmd)
                return JsonResponse({'output': output}, status=status.HTTP_200_OK)

            else:
                return JsonResponse({'error': 'Invalid scan type'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

