from django.shortcuts import render
from rest_framework.views import APIView
from django.http import JsonResponse
from rest_framework import status
from rest_framework.response import Response
import subprocess
from .serializers import NmapScanSerializer
from django.views.decorators.csrf import csrf_exempt

#Create your views here

#@csrf_exempt
#def execute_command(request, target_ip):
#    result = subprocess.check_output(['sudo','nmap','-sS', target_ip])
#    return HttpResponse(result.decode('utf-8'))

class NmapScanView(APIView):

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
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = p.communicate()
                print(out)
                return JsonResponse({'output': out.decode('utf-8')}, status=status.HTTP_200_OK)
            else:
                print(err)
                return JsonResponse({'error': 'Invalid scan type'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    #Allow CSRF exemption for the post request method
    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)




#class NmapScanView(APIView):

    #Post Method to have an input ip address to scan
#    def post(self, request, scan_type):
#        #Validate the ip address which takes it as ipput to scan using get api
#        ip_address = request.data.get('ip_address')
#        if not ip_address:
#            return Response({'error': 'IP address is required'}, status=400)#

        #Scan using nmap.PortScanner() from  nmap library
#        nm = nmap.PortScanner()

        #execute type of nmap scan
#        if scan_type == 'comprehensive':
#            nm.scan(ip_address, arguments='-ON -sV -O -A')
#        elif scan_type == 'stealth':
#            nm.scan(ip_address, arguments='-p 1-65535 -sS -T4 -v')
#        elif scan_type == 'tcp_connect':
#            nm.scan(ip_address, arguments='-p 1-65535 -sT -T4 -v')
#        else:
#            return Response({'error': 'Invalid scan type'}, status=400
        #check for open ports using below code:
 #       open_ports =[]
 #       for host in nm.all_hosts():
 #           for proto in nm[host].all_protocols():
 #               lport = nm[host][proto].keys()
 #               for port in lport:
 #                   if nm[host][proto][port]['state'] == 'open':
 #                       open_ports.append(port)

        #store the scanned report obtained
 #       report = nm.scaninfo()
        #view the result
 #       result = {
 #           'ip_address': ip_address,
 #           'scan_type' : scan_type,
 #           'open_ports': open_ports,
 #           'scan_report': report
 #       }
 #       return Response(result, status=status.HTTP_200_OK)

