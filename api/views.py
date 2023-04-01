import subprocess
from django.shortcuts import render
from rest_framework.views import APIView
from django.http import JsonResponse
from django.views import View
from rest_framework import status
from rest_framework.response import Response
from .serializers import NmapScanSerializer
#from django.views.decorators.csrf import csrf_exempt

#Create your views here

#@csrf_exempt
#def execute_command(request, target_ip):
#    result = subprocess.check_output(['sudo','nmap','-sS', target_ip])
#    return HttpResponse(result.decode('utf-8'))

class NmapScanView(APIView):

    #post method to post input parameters
    def post(self, request, format=None):

        serializer = NmapScanSerializer(data=request.data)

        #give the input parameters using request
        if serializer.valid():
            ip_address = request.data.get('ip_address')
            port_range = request.data.get('port_range')
            scan_type = request.data.get('scan_type')

            cmd = ['nmap', '-{0}'.format(scan_type), '-p', port_range, ip_address]
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = p.communicate()
            return Response({'output': out}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            #Scan the target using nmap by calling the function nmap_scan below
            #scan_report = self.nmap_scan(ip_address, port_range, scan_type)

            #Parse the scan report and create a Json response
            #parsed_report = {"scan_report": scan_report}
            #return Response(parsed_report, status=200)

    #created an API to scan using nmap command which takes the imput parameters using post method
    #def nmap_scan(self, ip_address, port_range, scan_type):
        #command = ["nmap", "-sS" + scan_type, "-p", port_range, ip_address]
        #result = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #output, error = p.communicate()
        #return Response(output.decode('utf-8'))



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

