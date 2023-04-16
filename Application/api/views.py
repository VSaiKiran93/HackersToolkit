from django.views.generic import TemplateView
from rest_framework.views import APIView
from rest_framework.response import Response
import subprocess
import requests
import re
import sys
from gvm.connections import UnixSocketConnection
from gvm.errors import GvmError
from gvm.protocols.gmpv224 import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from gvm.xml import pretty_print
from django.http import HttpResponse
from django.core.handlers.wsgi import WSGIRequest
from django.views.decorators.http import require_GET
import xml.etree.ElementTree as et
import datetime
from base64 import b64decode
from pathlib import Path
from django.http import StreamingHttpResponse
import io
from django.views.decorators.csrf import csrf_exempt


# Create your views here
class NmapScanView(APIView):
    #template_name = 'index.html'
    #def get(self, request):

        #return render(request, 'index.html')
    VULNERS_API_KEY = 'FSEH2XXM92N7FZ67A4AZ64B4D31ZIT53C1ZA8CE64RPLFG6MSX1O630Z1F0B6COR'
    def post(self, request):
        ip = request.data['ip']
        scan_type = request.data['scan_type']
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
        elif scan_type == 'Ping-Scan':
            cmd = f'sudo nmap -sn {ip}'
        else:
            return Response({'error': f'Scan type "{scan_type}" not supported.'}, status=400)

        #execute the command in linux kernel using subprocess module
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        #output = result.stdout

        # Format output as JSON
        if result.returncode == 0:
            output = result.stdout
        else:
            output = ['An error occurred while scanning']

        vulnerabilities = self.nmap_vuln_scan(ip)
        return Response({'output': output, 'vulnerabilities': vulnerabilities})

    def nmap_vuln_scan(self, ip):
        nmap_command = f'nmap -sV --script vulners {ip}'
        output = subprocess.check_output(nmap_command.split())
        # parse the Nmap output to extract the vulnerabilities
        vulnerabilities = []
        for line in output.splitlines():
            if b'CVE' in line:
                vulnerabilities.append(line.decode())
        # pass the vulnerabilities to the Vulners API
        vulners_data = []
        for vulnerability in vulnerabilities:
            query = f'https://vulners.com/api/v3/search/published/?query={vulnerability}&apiKey={VULNERS_API_KEY}'
            response = requests.get(query)
            if response.status_code == 200:
                data = response.json()
                if data.get('data'):
                    for item in data['data']:
                        if item.get('description'):
                            vulners_data.append(item['description'])
                else:
                    vulners_data.append('No vulnerabilities found.')
            else:
                vulners_data.append('An error occured while scanning.')
        return vulners_data



#OpenVAS :
path = '/run/gvmd/gvmd.sock'
ip = ''

connection = UnixSocketConnection(path=path)

@require_GET
def clean(request):
    with Gmp(connection=connection) as gmp:
        gmp.authenticate(username='user',password='d0cf49a5-37fe-4cab-a8a0-726bd9638529')
        tasks = gmp.get_tasks(filter_string="rows=-1 not status=Running and not status=Requested and not status=&quot;Stop Requested&quot;")
        for task_id in tasks.xpath("task/@id"):
            print(f"Removing task {task_id} ... ")
            status_text = gmp.delete_task(task_id, ultimate=True).xpath("@status_text")[0]
            print(status_text)
        targets = gmp.get_targets(filter_string="rows=-1 not _owner=&quot;&quot;")
        for target_id in targets.xpath("target/@id"):
            print(f"Removing target {target_id} ... ")
            status_text = gmp.delete_target(target_id, ultimate=True).xpath("@status_text")[0]
            print(status_text)
        configs = gmp.get_scan_configs(filter_string="rows=-1 not _owner=&quot;&quot;")
        for config_id in configs.xpath("config/@id"):
            print(f"Removing config {config_id} ... ")
            status_text = gmp.delete_scan_config(config_id, ultimate=True).xpath("@status_text")[0]
            print(status_text)
        port_lists = gmp.get_port_lists(filter_string="rows=-1 not _owner=&quot;&quot;")
        for port_list_id in port_lists.xpath("port_list/@id"):
            print(f"Removing port_list {port_list_id} ... ")
            status_text = gmp.delete_port_list(port_list_id, ultimate=True).xpath("@status_text")[0]
            print(status_text)
        credentials = gmp.get_credentials(filter_string="rows=-1 not _owner=&quot;&quot;")
        for config_id in credentials.xpath("credential/@id"):
            print(f"Removing credential {config_id} ... ")
            status_text = gmp.delete_credential(config_id, ultimate=True).xpath("@status_text")[0]
            print(status_text)
        print("Emptying trash... ")
        status_text = gmp.empty_trashcan().xpath("@status_text")[0]
    return HttpResponse(status_text)

def create_target(gmp, ipaddress, port_list_id):
    name = f"Target {ipaddress}"
    xml_response = gmp.create_target(name=name,hosts=ipaddress, port_list_id=port_list_id)
    root = et.fromstring(xml_response)
    id = root.get('id')
    print(xml_response)
    return id


def create_task(gmp, ipaddress, target_id, scan_config_id, scanner_id):
    name = f"Scan Suspect Host {ipaddress}"
    xml_response = gmp.create_task(name=name,config_id=scan_config_id,target_id=target_id,scanner_id=scanner_id)
    root = et.fromstring(xml_response)
    id = root.get('id')
    print(xml_response)
    return id


def start_task(gmp, task_id):
    xml_response = gmp.start_task(task_id)
    root = et.fromstring(xml_response)
    print(xml_response)
    id = root[0].text
    return id

def get_report(request, gmp, task_id)
    xml_response = gmp.start_task(task_id)
    root = et.fromstring(xml_response)
    print(xml_response)
    return HttpResponse(xml_response)


@api_view(['GET'])
def clean(request):
    try:
        with Gmp(connection=request.connection) as gmp:
            gmp.authenticate(username='user',password='d0cf49a5-37fe-4cab-a8a0-726bd9638529')
            return Response({'response': clean_sensor(gmp)})
    except ConnectionError as e:
        return Response({'error': str(e)})


@api_view(['GET'])
def default_call(request):
    try:
        with Gmp(connection=request.connection) as gmp:
            gmp.authenticate(username="user",password="d0cf49a5-37fe-4cab-a8a0-726bd9638529")
            return Response({'response': 'Authenticated successfully'})
    except ConnectionError as e:
        return Response({'error': str(e)})


@api_view(['GET'])
def call_create_target(request, ipaddress):
    try:
        with Gmp(connection=request.connection) as gmp:
            gmp.authenticate(username='user',password='d0cf49a5-37fe-4cab-a8a0-726bd9638529')
            port_list_id = '4a4717fe-57d2-11e1-9a26-406186ea4fc5'
            target_id = create_target(gmp, ipaddress, port_list_id)
            return Response({"response": target_id})
    except ConnectionError as e:
        return Response({'error': str(e)})


@api_view(['GET'])
def call_create_task(request, ipaddress, target_id):
    try:
        with Gmp(connection=request.connection) as gmp:
            gmp.authenticate(username='user',password='d0cf49a5-37fe-4cab-a8a0-726bd9638529')
            full_and_fast_scan_config_id = "daba56c8-73ec-11df-a475-002264764cea"
            openvas_scanner_id = "08b69003-5fc2-4037-a479-93b440211c73"
            task_id = create_task(gmp, ipaddress, target_id, full_and_fast_scan_config_id, openvas_scanner_id)
            return Response({"response": task_id})
    except ConnectionError as e:
        return Response({'error': str(e)})
