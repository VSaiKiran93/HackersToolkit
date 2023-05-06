from rest_framework.views import APIView
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.http import HttpResponse
from django.http import FileResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.core.handlers.wsgi import WSGIRequest
from django.conf import settings
import datetime
from pathlib import Path
import time
import subprocess
import requests
import sys
import io
import re
import gvm
import json
from base64 import b64decode
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import *
from gvmtools.helper import pretty_print as pretty
from gvm.xml import pretty_print
import xml.etree.ElementTree as ET
import paramiko

# Create your views here
path = '/run/gvmd/gvmd.sock'

connection = UnixSocketConnection(path=path)
#connection = SSHConnection(hostname= 'localhost', port=2222, username='azureuser', password=None )

def clean_sensor(gmp: Gmp) -> None:
    tasks = gmp.get_tasks(
        filter_string="rows=-1 not status=Running and "
        "not status=Requested and not "
        "status=&quot;Stop Requested&quot;"
    )

    for task_id in tasks.xpath("task/@id"):
        print(f"Removing task {task_id} ... ")
        status_text = gmp.delete_task(task_id, ultimate=True).xpath(
            "@status_text"
        )[0]
        print(status_text)

    targets = gmp.get_targets(filter_string="rows=-1 not _owner=&quot;&quot;")
    for target_id in targets.xpath("target/@id"):
        print(f"Removing target {target_id} ... ")
        status_text = gmp.delete_target(target_id, ultimate=True).xpath(
            "@status_text"
        )[0]
        print(status_text)

    configs = gmp.get_scan_configs(
        filter_string="rows=-1 not _owner=&quot;&quot;"
    )
    for config_id in configs.xpath("config/@id"):
        print(f"Removing config {config_id} ... ")
        status_text = gmp.delete_scan_config(config_id, ultimate=True).xpath(
            "@status_text"
        )[0]
        print(status_text)

    port_lists = gmp.get_port_lists(
        filter_string="rows=-1 not _owner=&quot;&quot;"
    )
    for port_list_id in port_lists.xpath("port_list/@id"):
        print(f"Removing port_list {port_list_id} ... ")
        status_text = gmp.delete_port_list(port_list_id, ultimate=True).xpath(
            "@status_text"
        )[0]
        print(status_text)

    credentials = gmp.get_credentials(
        filter_string="rows=-1 not _owner=&quot;&quot;"
    )
    for config_id in credentials.xpath("credential/@id"):
        print(f"Removing credential {config_id} ... ")
        status_text = gmp.delete_credential(config_id, ultimate=True).xpath(
            "@status_text"
        )[0]
        print(status_text)

    print("Emptying trash... ")
    status_text = gmp.empty_trashcan().xpath("@status_text")[0]
    print(status_text)

def create_target(gmp, ipaddress, port_list_id):
    import datetime
    # create a unique name by adding the current datetime
    name = f"Suspect Host {ipaddress} {str(datetime.datetime.now())}"
    response = gmp.create_target(name=name, hosts=[ipaddress], port_list_id=port_list_id)
    print(response)
    x = ET.fromstring(response)
    id = x.get('id')
    return id

def create_task(gmp, ipaddress, target_id, scan_config_id, scanner_id):
    name = f"Scan Suspect Host {ipaddress}"
    response = gmp.create_task(name=name, config_id=scan_config_id, target_id=target_id, scanner_id=scanner_id,)
    print(response)
    x = ET.fromstring(response)
    id = x.get('id')
    return id

def start_task(gmp, task_id):
    response = gmp.start_task(task_id)
    # the response is <start_task_response><report_id>id</report_id></start_task_response>
    x = ET.fromstring(response)
    id = x[0].text
    return id


with Gmp(connection=connection) as gmp:

    def authenticate():
        gmp.authenticate(username='admin', password='7571c6a3-bb88-485a-81f6-fafb205a184b')

    @require_http_methods(["GET"])
    @csrf_exempt
    def clean(request):
        authenticate()
        return HttpResponse(clean_sensor(gmp))

    @require_http_methods(["GET"])
    @csrf_exempt
    def default_call(request):
        authenticate()
        return HttpResponse(gmp.authenticate(username="admin", password="7571c6a3-bb88-485a-81f6-fafb205a184b"))

    @require_http_methods(["GET"])
    @csrf_exempt
    def call_create_target(request, ipaddress):
        authenticate()
        target_id = create_target(gmp, ipaddress, port_list_id='4a4717fe-57d2-11e1-9a26-406186ea4fc5')
        result = {"target_id": target_id}
        target = json.dumps(result)
        return HttpResponse(target)

    @require_http_methods(["GET"])
    @csrf_exempt
    def call_create_task(request,ipaddress, target_id):
        authenticate()
        print(target_id, request)
        full_and_fast_scan_config_id = "daba56c8-73ec-11df-a475-002264764cea"
        openvas_scanner_id = "08b69003-5fc2-4037-a479-93b440211c73"
        task_id = create_task(gmp, ipaddress, target_id, full_and_fast_scan_config_id, openvas_scanner_id)
        result = {"task_id": task_id}
        task = json.dumps(result)
        return HttpResponse(task)

    @require_http_methods(["GET"])
    @csrf_exempt
    def call_start_scan(request, task_id):
        authenticate()
        report_id = start_task(gmp, task_id)
        result = {"report_id": report_id}
        report = json.dumps(result)
        return HttpResponse(report)

    @require_http_methods(["GET"])
    @csrf_exempt
    def get_report(request, report_id):
        authenticate()
        plain_report_format_id = 'a3810a62-1f62-11e1-9219-406186ea4fc5'
        print("report call")
        xml_response = gmp.get_report(report_id=report_id, report_format_id=plain_report_format_id)
        root = ET.fromstring(xml_response)
        report_element = root[0]
        #get the  full content of report element
        content = report_element.find("report_format").tail
        binary_base64_plain =  content.encode('ascii')
        binary_plain = b64decode(binary_base64_plain)
        json_response = binary_plain.decode('utf-8')
        print(json_response)
        response = HttpResponse(json_response, content_type='text/html')
        print(response)
        return response


class NmapScanView(APIView):

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

        # SSH connection part
        ssh= paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        pkey = paramiko.RSAKey.from_private_key_file("/root/.ssh/id_rsa")
        ssh.connect(hostname="74.235.112.174",username="root",pkey=pkey, look_for_keys=False, allow_agent=False)
        stdin, stdout, stderr = ssh.exec_command(cmd)
        result=stdout.read().decode()
        ssh.close()
        print("Results"+result)

        # Format output as JSON
        output = result
        output_list = output.split('\n')

        return Response(output_list)




