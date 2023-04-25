from rest_framework.views import APIView
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.http import HttpResponse
from django.http import FileResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.core.handlers.wsgi import WSGIRequest
from django.conf import settings
import xml.etree.ElementTree as et
import datetime
from base64 import b64decode
from pathlib import Path
import time
import subprocess
import requests
import sys
import io
import re
import gvm
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import *
from gvm.xml import pretty_print 
import xml.etree.ElementTree as ET

# Create your views here
path = '/run/gvmd/gvmd.sock'

connection = UnixSocketConnection(path=path)

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
    task_id = x.get('id') 
    return id

def start_task(gmp, task_id):
    response = gmp.start_task(task_id)
    # the response is
    # <start_task_response><report_id>id</report_id></start_task_response>
    x = ET.fromstring(response)
    report_id = x[0].text
    return id


with Gmp(connection=connection) as gmp:

    def authenticate():
        gmp.authenticate(username='admin', password='a0c1f76a-7dbe-4a9b-a60a-12e691c197c0')

    @require_http_methods(["GET"])
    @csrf_exempt
    def clean(request):
        authenticate()
        return HttpResponse(clean_sensor(gmp))

    @require_http_methods(["GET"])
    @csrf_exempt
    def default_call(request):
        authenticate()
        return HttpResponse(gmp.authenticate(username="admin", password="a0c1f76a-7dbe-4a9b-a60a-12e691c197c0"))

    @require_http_methods(["GET"])
    @csrf_exempt
    def call_create_target(request, ipaddress):
        authenticate()
        target_id = create_target(gmp, ipaddress, port_list_id='4a4717fe-57d2-11e1-9a26-406186ea4fc5')
        return HttpResponse(target_id)

    @require_http_methods(["GET"])
    @csrf_exempt
    def call_create_task(request, ipaddress, target_id):
        authenticate()
        full_and_fast_scan_config_id = "daba56c8-73ec-11df-a475-002264764cea"
        openvas_scanner_id = "08b69003-5fc2-4037-a479-93b440211c73"
        task_id = create_task(gmp, ipaddress, target_id, full_and_fast_scan_config_id, openvas_scanner_id)
        return HttpResponse(task_id)

    @require_http_methods(["GET"])
    @csrf_exempt
    def call_start_scan(request, task_id):
        authenticate()
        report_id = start_task(gmp, task_id)
        return HttpResponse(report_id)

    @require_http_methods(["GET"])
    @csrf_exempt
    def get_report(report_id):
        authenticate()
        json_report_format_id = "c1645568-627a-4d4a-8c1f-5633a7c1f4db"
        json_response = gmp.get_report(report_id=report_id, report_format_id=json_report_format_id)
        pretty_json = json.dumps(json.loads(json_response), indent=4)
        # return the pretty-printed JSON content as an HTTP response with the appropriate content type
        response = HttpResponse(pretty_json, content_type='application/json')
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

        #execute the command in linux kernel using subprocess module
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        #output = result.stdout

        # Format output as JSON
        if result.returncode == 0:
            output = result.stdout
        else:
            output = ['An error occurred while scanning']

        #vulnerabilities = self.vulners_scan(ip)
        vulnerabilities = self.shodan_vuln_scan(ip)
        data = {"output": output, "vulnerabilities": vulnerabilities}
        return Response(data)


    def vulners_scan(self, ip):

        VULNERS_API_URL = "https://vulners.com/linux-scanner/apiscan"
        #Set the API parameters
        params = {
            "query": f"host:{ip} AND type: osvdb OR type: cve",
            "sort": "cvss.score"
        }

        headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
        }
        api_key = "FSEH2XXM92N7FZ67A4AZ64B4D31ZIT53C1ZA8CE64RPLFG6MSX1O630Z1F0B6COR" # Replace with your Vulners API key
        headers["X-Vulners-API-Key"] = api_key

        # Send the request to Vulners API
        response = requests.get(VULNERS_API_URL, headers=headers, params=params)

        # Parse the response and extract the vulnerability details
        if response.status_code == 200:
            data = response.json().get("data", {})
            vulnerabilities = []
            for item in data:
                vuln = {
                    "type": item.get("type"),
                    "id": item.get("id"),
                    "title": item.get("title"),
                    "description": item.get("description"),
                    "cvss": item.get("cvss", {}).get("score"),
                    "references": item.get("references"),
                    "published": item.get("published"),
                    "modified": item.get("modified"),
                    "software": item.get("software"),
                    "bulletinFamily": item.get("bulletinFamily"),
                }
                vulnerabilities.append(vuln)
            return vulnerabilities

        else:
            error_message = f"Failed to fetch vulnerabilities for IP {ip}. Status code: {response.status_code}"
            return error_message


