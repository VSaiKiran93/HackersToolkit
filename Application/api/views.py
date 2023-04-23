from django.views.generic import TemplateView
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from rest_framework.response import Response
import subprocess
import requests
from zapv2 import ZAPv2
from pprint import pprint
import re
import time
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
import shodan

# Create your views here
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


@api_view(['POST'])
def shodan_vuln_scan(request, ip):
    # Set up the Shodan API client
    api_key = "uhuBjP31CDHJsSL4sXFuzAGJawlKbeFI"
    api = shodan.Shodan(api_key)
    ip 

    try:
        # Search for vulnerabilities
        results = api.search(f"vulns:{ip}")
        print(results)
        # Get the list of verified vulnerabilities
        verified_vulns = results.get('facets', {}).get('vuln.verified', [])

        # Loop through the vulnerabilities and extract their details
        vulnerabilities = []
        for vuln in results['matches']:
            # Only include verified vulnerabilities
            if 'vuln' in vuln and vuln['vuln'].get('verified', False):
                vulnerability = {
                    'title': vuln['vuln'].get('title', 'N/A'),
                    'description': vuln['vuln'].get('description', 'N/A'),
                    'references': vuln['vuln'].get('references', []),
                    'cvss': vuln['vuln'].get('cvss', 'N/A'),
                    'summary': vuln['vuln'].get('summary', 'N/A'),
                }
                vulnerabilities.append(vulnerability)

            else:
                vulnerabilities = f"failed to fetch vulnerabilities for IP {ip}. Status code: {response.status_code}"

        # Return the list of vulnerabilities as a JSON response
        return Response(vulnerabilities)

    except shodan.APIError as e:
        print(f"Error: {e}")
        # Return an error message if the Shodan API call fails
        return Response({'error': str(e)})


## OWASP-ZAP ##
@api_view(['POST'])
@csrf_exempt
def zap_scan(request):
    apiKey = 'nu5pfsgc1krtnhbfaf41ag'
    zap = ZAPv2(apikey=apiKey, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})

    #Define new session name and load session
    session_name = 'scan_session'
    zap.core.new_session(name=session_name)
    zap.core.load_session(name=session_name)
    time.sleep(5)

    loaded_session_name = zap.session.current_session
    print(f"Loaded session: {loaded_session_name}")

    if request.method == 'POST':
        ip = request.data['ip']
        print(ip)
        target = f'http://{ip}'

        #Proxy a request to the target so that ZAP has something to deal with
        print('Acessing target {}'.format(target))
        zap.urlopen(target)
        time.sleep(2)

        # Spider the target to build up the application structure
        print('Spidering target {}'.format(target))
        scanID = zap.spider.scan(target)
        time.sleep(2)

        while (int(zap.spider.status(scanID)) < 100):
            # Loop until the spider has finished
            print('Spider progress %: {}'.format(zap.spider.status(scanID)))
            time.sleep(5)

        print('Spider completed')


        while (int(zap.pscan.records_to_scan) > 0):
            print('Records to passic scan : {}'.format(zap.pscan.records_to_scan))
            time.sleep(2)

        # Wait for passive scanning to complete
        zap.pscan.wait()
        print('Passive Scan Completed')

        # Active scan the target
        print('Active Scanning target {}'.format(target))
        scanID = zap.ascan.scan(target)
        while (int(zap.ascan.status(scanID)) < 100):
            # Loop until the scanner has finished
            print('Scan progress %: {}'.format(zap.ascan.status(scanID)))
            time.sleep(5)

        print('Active Scan completed')

        # Retrieve the scan results in JSON format
        alerts = zap.core.alerts(baseurl=target)
        results = []
        for alert in alerts:
            result = {
                'name': alert['name'],
                'risk': alert['risk'],
                'confidence': alert['confidence'],
                'description': alert['description']
            }
            results.append(result)

        return Response({'scan_results': results})
    else:
        return Response({'error': 'Invalid request method'}, status=405)


##  OWASP-ZAP ##
@api_view(['POST'])
def new_session(request):
    # Configure OWASP ZAP API settings
    zap_url = 'http://localhost:8080'
    zap_api_key = 'nu5pfsgc1krtnhbfaf41ag'

    # Start a new session
    session_url = f'{zap_url}/JSON/newSession'
    session_data = {
        'apikey': zap_api_key,
        'name': 'django-rest-scan'
    }
    session_response = requests.post(session_url, data=session_data)

    return Response({'session_response': session_response.json()})

@api_view(['POST'])
def spider_url(request):
    ip_address = request.data['ip_address']

    # Configure OWASP ZAP API settings
    zap_url = 'http://localhost:8080'
    zap_api_key = 'nu5pfsgc1krtnhbfaf41ag'
    target_url = f'http://{ip_address}'

    # Spider the target URL to discover all reachable pages
    spider_url = f'{zap_url}/JSON/spider/action/scanAsUser'
    spider_data = {
        'apikey': zap_api_key,
        'url': target_url,
        'maxDuration': 0
    }
    spider_response = requests.post(spider_url, data=spider_data)

    return Response({'spider_response': spider_response.json()})

@api_view(['GET'])
def spider_status(request):
    # Configure OWASP ZAP API settings
    zap_url = 'http://localhost:8080'
    zap_api_key = 'nu5pfsgc1krtnhbfaf41ag'

    # Wait for the spider to finish
    spider_status_url = f'{zap_url}/JSON/spider/view/status'
    spider_status_data = {
        'apikey': zap_api_key
    }
    spider_status = '100'
    while spider_status != 'Stopped':
        spider_status_response = requests.get(spider_status_url, params=spider_status_data)
        spider_status = spider_status_response.json()['status']

    return Response({'spider_status': spider_status})

@api_view(['POST'])
def scan_url(request):
    ip_address = request.data['ip_address']

    # Configure OWASP ZAP API settings
    zap_url = 'http://localhost:8080'
    zap_api_key = 'nu5pfsgc1krtnhbfaf41ag'
    target_url = f'http://{ip_address}'

    # Scan all discovered pages for vulnerabilities
    scan_url = f'{zap_url}/JSON/ascan/action/scanAsUser'
    scan_data = {
        'apikey': zap_api_key,
        'url': target_url,
        'recurse': 'true',
        'inScopeOnly': 'false'
    }
    scan_response = requests.post(scan_url, data=scan_data)

    return Response({'scan_response': scan_response.json()})

@api_view(['GET'])
def scan_status(request):
    # Configure OWASP ZAP API settings
    zap_url = 'http://localhost:8080'
    zap_api_key = 'nu5pfsgc1krtnhbfaf41ag'

    # Wait for the scan to finish
    scan_status_url = f'{zap_url}/JSON/ascan/view/status'
    scan_status_data = {
        'apikey': zap_api_key
    }
    scan_status = '100'
    while scan_status != 'Completed':
        scan_status_response = requests.get(scan_status_url, params=scan_status_data)
        scan_status = scan_status_response.json()['status']

    return Response({'scan_status': scan_status})

@api_view(['POST'])
def generate_report(request):
    ip_address = request.data['ip_address']

    # Configure OWASP ZAP API settings
    zap_url = 'http://localhost:8080'
    zap_api_key = 'nu5pfsgc1krtnhbfaf41ag'
    target_url = f'http://{ip_address}'

    # Retrieve the scan results
    report_url = f'{zap_url}/OTHER/core/other/htmlreport/'
    report_data = {
        'apikey': zap_api_key,
        'baseurl': target_url
    }
    report_response = requests.get(report_url, params=report_data)
    scan_results = report_response.content.decode('utf-8')

    # Return the scan results as a JSON response
    return Response({'scan_results': scan_results})




@api_view(['POST'])
def nikto_scan(request):
    if request.method == 'POST':
        ip = request.GET.get('ip')
        port_range = request.GET.get('port_range')

        # build the nikto command
        cmd = f'nikto -h {ip} -port {port_range}'

        # execute the command and capture output
        try:
            result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=60)
            output = result.decode('utf-8')
        except subprocess.CalledProcessError as e:
            output = e.output.decode('utf-8')
        except subprocess.TimeoutExpired:
            output = 'Nikto scan timed out after 60 seconds'

        # return the output as a JSON response
        return JsonResponse({'output': output})



#OpenVAS :
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

def get_report(request, gmp, task_id):
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
