import subprocess

class NmapMiddleware:

    #One -time configuration and initialization
    def __init__(self, get_response):
        self.get_response = get_response

    #code to be executed for each request before the views.py are called. 
    def __call__(self, request):
        response = self.get_response(request)
        if hasattr(request, 'nmap_output'):
            return JsonResponse({'output': request.nmap_output}, status=status.HTTP_200_OK)
        return response

    # method that gets called by Django before view function 
    def process_view(self, request, view_func, view_args, view_kwargs):
        from .views import test_nmap_middleware
        from .views import NmapScanView
        if view_func == NmapScanView.as_view():
            if request.method == 'POST':
                ip_address = request.POST.get('ip_address')
                port_range = request.POST.get('port_range')
                scan_type = request.POST.get('scan_type')

                #Created a dictionary that maps each scan type to its corresponding Nmap command
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
                    try:
                        completed_process = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
                        print(completed_process.stdout)
                        request.nmap_output = completed_process.stdout
                    except subprocess.CalledProcessError as e:
                        print(e.stderr)
                        request.nmap_output = 'Invalid scan type or error occurred'
                else:
                    print(err)
                    request.nmap_output = 'Invalid scan type'

        return None
