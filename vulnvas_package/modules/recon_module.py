import subprocess
import requests
import nmap
from bs4 import BeautifulSoup

def http_fingerprint(target):

    try:

        url = f"http://{target}"

        r = requests.get(url, timeout=10)

        soup = BeautifulSoup(r.text, "html.parser")

        return {
            "status_code": r.status_code,
            "server": r.headers.get("Server", "Unknown"),
            "title": soup.title.string if soup.title else "No Title"
        }

    except Exception as e:

        return {
            "error": str(e)
        }
def nmap_scan(target):

    nm = nmap.PortScanner()

    nm.scan(target,arguments="-sV -T4 -Pn")

    services=[]

    for host in nm.all_hosts():

        for proto in nm[host].all_protocols():

            ports=nm[host][proto].keys()

            for port in ports:

                data=nm[host][proto][port]

                services.append({
                    "service":data.get("product","unknown"),
                    "version":data.get("version",""),
                    "port":port
                })

    return services


def nikto_scan(target):

    cmd=["nikto","-h",f"http://{target}"]

    result=subprocess.run(cmd,capture_output=True,text=True)

    findings=[]

    for line in result.stdout.splitlines():

        if line.startswith("+"):

            findings.append(line)

    return findings


def run_all_recon(target):

    http=http_fingerprint(target)

    services=nmap_scan(target)

    nikto=nikto_scan(target)

    return{
        "target":target,
        "http":http,
        "services":services,
        "nikto":nikto
    }
