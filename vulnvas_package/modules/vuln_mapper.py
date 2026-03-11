import requests
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

def search_cve(service, version, port):

    query = f"{service} {version}"

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=3"

    try:
        r = requests.get(url, timeout=10)
        data = r.json()

        vulns = []

        for item in data.get("vulnerabilities", []):

            cve = item["cve"]["id"]

            metrics = item["cve"]["metrics"].get("cvssMetricV31", [])

            if metrics:
                cvss = metrics[0]["cvssData"]["baseScore"]
                severity = metrics[0]["cvssData"]["baseSeverity"]
            else:
                cvss = 0
                severity = "LOW"

            vulns.append({
                "service": service,
                "version": version,
                "port": port,
                "cve": cve,
                "cvss": cvss,
                "severity": severity
            })

        return vulns

    except Exception:
        return []


def map_vulnerabilities(services):

    vulnerabilities = []

    print("\n[+] Searching CVEs (Parallel Mode)\n")

    with ThreadPoolExecutor(max_workers=6) as executor:

        futures = [
            executor.submit(search_cve, s["service"], s["version"], s["port"])
            for s in services
        ]

        for future in tqdm(futures):
            vulnerabilities.extend(future.result())

    return vulnerabilities
