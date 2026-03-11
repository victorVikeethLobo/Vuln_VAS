import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def search_cve(service, version):

    query = f"{service} {version}"

    params = {
        "keywordSearch": query,
        "resultsPerPage": 3
    }

    try:
        r = requests.get(NVD_API, params=params, timeout=15)

        data = r.json()

        results = []

        for item in data.get("vulnerabilities", []):

            cve = item["cve"]["id"]

            metrics = item["cve"].get("metrics", {})

            cvss_score = 0
            severity = "Unknown"

            if "cvssMetricV31" in metrics:
                metric = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = metric["baseScore"]
                severity = metric["baseSeverity"]

            results.append({
                "service": service,
                "version": version,
                "cve": cve,
                "cvss": cvss_score,
                "severity": severity
            })

        return results

    except Exception as e:

        print("CVE lookup failed:", e)

        return []
