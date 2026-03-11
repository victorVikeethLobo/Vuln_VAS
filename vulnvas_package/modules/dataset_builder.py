import requests
import pandas as pd

def collect_cve_data(keyword="apache"):

    print("[+] Collecting CVE data from NVD...")

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=100"

    r = requests.get(url)
    data = r.json()

    rows = []

    for item in data.get("vulnerabilities", []):

        cve = item["cve"]["id"]

        metrics = item["cve"]["metrics"].get("cvssMetricV31", [])

        if metrics:
            cvss = metrics[0]["cvssData"]["baseScore"]
            severity = metrics[0]["cvssData"]["baseSeverity"]
        else:
            cvss = 0
            severity = "LOW"

        rows.append({
            "cve": cve,
            "cvss": cvss,
            "severity": severity
        })

    df = pd.DataFrame(rows)

    df.to_csv("cve_dataset.csv", index=False)
    print("[✓] Dataset saved as cve_dataset.csv")


if __name__ == "__main__":
    collect_cve_data()
