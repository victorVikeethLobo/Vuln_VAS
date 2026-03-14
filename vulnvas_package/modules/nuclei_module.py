import subprocess

def run_nuclei_scan(target):

    print("[+] Running Nuclei Vulnerability Scan...")

    try:

        cmd = [
            "nuclei",
            "-u",
            f"http://{target}",
            "-severity",
            "critical,high,medium",
            "-silent"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        findings = result.stdout.splitlines()

        vulns = []

        for line in findings:

            parts = line.split(" ")

            if len(parts) > 1:

                vulns.append({
                    "service": "web",
                    "cve": "Nuclei Finding",
                    "severity": "MEDIUM"
                })

        return vulns

    except Exception as e:

        print("Nuclei scan error:", e)

        return []
