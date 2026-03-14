import json
from concurrent.futures import ThreadPoolExecutor
from vulnvas_package.modules.nuclei_module import run_nuclei_scan
from vulnvas_package.modules.recon_module import run_all_recon
from vulnvas_package.modules.vulnerability_module import analyze_vulnerabilities
from vulnvas_package.modules.ml_module import predict_priority
from vulnvas_package.modules.exploit_lookup import check_exploit
from vulnvas_package.modules.remediation_module import remediation_advice
from vulnvas_package.modules.report_summary import risk_summary
from vulnvas_package.modules.graph_module import generate_graph


def run_scan(target,quick=False):

    print("\n[+] Starting Vuln_VAS Scan")
    print("[+] Target:", target)

    # --------------------------------
    # STEP 1 - Recon
    # --------------------------------

    print("\n[1] Running Recon Module...")

    recon = run_all_recon(target)

    print("[✓] Recon Complete")

    # --------------------------------
    # STEP 2 - Vulnerability Mapping
    # --------------------------------

    print("\n[2] Running Vulnerability Mapping...")

    services = recon.get("services", [])

    vulns = analyze_vulnerabilities(services)

    print("[✓] Vulnerability Analysis Complete")
    print("\n[+] Running Nuclei Scan")

    nuclei_vulns = run_nuclei_scan(target)

    vulns.extend(nuclei_vulns)

    # --------------------------------
    # STEP 3 - Exploit Detection
    # --------------------------------

    print("\n[3] Checking Exploit Database...")

    for v in vulns:

        cve = v.get("cve")

        exploit = check_exploit(cve)

        v["exploit_available"] = exploit

        if exploit:
            print(f"[!] Exploit Found for {cve}")

    print("[✓] Exploit Detection Complete")

    # --------------------------------
    # STEP 4 - ML Risk Prioritization
    # --------------------------------

    print("\n[4] Running ML Risk Prioritization...")

    ml = predict_priority(vulns)

    print("[✓] ML Analysis Complete")

    # --------------------------------
    # STEP 5 - Remediation Suggestions
    # --------------------------------

    print("\n[5] Generating Remediation Advice...")

    for v in vulns:

        advice = remediation_advice(v)

        v["remediation"] = advice

    print("[✓] Remediation Suggestions Added")

    # --------------------------------
    # STEP 6 - Risk Summary
    # --------------------------------

    print("\n[6] Generating Risk Summary...")

    summary = risk_summary(vulns)

    print(summary)

    # --------------------------------
    # STEP 7 - Graph Generation
    # --------------------------------

    print("\n[7] Generating Vulnerability Graph...")

    generate_graph(vulns)

    # --------------------------------
    # STEP 8 - Save Report
    # --------------------------------

    report = {
        "target": target,
        "recon": recon,
        "vulnerabilities": vulns,
        "ml_priority": ml,
        "risk_summary": summary
    }

    filename = f"reports/vulnvas_{target.replace('.','_')}.json"

    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    print("\n[✓] Scan Finished")
    print("[✓] Report saved:", filename)
