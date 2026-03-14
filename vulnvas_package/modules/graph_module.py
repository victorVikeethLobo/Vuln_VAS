
import pandas as pd
import matplotlib.pyplot as plt
import os

def generate_graph(vulns):

    # create reports directory if it does not exist
    os.makedirs("reports", exist_ok=True)

    # ensure reports directory exists
    os.makedirs("reports", exist_ok=True)

    # handle empty vulnerabilities
    if not vulns:
        print("[!] No vulnerabilities to graph.")
        return

    df = pd.DataFrame(vulns)

    # ensure severity column exists
    if "severity" not in df.columns:
        print("[!] No severity data available for graph.")
        return


    severity_count = {}


    for v in vulns:

        sev = v.get("severity", "Unknown")

        severity_count[sev] = severity_count.get(sev, 0) + 1

    labels = severity_count.keys()
    values = severity_count.values()

    plt.figure(figsize=(6,4))
    plt.bar(labels, values)

    counts.plot(kind="bar")


    plt.title("Vulnerability Severity Distribution")
    plt.xlabel("Severity")
    plt.ylabel("Count")

    plt.tight_layout()

    plt.savefig("reports/severity_graph.png")


=======
    print("[✓] Graph saved: reports/severity_graph.png")

>>>>>>> 73bb303 (Fix graph module crash when no vulnerabilities detected)
    plt.close()
