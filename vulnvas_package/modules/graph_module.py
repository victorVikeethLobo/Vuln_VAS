import matplotlib.pyplot as plt
import os

def generate_graph(vulns):

    # create reports directory if it does not exist
    os.makedirs("reports", exist_ok=True)

    severity_count = {}

    for v in vulns:

        sev = v.get("severity", "Unknown")

        severity_count[sev] = severity_count.get(sev, 0) + 1

    labels = severity_count.keys()
    values = severity_count.values()

    plt.figure(figsize=(6,4))
    plt.bar(labels, values)

    plt.title("Vulnerability Severity Distribution")
    plt.xlabel("Severity")
    plt.ylabel("Count")

    plt.savefig("reports/severity_graph.png")

    plt.close()
