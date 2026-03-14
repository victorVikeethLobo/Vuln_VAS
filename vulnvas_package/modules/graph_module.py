import pandas as pd
import matplotlib.pyplot as plt
import os


def generate_graph(vulns):

    os.makedirs("reports", exist_ok=True)

    if not vulns:
        print("[!] No vulnerabilities to graph.")
        return

    df = pd.DataFrame(vulns)

    if "severity" not in df.columns:
        print("[!] No severity data available.")
        return

    counts = df["severity"].value_counts()

    plt.figure(figsize=(6,4))

    counts.plot(kind="bar")

    plt.title("Vulnerability Severity Distribution")
    plt.xlabel("Severity")
    plt.ylabel("Count")

    plt.tight_layout()

    plt.savefig("reports/severity_graph.png")

    print("[✓] Graph saved to reports/severity_graph.png")

    plt.close()
