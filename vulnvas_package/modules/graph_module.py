import matplotlib.pyplot as plt
import pandas as pd

def generate_graph(vulnerabilities):

    df = pd.DataFrame(vulnerabilities)

    counts = df["severity"].value_counts()

    plt.figure(figsize=(6,6))
    counts.plot(kind="bar")

    plt.title("Vulnerability Severity Distribution")
    plt.xlabel("Severity")
    plt.ylabel("Count")

    plt.savefig("reports/severity_graph.png")

    print("[✓] Graph saved: reports/severity_graph.png")
