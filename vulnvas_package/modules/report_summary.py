import pandas as pd

def risk_summary(vulns):

    if not vulns:
        print("[!] No vulnerabilities detected.")
        return {"Info": 0}

    df = pd.DataFrame(vulns)

    if "severity" not in df.columns:
        print("[!] No severity information available.")
        return {"Unknown": len(vulns)}

    summary = df["severity"].value_counts().to_dict()

    return summary
