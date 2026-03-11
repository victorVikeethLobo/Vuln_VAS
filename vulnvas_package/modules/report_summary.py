import pandas as pd

def risk_summary(vulnerabilities):

    df = pd.DataFrame(vulnerabilities)

    summary = df["severity"].value_counts().to_dict()

    return summary
