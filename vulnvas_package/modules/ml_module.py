import pandas as pd
from sklearn.tree import DecisionTreeClassifier

data={
"cvss":[9.8,9.5,8.0,7.5,6.0,5.0,3.0],
"exploit":[1,1,1,0,0,0,0],
"port":[21,80,22,443,8080,3306,25],
"priority":["Immediate","Immediate","High","High","Medium","Medium","Low"]
}

df=pd.DataFrame(data)

X=df[["cvss","exploit","port"]]

y=df["priority"]

model=DecisionTreeClassifier()

model.fit(X,y)


def predict_priority(vulnerabilities):

    results = []

    for v in vulnerabilities:

        cvss = v.get("cvss", 5.0)

        exploit = 1 if v.get("exploit_available", False) else 0

        port = v.get("port", 0)

        pred = model.predict([[cvss, exploit, port]])[0]

        results.append({
            "service": v.get("service", "unknown"),
            "cve": v.get("cve", "N/A"),
            "priority": pred
        })

    return results
