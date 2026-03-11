import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib

df = pd.read_csv("cve_dataset.csv")

severity_map = {
"LOW":1,
"MEDIUM":2,
"HIGH":3,
"CRITICAL":4
}

df["severity_num"]=df["severity"].map(severity_map)

X=df[["cvss","severity_num"]]
y=df["severity_num"]

model=RandomForestClassifier()

model.fit(X,y)

joblib.dump(model,"ml_model.pkl")

print("Model trained and saved")
