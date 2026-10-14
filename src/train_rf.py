import pandas as pd
import joblib
import json
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from src.config import FEATURES, DATA_PATH, MODEL_DIR, SEED

df = pd.read_csv(DATA_PATH).drop_duplicates().dropna()
X, y = df[FEATURES], df["label"]

X_tr, X_te, y_tr, y_te, df_tr, df_te = train_test_split(
    X, y, df, test_size=0.2, stratify=y, random_state=SEED)

rf = RandomForestClassifier(n_estimators=200, class_weight="balanced",
                            n_jobs=-1, random_state=SEED)
rf.fit(X_tr, y_tr)
pred = rf.predict(X_te)
proba = rf.predict_proba(X_te)[:, 1]

print(classification_report(y_te, pred, digits=4))
print("Confusion matrix:\n", confusion_matrix(y_te, pred))
print("ROC-AUC:", round(roc_auc_score(y_te, proba), 4))

# Recall per attack type (shows where the base model is weak)
print("\nRecall by attack type:")
res = df_te.assign(pred=pred)
for t, g in res[res.label == 1].groupby("attack_type"):
    print(f"  {t:6s}: {(g.pred == 1).mean():.3f}  ({len(g)} flows)")

os.makedirs(MODEL_DIR, exist_ok=True)
joblib.dump(rf, f"{MODEL_DIR}/rf_model.joblib")
json.dump({"features": FEATURES,
           "importances": dict(zip(FEATURES, rf.feature_importances_.round(4).tolist()))},
          open(f"{MODEL_DIR}/meta.json", "w"))
print("\nSaved models/rf_model.joblib")