"""
Train + evaluate on the real IoT-23 sample (data/iot23_small.csv).

Two honest tests:
  1) TIME split: train on the first 70% of the capture, test on the last 30%
     (the model never sees the future). This is the main result.
  2) RANDOM split: shown only for comparison; it is optimistic because
     neighbouring flows of one scan are nearly identical (leakage).
Also an ablation: per-flow features only vs. + per-device window features.
"""
import json
import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from src.config import REAL_PATH, REAL_FEATURES, FLOW_FEATURES, MODEL_DIR, SEED

df = pd.read_csv(REAL_PATH, parse_dates=["timestamp"]).sort_values("timestamp").reset_index(drop=True)
print(f"Loaded {len(df)} flows | malicious {df.label.sum()} | benign {(df.label == 0).sum()}")
print(df.attack_type.value_counts().to_string(), "\n")

cut = int(len(df) * 0.7)
tr_t, te_t = df.iloc[:cut], df.iloc[cut:]
tr_r, te_r = train_test_split(df, test_size=0.3, stratify=df.label, random_state=SEED)


def make_rf():
    return RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                  min_samples_leaf=2, n_jobs=-1, random_state=SEED)


def evaluate(name, model, feats, tr, te, detail=False):
    model.fit(tr[feats], tr.label)
    pred = model.predict(te[feats])
    proba = model.predict_proba(te[feats])[:, 1]
    p, r, f, _ = precision_recall_fscore_support(te.label, pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(te.label, pred, labels=[0, 1]).ravel()
    auc = roc_auc_score(te.label, proba) if te.label.nunique() > 1 else float("nan")
    print(f"{name:42s} P={p:.3f} R={r:.3f} F1={f:.3f} AUC={auc:.3f} FPR={fp / max(fp + tn, 1):.3f}  [TN={tn} FP={fp} FN={fn} TP={tp}]")
    if detail:
        res = te.assign(pred=pred)
        print("   recall by attack type:", {t: f"{(g.pred == 1).mean():.3f} (n={len(g)})"
                                           for t, g in res[res.label == 1].groupby("attack_type")})
    return model


print("=== TIME split (main result) ===")
lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced"))
evaluate("Logistic Regression (all features)", lr, REAL_FEATURES, tr_t, te_t, detail=True)
evaluate("Random Forest (per-flow features only)", make_rf(), FLOW_FEATURES, tr_t, te_t, detail=True)
rf = evaluate("Random Forest (flow + device-window)", make_rf(), REAL_FEATURES, tr_t, te_t, detail=True)

print("\n=== RANDOM split (optimistic, for comparison only) ===")
evaluate("Random Forest (flow + device-window)", make_rf(), REAL_FEATURES, tr_r, te_r, detail=True)

# final model for the app: train on everything
final = make_rf().fit(df[REAL_FEATURES], df.label)
imp = dict(sorted(zip(REAL_FEATURES, final.feature_importances_.round(4).tolist()), key=lambda x: -x[1]))
print("\nTop features:", dict(list(imp.items())[:8]))
os.makedirs(MODEL_DIR, exist_ok=True)
joblib.dump(final, f"{MODEL_DIR}/real_rf.joblib")
json.dump({"features": REAL_FEATURES, "importances": imp}, open(f"{MODEL_DIR}/real_meta.json", "w"))
print(f"Saved {MODEL_DIR}/real_rf.joblib")