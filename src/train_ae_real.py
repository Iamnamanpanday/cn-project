"""
Autoencoder (anomaly detector) on the real IoT-23 sample + 'unseen attack' test.

Idea: the autoencoder only ever sees BENIGN flows. Attacks reconstruct badly
(high error) -> flagged. The Random Forest only knows the attacks it was shown.
Test: hide one attack type from the Random Forest and see who still catches it.

Uses scikit-learn's MLPRegressor as the autoencoder (no PyTorch needed).
"""
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from src.config import REAL_PATH, REAL_FEATURES, MODEL_DIR, SEED

df = pd.read_csv(REAL_PATH, parse_dates=["timestamp"]).sort_values("timestamp").reset_index(drop=True)
cut = int(len(df) * 0.7)
train, test = df.iloc[:cut], df.iloc[cut:]


def prep(frame, scaler=None):
    x = np.log1p(frame[REAL_FEATURES].clip(lower=0).values.astype(float))
    if scaler is None:
        scaler = StandardScaler().fit(x)
    return scaler.transform(x), scaler


def train_ae(benign_df):
    fit_df = benign_df.sample(frac=0.9, random_state=SEED)
    val_df = benign_df.drop(fit_df.index)
    X, scaler = prep(fit_df)
    ae = MLPRegressor(hidden_layer_sizes=(16, 6, 16), activation="relu", max_iter=400,
                      random_state=SEED, early_stopping=True)
    ae.fit(X, X)                                   # learn to copy benign flows
    err = lambda frame: ((ae.predict(prep(frame, scaler)[0]) - prep(frame, scaler)[0]) ** 2).mean(axis=1)
    thr = float(np.percentile(err(val_df), 99))    # 1% of normal flows may be flagged
    return ae, scaler, err, thr


def rf_fit(frame):
    return RandomForestClassifier(n_estimators=200, class_weight="balanced", min_samples_leaf=2,
                                  n_jobs=-1, random_state=SEED).fit(frame[REAL_FEATURES], frame.label)


def report(title, rf, ae_err, thr, te):
    rf_flag = rf.predict(te[REAL_FEATURES]) == 1
    ae_flag = ae_err(te) > thr
    both = rf_flag | ae_flag
    ben = (te.label == 0).values
    print(f"\n--- {title} ---")
    print(f"False positive rate:  RF={rf_flag[ben].mean():.3f}  AE={ae_flag[ben].mean():.3f}  combined={both[ben].mean():.3f}")
    for t in sorted(te[te.label == 1].attack_type.unique()):
        m = (te.attack_type == t).values
        print(f"Recall on {t:7s} (n={m.sum():4d}):  RF={rf_flag[m].mean():.3f}  AE={ae_flag[m].mean():.3f}  combined={both[m].mean():.3f}")


# ---- 1) normal setting: RF sees all attack types, AE sees only benign ----
ae, scaler, err, thr = train_ae(train[train.label == 0])
print(f"AE threshold (99th pct of benign error): {thr:.4f}")
report("KNOWN attacks (time split)", rf_fit(train), err, thr, test)

# ---- 2) unseen-attack test: hide one attack type from the RF ----
for hidden in ["attack", "scan"]:
    rf_hidden = rf_fit(train[train.attack_type != hidden])
    report(f"UNSEEN '{hidden}' (RF never saw it; AE never saw ANY attack)", rf_hidden, err, thr, test)

# ---- save the AE for the app ----
joblib.dump({"ae": ae, "scaler": scaler}, f"{MODEL_DIR}/real_ae.joblib")
json.dump({"threshold": thr}, open(f"{MODEL_DIR}/real_ae_meta.json", "w"))
print(f"\nSaved {MODEL_DIR}/real_ae.joblib")