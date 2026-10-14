"""
Cross-capture test (leave-one-capture-out).

For each capture C in data/iot23_small.csv:
  train on ALL OTHER captures, test on C (traffic the models have never seen,
  from a different device / malware / day).  This is the honest
  generalisation test.  Needs at least 2 captures:

    python -m src.load_iot23 data/capA.log.labeled data/capB.log.labeled data/capC.log.labeled
    python -m src.train_cross
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from src.config import REAL_PATH, REAL_FEATURES, SEED

df = pd.read_csv(REAL_PATH)
caps = sorted(df.capture.unique())
print(f"{len(df)} flows, {len(caps)} captures: {caps}")
if len(caps) < 2:
    raise SystemExit("Need at least 2 captures. Run load_iot23 with several files.")


def prep(frame, scaler=None):
    x = np.log1p(frame[REAL_FEATURES].clip(lower=0).values.astype(float))
    if scaler is None:
        scaler = StandardScaler().fit(x)
    return scaler.transform(x), scaler


def fit_ae(benign):
    fit = benign.sample(frac=0.9, random_state=SEED)
    val = benign.drop(fit.index)
    X, sc = prep(fit)
    ae = MLPRegressor(hidden_layer_sizes=(16, 6, 16), max_iter=400, early_stopping=True,
                      random_state=SEED).fit(X, X)
    Xv, _ = prep(val, sc)
    thr = float(np.percentile(((ae.predict(Xv) - Xv) ** 2).mean(axis=1), 99))
    return ae, sc, thr


rows = []
for held in caps:
    tr, te = df[df.capture != held], df[df.capture == held]
    if tr.label.nunique() < 2 or (tr.label == 0).sum() < 50:
        print(f"\n[{held}] skipped: training captures lack enough benign or malicious flows")
        continue
    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced", min_samples_leaf=2,
                                n_jobs=-1, random_state=SEED).fit(tr[REAL_FEATURES], tr.label)
    ae, sc, thr = fit_ae(tr[tr.label == 0])
    rf_flag = rf.predict(te[REAL_FEATURES]) == 1
    Xt, _ = prep(te, sc)
    ae_flag = ((ae.predict(Xt) - Xt) ** 2).mean(axis=1) > thr
    both = rf_flag | ae_flag
    mal, ben = (te.label == 1).values, (te.label == 0).values
    rec = lambda f: f[mal].mean() if mal.any() else float("nan")
    fpr = lambda f: f[ben].mean() if ben.any() else float("nan")
    rows.append({"held_out_capture": held, "flows": len(te), "malicious": int(mal.sum()),
                 "RF_recall": rec(rf_flag), "AE_recall": rec(ae_flag), "combined_recall": rec(both),
                 "RF_FPR": fpr(rf_flag), "AE_FPR": fpr(ae_flag), "combined_FPR": fpr(both)})

res = pd.DataFrame(rows).round(3)
print("\nLEAVE-ONE-CAPTURE-OUT RESULTS (nan = that capture has no flows of that class)")
print(res.to_string(index=False))
res.to_csv("data/cross_capture_results.csv", index=False)
print("\nSaved data/cross_capture_results.csv  (put this table in your report)")