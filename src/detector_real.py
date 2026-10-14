"""
Combined detector for the real IoT-23 pipeline.
  - Random Forest  -> catches KNOWN attack patterns
  - Autoencoder    -> catches anything that does not look like normal traffic
Also: per-device risk table, C2/target candidates, graph data, firewall rules.
"""
import json
import os
import tempfile
import joblib
import numpy as np
import pandas as pd
import networkx as nx
from src.config import REAL_FEATURES, MODEL_DIR
from src.load_iot23 import read_zeek_csv, add_features


class Detector:
    def __init__(self, model_dir=MODEL_DIR, rf_threshold=0.5):
        self.rf = joblib.load(f"{model_dir}/real_rf.joblib")
        bundle = joblib.load(f"{model_dir}/real_ae.joblib")
        self.ae, self.scaler = bundle["ae"], bundle["scaler"]
        self.ae_threshold = json.load(open(f"{model_dir}/real_ae_meta.json"))["threshold"]
        self.rf_threshold = rf_threshold

    def _ae_error(self, X):
        x = self.scaler.transform(np.log1p(X.clip(lower=0).values.astype(float)))
        return ((self.ae.predict(x) - x) ** 2).mean(axis=1)

    def score(self, df, rf_threshold=None, ae_scale=1.0):
        """ae_scale > 1 makes the autoencoder less sensitive (fewer false alarms)."""
        thr = self.rf_threshold if rf_threshold is None else rf_threshold
        X = df[REAL_FEATURES].replace([np.inf, -np.inf], 0).fillna(0)
        out = df.copy()
        out["rf_prob"] = self.rf.predict_proba(X)[:, 1]
        out["ae_error"] = self._ae_error(X)
        rf_flag = out["rf_prob"] >= thr
        ae_flag = out["ae_error"] > self.ae_threshold * ae_scale
        out["is_botnet"] = rf_flag | ae_flag
        out["reason"] = np.select(
            [rf_flag & ae_flag, rf_flag, ae_flag],
            ["known attack + anomaly", "known attack", "anomaly (unseen)"], default="normal")
        return out


# ---------- loading ----------
def load_any(path_or_buffer, name="upload.csv"):
    """Accept the small processed CSV (has REAL_FEATURES) or a raw Zeek conn.log.labeled CSV."""
    if hasattr(path_or_buffer, "read"):
        tmp = os.path.join(tempfile.gettempdir(), name)
        with open(tmp, "wb") as f:
            f.write(path_or_buffer.read())
        path_or_buffer = tmp
    head = pd.read_csv(path_or_buffer, nrows=2)
    if all(c in head.columns for c in REAL_FEATURES):
        return pd.read_csv(path_or_buffer)
    raw = add_features(read_zeek_csv(path_or_buffer))      # raw Zeek file
    raw["label"] = raw["label_bin"]
    return raw


# ---------- per-device view ----------
def device_table(scored, cutoff_pct=30, min_flows=5):
    g = scored.groupby("src_ip").agg(
        flows=("is_botnet", "size"), flagged=("is_botnet", "sum"),
        avg_rf_prob=("rf_prob", "mean"), unique_dsts=("dst_ip", "nunique")).reset_index()
    g["flagged_%"] = (g["flagged"] / g["flows"] * 100).round(1)
    g["status"] = np.where((g["flagged_%"] > cutoff_pct) & (g["flows"] >= min_flows),
                           "INFECTED", "clean")
    return g.sort_values(["status", "flagged_%"], ascending=[True, False]).reset_index(drop=True)


def suspicious_destinations(scored, top=15):
    bad = scored[scored.is_botnet]
    if bad.empty:
        return pd.DataFrame(columns=["dst_ip", "flagged_flows", "from_devices", "ports"])
    g = bad.groupby("dst_ip").agg(flagged_flows=("is_botnet", "size"),
                                  from_devices=("src_ip", "nunique"),
                                  ports=("dst_port", lambda s: ",".join(map(str, sorted(set(s.astype(int)))[:4]))))
    return g.sort_values(["from_devices", "flagged_flows"], ascending=False).head(top).reset_index()


# ---------- graph ----------
def build_graph(scored, devices, top_dst=25):
    infected = set(devices.loc[devices.status == "INFECTED", "src_ip"])
    bad = scored[scored.is_botnet & scored.src_ip.isin(infected)]
    top = bad.dst_ip.value_counts().head(top_dst)
    G = nx.Graph()
    for ip in infected:
        G.add_node(ip, kind="infected device")
    for dst, n in top.items():
        G.add_node(dst, kind="suspicious destination")
        for src in bad[bad.dst_ip == dst].src_ip.unique():
            G.add_edge(src, dst, weight=int(n))
    return G


# ---------- mitigation (text only, never executed) ----------
def block_rules(devices, dst_df, max_dst=10):
    lines_ipt, lines_win = ["# Linux iptables (review before running)"], ["REM Windows firewall (review first)"]
    for ip in devices.loc[devices.status == "INFECTED", "src_ip"]:
        lines_ipt += [f"iptables -A FORWARD -s {ip} -j DROP", f"iptables -A FORWARD -d {ip} -j DROP"]
        lines_win.append(f'netsh advfirewall firewall add rule name="Quarantine {ip}" dir=out action=block remoteip={ip}')
    for ip in dst_df.dst_ip.head(max_dst):
        lines_ipt.append(f"iptables -A OUTPUT -d {ip} -j DROP")
        lines_win.append(f'netsh advfirewall firewall add rule name="Block {ip}" dir=out action=block remoteip={ip}')
    return "\n".join(lines_ipt), "\n".join(lines_win)


if __name__ == "__main__":
    df = load_any("data/iot23_small.csv")
    det = Detector()
    s = det.score(df)
    print("Reason counts:\n", s.reason.value_counts().to_string())
    dev = device_table(s)
    print("\nDevices flagged INFECTED:\n", dev[dev.status == "INFECTED"].to_string(index=False))
    dst = suspicious_destinations(s)
    print("\nTop suspicious destinations:\n", dst.head(5).to_string(index=False))
    G = build_graph(s, dev)
    print(f"\nGraph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    ipt, win = block_rules(dev, dst)
    print("\n" + ipt[:400])