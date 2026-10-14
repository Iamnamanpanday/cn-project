"""
Convert one or more IoT-23 Zeek 'conn.log.labeled' CSV files into a small,
model-ready CSV (about 10k rows).

Usage (from project root):
  python -m src.load_iot23 data/conn4_log_labeled.csv
  python -m src.load_iot23 data/capA.csv data/capB.csv      # several captures
"""
import os
import sys
import numpy as np
import pandas as pd
from src.config import SEED, REAL_PATH, REAL_FEATURES

RAW_COLS = ["ts", "uid", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "service",
            "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp",
            "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts",
            "resp_ip_bytes", "tunnel_parents", "label", "detailed_label"]

# how many rows to keep per class (the file is ~97% port-scan, so we shrink it)
KEEP = {"scan": 2500, "attack": 2500, "c2": 10_000, "benign": 10_000}


def _rename(df):
    """Map Zeek names to ours and tidy the label columns."""
    df.columns = [c.strip() for c in df.columns]
    df = df.rename(columns={"id.orig_h": "src_ip", "id.orig_p": "src_port",
                            "id.resp_h": "dst_ip", "id.resp_p": "dst_port",
                            "detailed-label": "detailed_label"})
    return df


def read_zeek_csv(path, name=None):
    """
    Reads any of these IoT-23 formats:
      A) raw Zeek log  (first line '#separator', tab separated, label columns
         glued at the end)  <- what you get from the Stratosphere download
      B) the CSV conversion with a '#types' first line (your conn4 file)
      C) a normal CSV that already has column names and a 'label' column
    """
    with open(path, "r", errors="ignore") as f:
        first = f.readline()

    if first.startswith("#separator"):                      # ---- A) raw Zeek ----
        fields = None
        with open(path, "r", errors="ignore") as f:
            for line in f:
                if line.startswith("#fields"):
                    fields = line.rstrip("\n").split("\t")[1:]
                    break
        if fields is None:
            raise ValueError("No '#fields' line found in " + path)
        df = pd.read_csv(path, sep="\t", comment="#", names=fields, header=None,
                         na_values=["-", "(empty)"], low_memory=False, dtype=str)
        last = fields[-1]
        tokens = last.split()                               # e.g. tunnel_parents label detailed-label
        if len(tokens) > 1:
            parts = df[last].fillna("-").str.split(r"\s+", n=len(tokens) - 1, expand=True)
            parts = parts.reindex(columns=range(len(tokens)))
            parts.columns = tokens
            df = pd.concat([df.drop(columns=[last]), parts], axis=1)
        df = _rename(df)
    elif first.startswith("#types"):                        # ---- B) your CSV ----
        df = pd.read_csv(path, skiprows=1, names=RAW_COLS + ["_extra"], comment="#",
                         na_values=["-", "(empty)"], low_memory=False)
        df = df.drop(columns="_extra")
    else:                                                   # ---- C) plain CSV ----
        df = _rename(pd.read_csv(path, na_values=["-", "(empty)"], low_memory=False))

    for need in ("ts", "src_ip", "dst_ip", "label"):
        if need not in df.columns:
            raise ValueError(f"Column '{need}' missing in {path}. Columns found: {list(df.columns)}")
    if "uid" not in df.columns:
        df["uid"] = range(len(df))
    if "detailed_label" not in df.columns:
        df["detailed_label"] = ""
    df = df[pd.to_numeric(df["ts"], errors="coerce").notna()].copy()
    df["ts"] = df["ts"].astype(float)
    df["capture"] = name or os.path.basename(path)
    return df


def add_features(df):
    num = ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
           "orig_ip_bytes", "resp_ip_bytes", "missed_bytes", "dst_port", "src_port"]
    for c in num:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df[["duration", "orig_bytes", "resp_bytes"]] = df[["duration", "orig_bytes", "resp_bytes"]].fillna(0)

    pkts = df["orig_pkts"] + df["resp_pkts"]
    ip_bytes = df["orig_ip_bytes"] + df["resp_ip_bytes"]
    dur = df["duration"].clip(lower=1e-3)
    df["bytes_per_sec"] = ip_bytes / dur
    df["pkts_per_sec"] = pkts / dur
    df["avg_pkt_size"] = ip_bytes / pkts.clip(lower=1)
    df["byte_ratio"] = (df["orig_ip_bytes"] + 1) / (df["resp_ip_bytes"] + 1)

    for p in ["tcp", "udp", "icmp"]:
        df[f"is_{p}"] = (df["proto"] == p).astype(int)
    df["state_S0"] = (df["conn_state"] == "S0").astype(int)
    df["state_SF"] = (df["conn_state"] == "SF").astype(int)
    df["state_REJ"] = (df["conn_state"] == "REJ").astype(int)
    df["state_RST"] = df["conn_state"].isin(["RSTO", "RSTR", "RSTOS0", "RSTRH"]).astype(int)
    df["state_OTH"] = (~df["conn_state"].isin(["S0", "SF", "REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH"])).astype(int)

    h = df["history"].fillna("").str.upper()          # Zeek history letters
    for letter in "SADFR":
        df[f"hist_{letter}"] = h.str.count(letter)

    # ---- per-device behaviour in 60-second windows (computed on the FULL file) ----
    df["bucket"] = (df["ts"] // 60).astype(int)
    df["failed"] = df["conn_state"].isin(["S0", "REJ", "RSTO", "RSTOS0", "RSTRH"]).astype(int)
    g = df.groupby(["capture", "src_ip", "bucket"])
    win = g.agg(src_flows_1m=("uid", "size"),
                src_unique_dst_ips_1m=("dst_ip", "nunique"),
                src_unique_dst_ports_1m=("dst_port", "nunique"),
                src_fail_ratio_1m=("failed", "mean")).reset_index()
    df = df.merge(win, on=["capture", "src_ip", "bucket"], how="left")

    df["attack_type"] = np.select(
        [df["label"].str.lower().eq("benign"),
         df["detailed_label"].fillna("").str.contains("PortScan", case=False),
         df["detailed_label"].fillna("").str.contains("C&C", case=False)],
        ["benign", "scan", "c2"], default="attack")
    df["label_bin"] = (df["attack_type"] != "benign").astype(int)
    df["timestamp"] = pd.to_datetime(df["ts"], unit="s")
    return df


def main(paths):
    frames = []
    for p in paths:
        d = read_zeek_csv(p)
        print(f"{p}: {len(d)} raw flows")
        frames.append(add_features(d))
    df = pd.concat(frames, ignore_index=True)

    parts = []
    for t, g in df.groupby("attack_type"):
        parts.append(g.sample(min(len(g), KEEP[t]), random_state=SEED))
    small = pd.concat(parts).sort_values("timestamp").reset_index(drop=True)

    out = small[["timestamp", "src_ip", "dst_ip", "capture", "attack_type"] + REAL_FEATURES].copy()
    out.insert(3, "label", small["label_bin"].values)
    out = out.replace([np.inf, -np.inf], 0).fillna(0)
    os.makedirs(os.path.dirname(REAL_PATH), exist_ok=True)
    out.to_csv(REAL_PATH, index=False)
    print(f"\nSaved {REAL_PATH}: {len(out)} rows, {os.path.getsize(REAL_PATH)/1e6:.1f} MB")
    print(out.attack_type.value_counts().to_string())


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Usage: python -m src.load_iot23 <conn_log_labeled.csv> [more files]")
    main(sys.argv[1:])