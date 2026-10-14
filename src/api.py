"""
FastAPI backend wrapper for AI-Based IoT Botnet Detector.
Exposes REST endpoints for the React SOC console:
  - GET  /api/health
  - POST /api/analyze
  - GET  /api/analyze-sample
  - GET  /api/samples
  - GET  /api/explain/{ip}
  - GET  /api/model-card
"""
import io
import os
import glob
import json
import math
import tempfile
from typing import Optional, Dict, Any, List

import numpy as np
import pandas as pd
from fastapi import FastAPI, UploadFile, File, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.config import REAL_FEATURES, REAL_PATH
from src.detector_real import (
    Detector,
    load_any,
    device_table,
    suspicious_destinations,
    build_graph,
    block_rules,
)

app = FastAPI(
    title="SIGINT IoT Botnet Detector API",
    description="SOC Backend Engine for IoT-23 Traffic Analysis",
    version="1.0.0",
)

# Enable CORS for local development (Vite frontend on port 5173)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global detector instance (loaded once at module load)
print("[SOC-ENGINE] Initializing detector models...")
detector: Detector = Detector()
print("[SOC-ENGINE] Detector loaded successfully.")

# Baseline benign statistics computed from iot23_small.csv (for /api/explain/{ip})
benign_medians: Dict[str, float] = {}
benign_mads: Dict[str, float] = {}
benign_stds: Dict[str, float] = {}

# In-memory storage of the most recent scored DataFrame for explanation queries
current_scored_df: Optional[pd.DataFrame] = None
current_source_name: str = "iot23_small.csv"

# Plain-English descriptions for REAL_FEATURES
FEATURE_LABELS: Dict[str, str] = {
    "src_unique_dst_ips_1m": "Unique destinations / min",
    "src_flows_1m": "Flows initiated / min",
    "src_unique_dst_ports_1m": "Target ports / min",
    "src_fail_ratio_1m": "Failed / rejected flow ratio",
    "avg_pkt_size": "Mean packet size (bytes)",
    "byte_ratio": "Transmit-to-receive byte ratio",
    "bytes_per_sec": "Throughput (bytes / sec)",
    "pkts_per_sec": "Packet transmission rate (pkts / sec)",
    "duration": "Flow connection duration (s)",
    "orig_pkts": "Originator packets per flow",
    "resp_pkts": "Responder packets per flow",
    "orig_bytes": "Originator payload bytes",
    "resp_bytes": "Responder payload bytes",
    "dst_port": "Destination port distribution",
    "state_S0": "Unanswered SYN flows (S0 state)",
    "state_REJ": "Rejected connection attempts (REJ)",
    "state_SF": "Normal connection closures (SF)",
    "hist_S": "SYN-only connection history",
    "hist_A": "ACK acknowledgment history",
    "hist_D": "Payload data transfer history",
    "hist_F": "FIN tear-down history",
    "hist_R": "RST connection reset history",
    "is_tcp": "TCP protocol usage",
    "is_udp": "UDP protocol usage",
    "is_icmp": "ICMP protocol usage",
}

try:
    baseline_df = pd.read_csv(REAL_PATH)
    benign_df = baseline_df[baseline_df.get("label", 0) == 0]
    if len(benign_df) > 0:
        for feat in REAL_FEATURES:
            if feat in benign_df.columns:
                med = float(benign_df[feat].median())
                mad = float((benign_df[feat] - med).abs().median())
                std = float(benign_df[feat].std())
                benign_medians[feat] = med
                benign_mads[feat] = mad
                benign_stds[feat] = std if std > 1e-4 else 1.0
        print(f"[SOC-ENGINE] Baseline calculated from {len(benign_df)} benign reference flows.")
except Exception as e:
    print(f"[SOC-ENGINE] Warning: could not load benign baseline: {e}")


def find_sample_file(sample_name: str) -> str:
    """Find a sample file in data/ or test datasets."""
    candidates = [
        f"data/{sample_name}",
        f"data/test-dataset/test_sets/{sample_name}",
        f"data/test+dataset/test_sets/{sample_name}",
        sample_name,
    ]
    for c in candidates:
        if os.path.exists(c) and os.path.isfile(c):
            return c
    # Check if inside test_sets without prefix
    matches = glob.glob(f"data/**/{sample_name}", recursive=True)
    if matches:
        return matches[0]
    raise HTTPException(status_code=404, detail=f"Sample file not found: {sample_name}")


def process_dataframe(
    df: pd.DataFrame,
    source_name: str,
    rf_threshold: float = 0.5,
    ae_scale: float = 1.0,
    cutoff: float = 30.0,
    min_flows: int = 5,
) -> Dict[str, Any]:
    """Score dataframe and package into full SOC JSON payload."""
    global current_scored_df, current_source_name
    if detector is None:
        raise HTTPException(status_code=500, detail="Detector model is not loaded.")

    try:
        scored = detector.score(df, rf_threshold=rf_threshold, ae_scale=ae_scale)
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Scoring error: {str(e)}. Ensure CSV has REAL_FEATURES or valid Zeek format.",
        )

    current_scored_df = scored
    current_source_name = source_name

    total_flows = len(scored)
    flagged_flows = int(scored["is_botnet"].sum())
    flagged_pct = round((flagged_flows / total_flows * 100), 1) if total_flows > 0 else 0.0

    # Device analysis table
    dev_table = device_table(scored, cutoff_pct=cutoff, min_flows=min_flows)
    infected_df = dev_table[dev_table["status"] == "INFECTED"]
    infected_count = len(infected_df)

    # Threat level evaluation
    if infected_count > 0 and (flagged_pct >= 15.0 or infected_count >= 2):
        threat_level = "CRITICAL"
    elif infected_count > 0 or flagged_pct >= 5.0:
        threat_level = "ELEVATED"
    else:
        threat_level = "NOMINAL"

    # Evaluation metrics if ground-truth label exists
    recall = None
    fpr = None
    if "label" in scored.columns:
        valid_labels = scored["label"].dropna()
        if valid_labels.isin([0, 1]).any():
            malicious = scored[scored["label"] == 1]
            benign = scored[scored["label"] == 0]
            if len(malicious) > 0:
                recall = round(float(malicious["is_botnet"].mean() * 100), 1)
            if len(benign) > 0:
                fpr = round(float(benign["is_botnet"].mean() * 100), 2)

    # Reasons distribution
    reason_series = scored["reason"].value_counts()
    reasons_dict = {str(k): int(v) for k, v in reason_series.items()}

    # Breakdown by attack type if labeled
    by_type = []
    if "attack_type" in scored.columns:
        grouped = scored.groupby("attack_type")
        for atype, grp in grouped:
            if str(atype).lower() != "nan" and str(atype).strip():
                by_type.append({
                    "attack_type": str(atype),
                    "total": int(len(grp)),
                    "flagged": int(grp["is_botnet"].sum()),
                    "detected_pct": round(float(grp["is_botnet"].mean() * 100), 1),
                })

    # Prepare timeline buckets (up to 36 buckets for histogram)
    scored_sorted = scored.copy()
    has_timestamp = "timestamp" in scored_sorted.columns
    if has_timestamp:
        try:
            scored_sorted["dt"] = pd.to_datetime(scored_sorted["timestamp"], errors="coerce")
            scored_sorted = scored_sorted.sort_values("dt").reset_index(drop=True)
        except Exception:
            has_timestamp = False

    num_buckets = min(36, max(12, total_flows // 20))
    timeline_buckets = []
    chunk_size = max(1, math.ceil(total_flows / num_buckets))

    for b_idx in range(num_buckets):
        start_i = b_idx * chunk_size
        end_i = min(total_flows, (b_idx + 1) * chunk_size)
        if start_i >= total_flows:
            break
        chunk = scored_sorted.iloc[start_i:end_i]
        b_flows = len(chunk)
        b_flagged = int(chunk["is_botnet"].sum())

        if has_timestamp and not chunk["dt"].isna().all():
            first_valid = chunk["dt"].dropna().iloc[0]
            t_label = first_valid.strftime("%H:%M:%SZ")
            t_iso = first_valid.isoformat()
        else:
            t_label = f"T+{b_idx * 10}s"
            t_iso = f"T+{b_idx * 10}s"

        timeline_buckets.append({
            "bucket_index": b_idx,
            "t": t_label,
            "iso": t_iso,
            "flows": b_flows,
            "flagged": b_flagged,
            "start_flow": start_i,
            "end_flow": end_i,
        })

    # Per-device sparklines & observed behaviors
    device_records = []
    for _, dev_row in dev_table.iterrows():
        sip = str(dev_row["src_ip"])
        dev_flows = scored_sorted[scored_sorted["src_ip"] == sip]
        
        # 12-slot sparkline of flagged flows
        sparkline = []
        dev_total = len(dev_flows)
        if dev_total > 0:
            sp_chunk = max(1, math.ceil(dev_total / 12))
            for s_idx in range(12):
                s_start = s_idx * sp_chunk
                s_end = min(dev_total, (s_idx + 1) * sp_chunk)
                if s_start < dev_total:
                    sub = dev_flows.iloc[s_start:s_end]
                    sparkline.append(int(sub["is_botnet"].sum()))
                else:
                    sparkline.append(0)
        else:
            sparkline = [0] * 12

        # Observed attack types & kill chain stages
        observed_types = []
        if "attack_type" in dev_flows.columns:
            obs = dev_flows[dev_flows["is_botnet"]]["attack_type"].dropna().unique().tolist()
            observed_types = [str(x) for x in obs if str(x).lower() != "benign"]

        # Infer kill chain stages for host
        # Stage 1: RECON (scanning multiple targets/ports)
        has_recon = (
            any("scan" in t.lower() for t in observed_types)
            or dev_row["unique_dsts"] > 50
            or float(dev_flows.get("src_unique_dst_ips_1m", pd.Series([0])).max()) > 20
        )
        # Stage 2: ATTACK (SSH brute force / command injection)
        ports = set(dev_flows["dst_port"].dropna().astype(int).tolist()) if "dst_port" in dev_flows.columns else set()
        has_attack = (
            any("attack" in t.lower() or "ssh" in t.lower() for t in observed_types)
            or (22 in ports)
            or (23 in ports)
        )
        # Stage 3: C2 (C&C Beaconing)
        has_c2 = (
            any("c2" in t.lower() or "c&c" in t.lower() for t in observed_types)
            or (6667 in ports)
            or (float(dev_flows.get("duration", pd.Series([0])).mean()) > 15.0 and dev_row["flagged_%"] > 5)
        )

        device_records.append({
            "src_ip": sip,
            "flows": int(dev_row["flows"]),
            "flagged": int(dev_row["flagged"]),
            "flagged_pct": float(dev_row["flagged_%"]),
            "avg_rf_prob": round(float(dev_row["avg_rf_prob"]), 4),
            "unique_dsts": int(dev_row["unique_dsts"]),
            "status": str(dev_row["status"]),
            "sparkline": sparkline,
            "attack_types": observed_types,
            "kill_chain": {
                "recon": bool(has_recon),
                "attack": bool(has_attack),
                "c2": bool(has_c2),
            },
        })

    # Top suspicious destinations
    dest_df = suspicious_destinations(scored)
    destination_records = []
    if not dest_df.empty:
        for _, d_row in dest_df.iterrows():
            destination_records.append({
                "dst_ip": str(d_row["dst_ip"]),
                "flagged_flows": int(d_row["flagged_flows"]),
                "from_devices": int(d_row["from_devices"]),
                "ports": str(d_row["ports"]),
            })

    # Network topology graph
    nx_graph = build_graph(scored, dev_table)
    graph_nodes = []
    graph_links = []

    # Map existing nodes
    node_set = set()
    for n, d in nx_graph.nodes(data=True):
        kind = d.get("kind", "normal host")
        is_inf = (kind == "infected device")
        node_set.add(n)
        graph_nodes.append({
            "id": n,
            "label": n,
            "kind": kind,
            "is_infected": is_inf,
            "status": "INFECTED" if is_inf else "clean",
        })

    for u, v, d in nx_graph.edges(data=True):
        graph_links.append({
            "source": u,
            "target": v,
            "weight": int(d.get("weight", 1)),
            "is_threat": True,
        })

    # If no infected devices or small graph, include top active devices/destinations for visual richness
    if len(graph_nodes) == 0:
        top_talkers = dev_table.head(6)
        for _, trow in top_talkers.iterrows():
            tip = str(trow["src_ip"])
            if tip not in node_set:
                node_set.add(tip)
                graph_nodes.append({
                    "id": tip,
                    "label": tip,
                    "kind": "normal host",
                    "is_infected": False,
                    "status": "clean",
                })
            # Add its top destination
            dev_dsts = scored[scored["src_ip"] == tip]["dst_ip"].value_counts().head(3)
            for dst_ip, cnt in dev_dsts.items():
                if dst_ip not in node_set:
                    node_set.add(dst_ip)
                    graph_nodes.append({
                        "id": dst_ip,
                        "label": dst_ip,
                        "kind": "normal peer",
                        "is_infected": False,
                        "status": "clean",
                    })
                graph_links.append({
                    "source": tip,
                    "target": dst_ip,
                    "weight": int(cnt),
                    "is_threat": False,
                })

    # Live event feed (up to 3000 events sorted by time/index)
    event_list = []
    max_events = min(3000, total_flows)
    sub_events = scored_sorted.head(max_events)

    for idx, row in sub_events.iterrows():
        t_str = ""
        if has_timestamp and pd.notna(row.get("timestamp")):
            try:
                t_str = pd.to_datetime(row["timestamp"]).strftime("%H:%M:%SZ")
            except Exception:
                t_str = str(row["timestamp"])[:10]
        else:
            t_str = f"T+{idx:04d}"

        event_list.append({
            "id": int(idx),
            "timestamp": t_str,
            "src_ip": str(row["src_ip"]),
            "dst_ip": str(row["dst_ip"]),
            "dst_port": int(row.get("dst_port", 0)) if pd.notna(row.get("dst_port")) else 0,
            "rf_prob": round(float(row.get("rf_prob", 0.0)), 3),
            "ae_error": round(float(row.get("ae_error", 0.0)), 3),
            "reason": str(row.get("reason", "normal")),
            "is_botnet": bool(row.get("is_botnet", False)),
            "attack_type": str(row.get("attack_type", "")) if pd.notna(row.get("attack_type")) else None,
        })

    # Firewall Mitigation Rules
    ipt_rules, win_rules = block_rules(dev_table, dest_df)

    # Per-device isolation rules
    per_device_rules = {}
    for _, drow in dev_table.iterrows():
        dip = str(drow["src_ip"])
        d_ipt = f"# Linux iptables quarantine for {dip}\niptables -A FORWARD -s {dip} -j DROP\niptables -A FORWARD -d {dip} -j DROP"
        d_win = f'REM Windows Firewall quarantine for {dip}\nnetsh advfirewall firewall add rule name="Quarantine {dip}" dir=out action=block remoteip={dip}'
        per_device_rules[dip] = {"iptables": d_ipt, "netsh": d_win}

    return {
        "summary": {
            "source_file": source_name,
            "total": total_flows,
            "flagged": flagged_flows,
            "flagged_pct": flagged_pct,
            "infected_devices": infected_count,
            "threat_level": threat_level,
            "recall": recall,
            "fpr": fpr,
        },
        "reasons": reasons_dict,
        "by_type": by_type,
        "devices": device_records,
        "destinations": destination_records,
        "graph": {
            "nodes": graph_nodes,
            "links": graph_links,
        },
        "timeline": timeline_buckets,
        "events": event_list,
        "rules": {
            "iptables": ipt_rules,
            "netsh": win_rules,
        },
        "per_device_rules": per_device_rules,
    }


@app.get("/api/health")
def get_health():
    """Verify backend health and model loading."""
    return {
        "status": "healthy",
        "detector_loaded": detector is not None,
        "models": {
            "random_forest": detector.rf is not None if detector else False,
            "autoencoder": detector.ae is not None if detector else False,
            "rf_threshold": detector.rf_threshold if detector else 0.5,
            "ae_threshold": detector.ae_threshold if detector else None,
        },
    }


@app.get("/api/samples")
def list_samples():
    """List built-in sample and test CSV datasets."""
    built_in = [
        {
            "name": "iot23_small.csv",
            "category": "Reference Sample",
            "desc": "Balanced IoT-23 reference slice (~9.5k flows, 1 infected host)",
            "expected": "5,025 flagged (52.6%), 192.168.2.5 INFECTED",
        },
        {
            "name": "test_01_mixed_100.csv",
            "category": "Test Suite",
            "desc": "Mixed benign + attack flows (100 flows)",
            "expected": "50 flagged, 192.168.2.5 INFECTED",
        },
        {
            "name": "test_02_mixed_500.csv",
            "category": "Test Suite",
            "desc": "Larger mixed traffic slice (500 flows)",
            "expected": "~252 flagged, 192.168.2.5 INFECTED",
        },
        {
            "name": "test_03_clean_100.csv",
            "category": "Test Suite",
            "desc": "Pure clean normal traffic (100 flows)",
            "expected": "<=1 flagged, 0 infected, threat level NOMINAL",
        },
        {
            "name": "test_04_clean_500.csv",
            "category": "Test Suite",
            "desc": "Pure clean normal traffic (500 flows)",
            "expected": "<=1 flagged, 0 infected, threat level NOMINAL",
        },
        {
            "name": "test_05_scan_only_150.csv",
            "category": "Test Suite",
            "desc": "Port scan & reconnaissance traffic (150 flows)",
            "expected": "150 flagged (all), 192.168.2.5 INFECTED",
        },
        {
            "name": "test_06_ssh_bruteforce_150.csv",
            "category": "Test Suite",
            "desc": "SSH brute force dictionary attacks (150 flows)",
            "expected": "120 flagged, 192.168.2.5 INFECTED",
        },
        {
            "name": "test_07_c2_hidden_100.csv",
            "category": "Test Suite",
            "desc": "Low-volume C&C beacons (100 flows, 8 C2 flows)",
            "expected": "8 flagged; no host infected at 30%, flips at cutoff=5%",
        },
        {
            "name": "test_08_unlabeled_300.csv",
            "category": "Test Suite",
            "desc": "Production unlabeled traffic capture (300 flows)",
            "expected": "Recall/FPR hidden; flags botnet activity accurately",
        },
    ]
    return {"samples": built_in}


@app.get("/api/analyze-sample")
def analyze_sample(
    sample_name: str = Query("iot23_small.csv", description="Name of the sample file"),
    rf_threshold: float = Query(0.5, ge=0.05, le=0.95),
    ae_scale: float = Query(1.0, ge=0.5, le=5.0),
    cutoff: float = Query(30.0, ge=1.0, le=99.0),
    min_flows: int = Query(5, ge=1, le=500),
):
    """Analyze one of the built-in sample or test dataset files."""
    filepath = find_sample_file(sample_name)
    try:
        df = load_any(filepath)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to load sample {sample_name}: {str(e)}")

    payload = process_dataframe(
        df=df,
        source_name=sample_name,
        rf_threshold=rf_threshold,
        ae_scale=ae_scale,
        cutoff=cutoff,
        min_flows=min_flows,
    )
    return JSONResponse(content=payload)


@app.post("/api/analyze")
async def analyze_upload(
    file: UploadFile = File(...),
    rf_threshold: float = Query(0.5, ge=0.05, le=0.95),
    ae_scale: float = Query(1.0, ge=0.5, le=5.0),
    cutoff: float = Query(30.0, ge=1.0, le=99.0),
    min_flows: int = Query(5, ge=1, le=500),
):
    """Analyze a user-uploaded CSV file (processed features or raw Zeek conn.log.labeled)."""
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    try:
        buffer = io.BytesIO(contents)
        df = load_any(buffer, name=file.filename or "upload.csv")
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Unable to parse CSV file '{file.filename}'. Ensure it is a valid CSV with REAL_FEATURES or Zeek log: {str(e)}",
        )

    payload = process_dataframe(
        df=df,
        source_name=file.filename or "uploaded.csv",
        rf_threshold=rf_threshold,
        ae_scale=ae_scale,
        cutoff=cutoff,
        min_flows=min_flows,
    )
    return JSONResponse(content=payload)


@app.get("/api/explain/{ip}")
def explain_host(ip: str):
    """
    Compare the device mean of each REAL_FEATURES column against the median of
    benign flows from baseline (data/iot23_small.csv), returning top 5 behavioral deviations.
    """
    global current_scored_df
    df_to_use = current_scored_df
    if df_to_use is None or ip not in df_to_use["src_ip"].values:
        # Fall back to baseline dataset
        try:
            df_to_use = pd.read_csv(REAL_PATH)
        except Exception:
            raise HTTPException(status_code=404, detail=f"No data available to explain host {ip}")

    dev_flows = df_to_use[df_to_use["src_ip"] == ip]
    if dev_flows.empty:
        raise HTTPException(status_code=404, detail=f"Host IP {ip} not found in active dataset.")

    dev_means = dev_flows[REAL_FEATURES].replace([np.inf, -np.inf], 0).fillna(0).mean()

    deviations = []
    for feat in REAL_FEATURES:
        b_med = benign_medians.get(feat, 0.0)
        b_mad = benign_mads.get(feat, 0.0)
        b_std = benign_stds.get(feat, 1.0)

        scale = 1.4826 * b_mad if b_mad > 1e-4 else (b_std if b_std > 1e-4 else 1.0)
        d_val = float(dev_means.get(feat, 0.0))
        z_score = (d_val - b_med) / scale

        # Calculate comparative multiplier
        if b_med > 1e-3:
            multiplier = round(d_val / b_med, 1)
        else:
            multiplier = round(d_val, 1)

        name = FEATURE_LABELS.get(feat, feat)

        # Formulate concise human-readable description
        if b_med > 0:
            desc = f"{name}: {d_val:,.1f} vs benign median {b_med:,.1f} (x{multiplier})"
        else:
            desc = f"{name}: {d_val:,.1f} vs benign median 0.0 (+{d_val:,.1f})"

        deviations.append({
            "feature": feat,
            "label": name,
            "device_value": round(d_val, 2),
            "benign_median": round(b_med, 2),
            "multiplier": multiplier,
            "z_score": round(float(z_score), 2),
            "description": desc,
        })

    # Sort by absolute z-score descending and return top 5
    deviations.sort(key=lambda x: abs(x["z_score"]), reverse=True)
    top_5 = deviations[:5]

    return {
        "host_ip": ip,
        "flows_analyzed": len(dev_flows),
        "deviations": top_5,
    }


@app.get("/api/model-card")
def get_model_card():
    """
    Evidence evaluation table and limitations for Random Forest and Autoencoder models.
    """
    return {
        "evidence": [
            {
                "test": "Known Attacks (Time Split)",
                "metric": "Recall (%)",
                "rf_score": 100.0,
                "ae_score": 100.0,
                "note": "Both models reliably classify known patterns present in training distribution.",
            },
            {
                "test": "Unseen SSH Brute Force",
                "metric": "Recall (%)",
                "rf_score": 0.0,
                "ae_score": 100.0,
                "note": "Random Forest fails completely when attack was excluded from training; Autoencoder flags anomalous reconstruction error.",
            },
            {
                "test": "Unseen Network Port Scan",
                "metric": "Recall (%)",
                "rf_score": 0.0,
                "ae_score": 100.0,
                "note": "Supervised model misses zero-day scan behavior; Autoencoder catches structural communication deviation.",
            },
            {
                "test": "Clean Benign Baseline",
                "metric": "False Positive Rate (%)",
                "rf_score": 0.0,
                "ae_score": 0.5,
                "note": "Random Forest produces zero false alarms; Autoencoder exhibits minimal 0.5% tolerance noise.",
            },
        ],
        "limitations": [
            "Single capture environment: Trained and benchmarked on Stratosphere IoT-23 capture topologies.",
            "Single active infected host: Reference slice contains host 192.168.2.5 as the sole compromised generator.",
            "Sparse C&C beaconing: Only 8 command-and-control beacon flows exist in the reference slice, requiring low cutoff percentages (<10%) for host isolation.",
            "Scan and SSH brute-force behaviors exhibit high volume variance and are comparatively easy to separate from quiescent IoT states.",
            "Feature extraction is limited to flow statistical aggregates and 1-minute window metrics; packet payloads and encrypted contents are uninspected.",
        ],
        "metadata": {
            "features_count": len(REAL_FEATURES),
            "model_family": "Dual-Engine Hybrid (Supervised RF + Unsupervised MLP Autoencoder)",
            "pipeline": "IoT-23 Real Feature Extraction & Sliding Window Profiling",
        },
    }
