"""Pure helper functions for the dashboard (no Streamlit inside, so they are easy to test)."""
import html
import numpy as np
import pandas as pd
from src.config import REAL_FEATURES

NAMES = {
    "duration": "connection duration (s)", "orig_pkts": "packets sent", "resp_pkts": "packets received",
    "orig_bytes": "bytes sent", "resp_bytes": "bytes received", "missed_bytes": "missed bytes",
    "bytes_per_sec": "bytes per second", "pkts_per_sec": "packets per second",
    "avg_pkt_size": "average packet size", "byte_ratio": "sent/received byte ratio",
    "dst_port": "destination port", "is_tcp": "TCP share", "is_udp": "UDP share", "is_icmp": "ICMP share",
    "state_S0": "half-open connections (S0)", "state_SF": "completed connections",
    "state_REJ": "rejected connections", "state_RST": "reset connections", "state_OTH": "other conn states",
    "hist_S": "SYN flags", "hist_A": "ACK flags", "hist_D": "data packets", "hist_F": "FIN flags",
    "hist_R": "RST flags", "src_flows_1m": "flows from host per minute",
    "src_unique_dst_ips_1m": "unique destinations per minute", "src_unique_dst_ports_1m": "unique ports per minute",
    "src_fail_ratio_1m": "failed-connection ratio",
}


def num(x):
    x = float(x)
    if abs(x) >= 1000:
        return f"{x:,.0f}"
    if abs(x) >= 10:
        return f"{x:.1f}"
    return f"{x:.3g}"


def threat_level(flagged_pct, n_infected):
    if n_infected >= 1:
        return ("CRITICAL", "crit") if flagged_pct >= 20 else ("ELEVATED", "warn")
    return ("ELEVATED", "warn") if flagged_pct >= 5 else ("NOMINAL", "ok")


def baseline(benign):
    med = benign[REAL_FEATURES].median()
    return pd.DataFrame({"median": med, "std": benign[REAL_FEATURES].std()})


def deviations(host_df, base, top=5):
    """How far this host's behaviour is from the benign median (robust z-score)."""
    use = host_df[host_df.is_botnet] if host_df.is_botnet.any() else host_df
    hv = use[REAL_FEATURES].median()
    scale = base["std"].clip(lower=1e-6)
    z = ((hv - base["median"]).abs() / scale).sort_values(ascending=False)
    return [dict(feature=NAMES.get(c, c), host=float(hv[c]), benign=float(base.loc[c, "median"]),
                 score=float(min(z[c], 999))) for c in z.index[:top]]


def kill_chain(host_df):
    bad = host_df[host_df.is_botnet]
    if bad.empty:
        return {"RECON": False, "ATTACK": False, "C2": False}, "no flagged flows"
    if "attack_type" in bad.columns and bad.attack_type.isin(["scan", "attack", "c2"]).any():
        seen = set(bad.attack_type)
        return {"RECON": "scan" in seen, "ATTACK": "attack" in seen, "C2": "c2" in seen}, "from dataset labels"
    recon = bool(bad.state_S0.mean() > 0.5 or bad.src_unique_dst_ips_1m.max() > 50)
    attack = bool(((bad.dst_port.isin([22, 23, 2323, 80, 8080])) & (bad.state_SF == 1)).any())
    return {"RECON": recon, "ATTACK": attack, "C2": False}, "heuristic (no labels in file)"


def _ts(df):
    if "timestamp" in df.columns:
        return pd.to_datetime(df["timestamp"], errors="coerce")
    return pd.Series(pd.NaT, index=df.index)


def feed_lines(df, n=40):
    bad = df[df.is_botnet].copy()
    bad["_t"] = _ts(bad)
    bad = bad.sort_values("_t", ascending=False).head(n) if bad["_t"].notna().any() else bad.head(n)
    lvl = {"known attack + anomaly": "CRIT", "known attack": "ALERT", "anomaly (unseen)": "WARN"}
    out = []
    for _, r in bad.iterrows():
        t = r["_t"].strftime("%H:%M:%SZ") if pd.notna(r["_t"]) else "--:--:--Z"
        out.append(dict(ts=t, level=lvl.get(r["reason"], "WARN"),
                        text=f'{r["src_ip"]} -> {r["dst_ip"]}:{int(r["dst_port"])}  rf={r["rf_prob"]:.2f} ae={r["ae_error"]:.2f}'))
    return out


def feed_html(lines, empty="NO ALERTS. TRAFFIC WITHIN BASELINE."):
    if not lines:
        return f"<div class='feed'><div class='row dim'>{html.escape(empty)}</div></div>"
    rows = "".join(
        f"<div class='row'><span class='ts'>{html.escape(l['ts'])}</span>"
        f"<span class='lvl lvl-{l['level']}'>{l['level']}</span>{html.escape(l['text'])}</div>" for l in lines)
    return f"<div class='feed'>{rows}</div>"


def host_rows_html(devices, limit=25):
    rows = []
    for _, r in devices.head(limit).iterrows():
        bad = r["status"] == "INFECTED"
        rows.append(
            f"<div class='host {'bad' if bad else ''}'><div class='hip'>{html.escape(str(r['src_ip']))}</div>"
            f"<div class='hmeta'>{int(r['flows']):,} flows / {int(r['flagged']):,} flagged</div>"
            f"<div class='bar'><div style='width:{min(float(r['flagged_%']), 100):.0f}%'></div></div>"
            f"<div class='tag {'bad' if bad else 'ok'}'>{r['status']}</div></div>")
    return "".join(rows)


def timeline(scored, bins=60):
    t = _ts(scored)
    if t.notna().sum() == 0:
        pos = pd.Series(np.arange(len(scored)), index=scored.index).astype(float)
        edges = np.linspace(pos.min(), pos.max() + 1, bins + 1)
        labels = [str(int(e)) for e in edges[:-1]]
    else:
        pos = t.astype("int64").astype(float)
        edges = np.linspace(pos.min(), pos.max() + 1, bins + 1)
        labels = list(pd.to_datetime(edges[:-1].astype("int64")))
    b = np.clip(np.searchsorted(edges, pos.values, side="right") - 1, 0, bins - 1)
    flagged = np.bincount(b[scored.is_botnet.values], minlength=bins)
    total = np.bincount(b, minlength=bins)
    return pd.DataFrame({"t": labels, "normal": total - flagged, "flagged": flagged})


def report_html(summary, devices, dests, rules_ipt):
    inf = devices[devices.status == "INFECTED"]
    css = ("body{font-family:Arial,sans-serif;max-width:900px;margin:30px auto;color:#111}"
           "h1{border-bottom:3px solid #c00;padding-bottom:6px}table{border-collapse:collapse;width:100%;font-size:12px}"
           "td,th{border:1px solid #bbb;padding:4px 6px;text-align:left}th{background:#eee}pre{background:#f4f4f4;padding:8px;font-size:11px}"
           ".k{display:inline-block;margin-right:24px}")
    ks = "".join(f"<div class='k'><b>{html.escape(k)}</b><br>{html.escape(str(v))}</div>" for k, v in summary.items())
    return (f"<html><head><meta charset='utf-8'><title>Incident report</title><style>{css}</style></head><body>"
            f"<h1>IoT Botnet Incident Report</h1><p>Generated {pd.Timestamp.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>"
            f"<h2>Summary</h2><p>{ks}</p><h2>Infected hosts</h2>"
            + (inf.to_html(index=False, escape=True) if len(inf) else "<p>None.</p>")
            + "<h2>Suspicious destinations</h2>" + (dests.head(10).to_html(index=False, escape=True) if len(dests) else "<p>None.</p>")
            + f"<h2>Recommended blocks (not executed)</h2><pre>{html.escape(rules_ipt)}</pre>"
            "<h2>Notes</h2><p>Detection combines a Random Forest (known attacks) and an autoencoder trained on benign "
            "traffic (unseen anomalies). Results depend on the captures used for training; see the limitations in the dashboard.</p>"
            "</body></html>")