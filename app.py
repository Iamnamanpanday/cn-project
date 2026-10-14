import os
import os
import tempfile
import time
import networkx as nx
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from src.detector_real import (Detector, load_any, device_table,
                               suspicious_destinations, build_graph, block_rules)

st.set_page_config(page_title="IoT Botnet Detector", layout="wide")
st.title("AI-Based IoT Botnet Detector")
st.caption("Random Forest (known attacks) + Autoencoder (unseen anomalies) on real IoT-23 traffic")


@st.cache_resource
def get_detector():
    return Detector()


@st.cache_data
def load_bytes(data: bytes, name: str):
    path = os.path.join(tempfile.gettempdir(), name)
    with open(path, "wb") as f:
        f.write(data)
    return load_any(path)


@st.cache_data
def load_sample():
    return load_any("data/iot23_small.csv")


@st.cache_data
def run_scoring(df, rf_thr, ae_scale):
    return get_detector().score(df, rf_threshold=rf_thr, ae_scale=ae_scale)


# ---------------- sidebar ----------------
st.sidebar.header("Data")
source = st.sidebar.radio("Source", ["Sample (iot23_small.csv)", "Upload CSV"])
rf_thr = st.sidebar.slider("Random Forest threshold", 0.1, 0.9, 0.5, 0.05)
ae_scale = st.sidebar.slider("Autoencoder tolerance (higher = fewer alerts)", 1.0, 3.0, 1.0, 0.1)
cutoff = st.sidebar.slider("Device is INFECTED if flagged % >", 5, 95, 30)
min_flows = st.sidebar.number_input("Min flows per device", 1, 100, 5)

if source.startswith("Sample"):
    df = load_sample()
else:
    up = st.sidebar.file_uploader("Processed CSV or raw Zeek conn.log.labeled CSV", type="csv")
    if up is None:
        st.info("Upload a CSV in the sidebar, or switch to the sample data.")
        st.stop()
    df = load_bytes(up.getvalue(), up.name)

scored = run_scoring(df, rf_thr, ae_scale)
devices = device_table(scored, cutoff, min_flows)
dests = suspicious_destinations(scored)
infected = devices[devices.status == "INFECTED"]

tab1, tab2, tab3, tab4, tab5 = st.tabs(["Overview", "Devices", "Graph", "Live replay", "Mitigation"])

# ---------------- Overview ----------------
with tab1:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Flows analysed", f"{len(scored):,}")
    c2.metric("Flagged flows", f"{int(scored.is_botnet.sum()):,}")
    c3.metric("Flagged %", f"{scored.is_botnet.mean() * 100:.1f}%")
    c4.metric("Infected devices", len(infected))

    left, right = st.columns(2)
    with left:
        counts = scored.reason.value_counts().reset_index()
        counts.columns = ["reason", "flows"]
        st.plotly_chart(px.pie(counts, names="reason", values="flows", title="Why flows were flagged"))
    with right:
        if "attack_type" in scored.columns:
            t = scored.groupby("attack_type").is_botnet.mean().mul(100).round(1).reset_index()
            t.columns = ["attack_type", "detected_%"]
            st.plotly_chart(px.bar(t, x="attack_type", y="detected_%", title="Detection rate by traffic type (needs labels)"))

    if "label" in scored.columns:
        ben, mal = scored[scored.label == 0], scored[scored.label == 1]
        a, b = st.columns(2)
        if len(mal):
            a.metric("Recall (malicious caught)", f"{mal.is_botnet.mean() * 100:.1f}%")
        if len(ben):
            b.metric("False positive rate", f"{ben.is_botnet.mean() * 100:.2f}%")
        st.caption("Note: if you scan the same data the models were trained on, these numbers are optimistic.")

    st.subheader("Most suspicious flows")
    cols = [c for c in ["timestamp", "src_ip", "dst_ip", "dst_port", "rf_prob", "ae_error", "reason"] if c in scored.columns]
    st.dataframe(scored.sort_values("rf_prob", ascending=False).head(200)[cols])

# ---------------- Devices ----------------
with tab2:
    st.subheader("Per-device risk")
    if len(infected):
        st.error(f"{len(infected)} device(s) look infected: " + ", ".join(infected.src_ip.head(10)))
    else:
        st.success("No device crossed the infection threshold.")
    st.dataframe(devices)
    st.subheader("Most contacted suspicious destinations")
    st.dataframe(dests)

# ---------------- Graph ----------------
with tab3:
    G = build_graph(scored, devices)
    if G.number_of_nodes() == 0:
        st.info("No infected devices, so there is nothing to draw.")
    else:
        pos = nx.spring_layout(G, seed=1, k=0.9)
        ex, ey = [], []
        for u, v in G.edges():
            ex += [pos[u][0], pos[v][0], None]
            ey += [pos[u][1], pos[v][1], None]
        fig = go.Figure(go.Scatter(x=ex, y=ey, mode="lines", line=dict(width=0.7, color="#999"), hoverinfo="none"))
        for kind, color in [("infected device", "red"), ("suspicious destination", "orange")]:
            nodes = [n for n, d in G.nodes(data=True) if d["kind"] == kind]
            fig.add_trace(go.Scatter(
                x=[pos[n][0] for n in nodes], y=[pos[n][1] for n in nodes], mode="markers+text",
                text=[n if kind == "infected device" else "" for n in nodes], textposition="top center",
                hovertext=nodes, hoverinfo="text", name=kind,
                marker=dict(size=22 if kind == "infected device" else 10, color=color)))
        fig.update_layout(title="Communication graph: infected devices and who they talk to",
                          xaxis=dict(visible=False), yaxis=dict(visible=False), height=600)
        st.plotly_chart(fig)
        st.caption("Destinations contacted by several infected devices are the best command-and-control candidates.")

# ---------------- Live replay ----------------
with tab4:
    st.write("Replays traffic in time order, in small batches, as if it were arriving live.")
    n_flows = st.slider("Flows to replay", 200, 2000, 600, 100)
    batch = st.slider("Batch size", 10, 100, 40, 10)
    if st.button("Start replay"):
        sub = scored.sort_values("timestamp").head(n_flows) if "timestamp" in scored.columns else scored.head(n_flows)
        chart_box, alert_box = st.empty(), st.empty()
        seen, flagged_total, history = 0, 0, []
        for i in range(0, len(sub), batch):
            chunk = sub.iloc[i:i + batch]
            seen += len(chunk)
            flagged_total += int(chunk.is_botnet.sum())
            history.append({"flows seen": seen, "flagged so far": flagged_total})
            chart_box.line_chart(pd.DataFrame(history).set_index("flows seen"))
            bad_ips = chunk.loc[chunk.is_botnet, "src_ip"].value_counts()
            if len(bad_ips):
                alert_box.warning(f"ALERT: {bad_ips.index[0]} sent {int(bad_ips.iloc[0])} suspicious flows in the latest batch")
            else:
                alert_box.success("Latest batch looks normal")
            time.sleep(0.4)

# ---------------- Mitigation ----------------
with tab5:
    ipt, win = block_rules(devices, dests)
    st.warning("These rules are only generated as text. Nothing is executed. Review before use.")
    st.subheader("Linux (iptables)")
    st.code(ipt)
    st.download_button("Download iptables rules", ipt, "block_rules.sh")
    st.subheader("Windows (netsh)")
    st.code(win)
    st.download_button("Download netsh rules", win, "block_rules.bat")