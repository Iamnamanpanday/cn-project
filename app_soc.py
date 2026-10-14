"""SOC-style dashboard.  Run:  streamlit run app_soc.py"""
import html
import os
import tempfile
import time
from datetime import datetime, timezone

import networkx as nx
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from src import ui_helpers as ui
from src.config import REAL_PATH
from src.detector_real import (Detector, build_graph, block_rules, device_table,
                               load_any, suspicious_destinations)

st.set_page_config(page_title="IoT BOTNET // SOC", layout="wide", initial_sidebar_state="expanded")

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Barlow+Condensed:wght@500;600;700&display=swap');
:root{--bg:#07090a;--panel:#0b0f10;--line:#1b2326;--text:#c7d1cf;--dim:#5b6968;--ok:#3fb27f;--warn:#d9a441;--threat:#ff3b30;--threat-dim:#4a1512;}
.stApp{background:var(--bg);color:var(--text);font-family:'IBM Plex Mono',monospace;font-size:13px;}
header[data-testid="stHeader"],#MainMenu,footer{display:none!important;visibility:hidden;}
.block-container{padding-top:.8rem;max-width:1700px;}
section[data-testid="stSidebar"]{background:var(--panel);border-right:1px solid var(--line);}
h1,h2,h3,h4{font-family:'Barlow Condensed',sans-serif!important;text-transform:uppercase;letter-spacing:.12em;font-weight:600;color:var(--text);}
button[data-baseweb="tab"]{font-family:'Barlow Condensed',sans-serif;text-transform:uppercase;letter-spacing:.14em;font-size:15px;}
button[data-baseweb="tab"][aria-selected="true"]{color:var(--threat);}
div[data-baseweb="tab-highlight"]{background:var(--threat)!important;}
.stButton>button,.stDownloadButton>button{border-radius:0;border:1px solid var(--line);background:var(--panel);color:var(--text);font-family:'IBM Plex Mono',monospace;text-transform:uppercase;letter-spacing:.08em;}
.stButton>button:hover,.stDownloadButton>button:hover{border-color:var(--threat);color:var(--threat);}
.topbar{display:flex;justify-content:space-between;align-items:center;border:1px solid var(--line);background:var(--panel);padding:8px 14px;margin-bottom:10px;}
.topbar .name{font-family:'Barlow Condensed',sans-serif;font-size:22px;letter-spacing:.2em;font-weight:700;}
.topbar .meta{color:var(--dim);font-size:11px;letter-spacing:.06em;}
.lvl-badge{font-family:'Barlow Condensed',sans-serif;font-weight:700;letter-spacing:.2em;font-size:18px;padding:2px 14px;border:1px solid;}
.lvl-badge.ok{color:var(--ok);border-color:var(--ok);}
.lvl-badge.warn{color:var(--warn);border-color:var(--warn);}
.lvl-badge.crit{color:#fff;background:var(--threat);border-color:var(--threat);animation:blink 1.4s infinite;}
@keyframes blink{50%{opacity:.65}}
.kpi{border:1px solid var(--line);background:var(--panel);padding:10px 14px;}
.kpi .l{color:var(--dim);font-size:10px;letter-spacing:.16em;text-transform:uppercase;}
.kpi .v{font-family:'Barlow Condensed',sans-serif;font-size:38px;font-weight:600;line-height:1.1;font-variant-numeric:tabular-nums;}
.kpi .s{color:var(--dim);font-size:11px;}
.kpi.bad{border-color:var(--threat-dim);} .kpi.bad .v{color:var(--threat);}
.feed{border:1px solid var(--line);background:#050707;height:430px;overflow-y:auto;padding:6px 8px;font-size:11px;}
.feed .row{padding:2px 0;border-bottom:1px solid #0f1517;white-space:nowrap;}
.feed .ts{color:var(--dim);margin-right:8px;} .feed .dim{color:var(--dim);}
.lvl{display:inline-block;width:46px;margin-right:8px;font-weight:600;}
.lvl-CRIT{color:var(--threat);} .lvl-ALERT{color:#ff7a45;} .lvl-WARN{color:var(--warn);}
.host{border:1px solid var(--line);background:var(--panel);padding:7px 10px;margin-bottom:5px;position:relative;}
.host.bad{border-left:3px solid var(--threat);}
.host .hip{font-weight:600;font-size:13px;} .host .hmeta{color:var(--dim);font-size:10px;}
.host .bar{height:3px;background:var(--line);margin-top:4px;} .host .bar div{height:3px;background:var(--dim);}
.host.bad .bar div{background:var(--threat);}
.tag{position:absolute;right:10px;top:8px;font-size:10px;letter-spacing:.14em;font-weight:600;}
.tag.bad{color:var(--threat);} .tag.ok{color:var(--ok);}
.panel{border:1px solid var(--line);background:var(--panel);padding:10px 14px;margin-bottom:8px;}
.panel .t{color:var(--dim);font-size:10px;letter-spacing:.16em;text-transform:uppercase;margin-bottom:6px;}
.risk{font-family:'Barlow Condensed',sans-serif;font-size:64px;font-weight:700;line-height:1;}
.risk.bad{color:var(--threat);} .risk.ok{color:var(--ok);}
.dev{margin:5px 0;} .dev .n{display:flex;justify-content:space-between;font-size:12px;}
.dev .b{height:4px;background:var(--line);} .dev .b div{height:4px;background:var(--threat);}
.chain{display:flex;gap:6px;} .chain div{flex:1;text-align:center;padding:8px 0;border:1px solid var(--line);color:var(--dim);letter-spacing:.14em;font-size:11px;}
.chain div.on{border-color:var(--threat);color:var(--threat);background:var(--threat-dim);}
.boot{font-family:'IBM Plex Mono',monospace;color:var(--ok);font-size:12px;border:1px solid var(--line);padding:10px 14px;background:#050707;}
table.ev{width:100%;border-collapse:collapse;font-size:12px;} table.ev td,table.ev th{border:1px solid var(--line);padding:6px 10px;text-align:left;}
table.ev th{color:var(--dim);font-weight:500;letter-spacing:.1em;text-transform:uppercase;font-size:10px;}
td.bad{color:var(--threat);font-weight:600;} td.good{color:var(--ok);font-weight:600;}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


# ---------------- cached loaders ----------------
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
    return load_any(REAL_PATH)


@st.cache_data
def load_baseline():
    d = pd.read_csv(REAL_PATH)
    return ui.baseline(d[d.label == 0])


@st.cache_data
def run_scoring(df, rf_thr, ae_scale):
    return get_detector().score(df, rf_threshold=rf_thr, ae_scale=ae_scale)


# ---------------- sidebar ----------------
st.sidebar.markdown("### Data source")
source = st.sidebar.radio("source", ["Built-in sample", "Upload CSV"], label_visibility="collapsed")
st.sidebar.markdown("### Detection tuning")
rf_thr = st.sidebar.slider("Random Forest threshold", 0.1, 0.9, 0.5, 0.05)
ae_scale = st.sidebar.slider("Autoencoder tolerance", 1.0, 3.0, 1.0, 0.1)
cutoff = st.sidebar.slider("Host INFECTED if flagged % >", 5, 95, 30)
min_flows = st.sidebar.number_input("Min flows per host", 1, 100, 5)

if source == "Built-in sample":
    df, src_name = load_sample(), "iot23_small.csv"
else:
    up = st.sidebar.file_uploader("Processed CSV or raw Zeek log (csv)", type="csv")
    if up is None:
        st.markdown("<div class='panel'><div class='t'>Awaiting input</div>Upload a CSV in the sidebar or switch to the built-in sample.</div>", unsafe_allow_html=True)
        st.stop()
    df, src_name = load_bytes(up.getvalue(), up.name), up.name

scored = run_scoring(df, rf_thr, ae_scale)
devices = device_table(scored, cutoff, min_flows)
dests = suspicious_destinations(scored)
infected = devices[devices.status == "INFECTED"]
flag_pct = float(scored.is_botnet.mean() * 100)
level, lcls = ui.threat_level(flag_pct, len(infected))
base = load_baseline()
ipt_all, win_all = block_rules(devices, dests)

# ---------------- boot sequence (once per session) ----------------
if "booted" not in st.session_state:
    box, out = st.empty(), ""
    for line in ["loading random forest ........ OK", "loading autoencoder ......... OK",
                 f"flows loaded: {len(scored):,}", f"hosts observed: {scored.src_ip.nunique():,}", "console ready"]:
        out += f"<div>&gt; {line}</div>"
        box.markdown(f"<div class='boot'>{out}</div>", unsafe_allow_html=True)
        time.sleep(0.22)
    box.empty()
    st.session_state.booted = True
if "quarantined" not in st.session_state:
    st.session_state.quarantined = set()

# ---------------- top bar ----------------
now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
st.markdown(
    f"<div class='topbar'><div><span class='name'>IoT BOTNET // DETECTION CONSOLE</span><br>"
    f"<span class='meta'>SRC {html.escape(src_name)} &nbsp;|&nbsp; FLOWS {len(scored):,} &nbsp;|&nbsp; MODELS RF+AE LOADED &nbsp;|&nbsp; {now}</span></div>"
    f"<div><span class='meta'>THREAT LEVEL &nbsp;</span><span class='lvl-badge {lcls}'>{level}</span></div></div>",
    unsafe_allow_html=True)

# ---------------- KPI row ----------------
total_hosts = scored.src_ip.nunique()
k1, k2, k3, k4 = st.columns(4)
bad_cls = "bad" if len(infected) else ""
k1.markdown(f"<div class='kpi {bad_cls}'><div class='l'>Hosts compromised</div><div class='v'>{len(infected)} / {total_hosts}</div><div class='s'>cutoff {cutoff}% flagged</div></div>", unsafe_allow_html=True)
k2.markdown(f"<div class='kpi'><div class='l'>Flagged flows</div><div class='v'>{int(scored.is_botnet.sum()):,}</div><div class='s'>of {len(scored):,}</div></div>", unsafe_allow_html=True)
k3.markdown(f"<div class='kpi'><div class='l'>Flagged share</div><div class='v'>{flag_pct:.1f}%</div><div class='s'>RF {int((scored.reason.str.contains('known')).sum()):,} / AE-only {int((scored.reason == 'anomaly (unseen)').sum()):,}</div></div>", unsafe_allow_html=True)
if "label" in scored.columns and (scored.label == 1).any() and (scored.label == 0).any():
    rec = scored[scored.label == 1].is_botnet.mean() * 100
    fp = scored[scored.label == 0].is_botnet.mean() * 100
    k4.markdown(f"<div class='kpi'><div class='l'>Recall / false alarms</div><div class='v'>{rec:.0f}% / {fp:.1f}%</div><div class='s'>needs labels in file</div></div>", unsafe_allow_html=True)
else:
    k4.markdown("<div class='kpi'><div class='l'>Recall / false alarms</div><div class='v'>n/a</div><div class='s'>file has no labels or one class</div></div>", unsafe_allow_html=True)

tab_c, tab_h, tab_r, tab_m, tab_x = st.tabs(["Console", "Hosts", "Replay", "Models", "Response"])


# ---------------- helpers that need plotly ----------------
def graph_fig(G):
    pos = nx.spring_layout(G, seed=3, k=0.9)
    ex, ey = [], []
    for u, v in G.edges():
        ex += [pos[u][0], pos[v][0], None]
        ey += [pos[u][1], pos[v][1], None]
    fig = go.Figure(go.Scatter(x=ex, y=ey, mode="lines", line=dict(width=0.6, color="#2a3436"), hoverinfo="none", showlegend=False))
    for kind, color, size in [("suspicious destination", "#d9a441", 9), ("infected device", "#ff3b30", 24)]:
        nodes = [n for n, d in G.nodes(data=True) if d["kind"] == kind]
        fig.add_trace(go.Scatter(
            x=[pos[n][0] for n in nodes], y=[pos[n][1] for n in nodes], mode="markers+text", name=kind,
            text=[n if kind == "infected device" else "" for n in nodes], textposition="top center",
            textfont=dict(color="#c7d1cf", size=11), hovertext=nodes, hoverinfo="text",
            marker=dict(size=size, color=color, line=dict(width=2 if kind == "infected device" else 0, color="#4a1512"))))
    fig.update_layout(paper_bgcolor="#0b0f10", plot_bgcolor="#0b0f10", height=430, margin=dict(l=0, r=0, t=0, b=0),
                      xaxis=dict(visible=False), yaxis=dict(visible=False), legend=dict(orientation="h", y=0, font=dict(color="#5b6968")))
    return fig


def timeline_fig(tl):
    fig = go.Figure()
    fig.add_bar(x=tl.t, y=tl.normal, marker_color="#1f2b2e", name="normal")
    fig.add_bar(x=tl.t, y=tl.flagged, marker_color="#ff3b30", name="flagged")
    fig.update_layout(barmode="stack", paper_bgcolor="#0b0f10", plot_bgcolor="#0b0f10", height=190,
                      margin=dict(l=10, r=10, t=10, b=20), bargap=0.1, font=dict(color="#5b6968", size=10),
                      xaxis=dict(gridcolor="#1b2326"), yaxis=dict(gridcolor="#1b2326"), legend=dict(orientation="h", y=1.15))
    return fig


# ---------------- CONSOLE ----------------
with tab_c:
    left, right = st.columns([2.2, 1])
    with left:
        st.markdown("#### Communication topology")
        G = build_graph(scored, devices)
        if G.number_of_nodes() == 0:
            st.markdown("<div class='panel'><div class='t'>Topology</div>No infected hosts. Nothing to draw.</div>", unsafe_allow_html=True)
        else:
            st.plotly_chart(graph_fig(G), theme=None)
    with right:
        st.markdown("#### Alert feed")
        st.markdown(ui.feed_html(ui.feed_lines(scored, 60)), unsafe_allow_html=True)
    st.markdown("#### Traffic timeline (red = flagged)")
    st.plotly_chart(timeline_fig(ui.timeline(scored)), theme=None)

# ---------------- HOSTS ----------------
with tab_h:
    hl, hr = st.columns([1, 2])
    with hl:
        st.markdown("#### Hosts by risk")
        st.markdown(ui.host_rows_html(devices), unsafe_allow_html=True)
    with hr:
        options = devices.src_ip.tolist()
        pick = st.selectbox("Open dossier", options, index=0)
        row = devices[devices.src_ip == pick].iloc[0]
        h = scored[scored.src_ip == pick]
        is_bad = row["status"] == "INFECTED"
        risk = int(round(max(row["flagged_%"], row["avg_rf_prob"] * 100)))
        d1, d2 = st.columns([1, 2])
        d1.markdown(f"<div class='panel'><div class='t'>Risk score</div><div class='risk {'bad' if is_bad else 'ok'}'>{risk}</div>"
                    f"<div class='s'>{'INFECTED' if is_bad else 'CLEAN'} &nbsp;|&nbsp; {int(row['flows']):,} flows</div></div>", unsafe_allow_html=True)
        reasons = h.reason.value_counts()
        rs = "".join(f"<div class='dev'><div class='n'><span>{html.escape(k)}</span><span>{v:,}</span></div></div>" for k, v in reasons.items())
        d2.markdown(f"<div class='panel'><div class='t'>Flows by verdict</div>{rs}</div>", unsafe_allow_html=True)

        devs = ui.deviations(h, base)
        mx = max([d["score"] for d in devs] + [1])
        items = "".join(
            f"<div class='dev'><div class='n'><span>{html.escape(d['feature'])}</span>"
            f"<span>{ui.num(d['host'])} vs benign {ui.num(d['benign'])}</span></div>"
            f"<div class='b'><div style='width:{min(d['score'] / mx * 100, 100):.0f}%'></div></div></div>" for d in devs)
        st.markdown(f"<div class='panel'><div class='t'>Why flagged: behavioural deviation from benign baseline</div>{items}</div>", unsafe_allow_html=True)

        chain, how = ui.kill_chain(h)
        cells = "".join(f"<div class='{'on' if on else ''}'>{k}</div>" for k, on in chain.items())
        st.markdown(f"<div class='panel'><div class='t'>Kill chain ({how})</div><div class='chain'>{cells}</div></div>", unsafe_allow_html=True)

        if is_bad:
            if pick in st.session_state.quarantined:
                st.error(f"QUARANTINE SIMULATED for {pick}. No real firewall was changed.")
            elif st.button(f"Quarantine {pick} (simulation)"):
                st.session_state.quarantined.add(pick)
                st.rerun()

# ---------------- REPLAY ----------------
with tab_r:
    st.markdown("Replays traffic in time order, in batches, as if it were arriving live.")
    c1, c2 = st.columns(2)
    n_flows = c1.slider("Flows to replay", 200, 3000, 800, 100)
    batch = c2.slider("Batch size", 10, 150, 40, 10)
    if st.button("Start replay"):
        sub = scored.copy()
        if "timestamp" in sub.columns:
            sub["_t"] = pd.to_datetime(sub["timestamp"], errors="coerce")
            sub = sub.sort_values("_t")
        sub = sub.head(n_flows)
        counter, chart_box, feed_box = st.empty(), st.empty(), st.empty()
        seen = flagged_total = 0
        hist = []
        for i in range(0, len(sub), batch):
            chunk = sub.iloc[i:i + batch]
            seen += len(chunk)
            flagged_total += int(chunk.is_botnet.sum())
            hist.append({"flows seen": seen, "flagged": flagged_total})
            counter.markdown(f"<div class='kpi bad'><div class='l'>Replay</div><div class='v'>{flagged_total:,} flagged / {seen:,} seen</div></div>", unsafe_allow_html=True)
            chart_box.line_chart(pd.DataFrame(hist).set_index("flows seen"), color="#ff3b30")
            feed_box.markdown(ui.feed_html(ui.feed_lines(chunk, 25), "latest batch: normal"), unsafe_allow_html=True)
            time.sleep(0.35)

# ---------------- MODELS ----------------
with tab_m:
    st.markdown("#### Why two models")
    st.markdown(
        "<table class='ev'><tr><th>Test (time split, single capture)</th><th>Random Forest</th><th>Autoencoder</th></tr>"
        "<tr><td>Known attacks</td><td class='good'>100%</td><td class='good'>100%</td></tr>"
        "<tr><td>Unseen SSH brute force</td><td class='bad'>0%</td><td class='good'>100%</td></tr>"
        "<tr><td>Unseen port scan</td><td class='bad'>0%</td><td class='good'>100%</td></tr>"
        "<tr><td>False positive rate</td><td class='good'>0.0%</td><td>0.5%</td></tr></table>"
        "<div class='s' style='color:#5b6968;margin-top:4px'>Source: src/train_ae_real.py. The Random Forest only knows attacks it was shown; the autoencoder flags anything unlike normal traffic.</div>",
        unsafe_allow_html=True)
    if os.path.exists("data/cross_capture_results.csv"):
        st.markdown("#### Cross-capture results (train on other captures, test on held-out)")
        st.dataframe(pd.read_csv("data/cross_capture_results.csv"), hide_index=True)
    st.markdown("#### Limitations")
    st.markdown(
        "<div class='panel'>- Few captures and few infected hosts, so results may not generalise.<br>"
        "- Very few command-and-control (C&C) flows in the training data.<br>"
        "- Scans and SSH brute force are easy to separate from benign traffic; subtler botnets would be harder.<br>"
        "- Scoring data the models trained on gives optimistic numbers.</div>", unsafe_allow_html=True)

# ---------------- RESPONSE ----------------
with tab_x:
    st.markdown("<div class='panel'><div class='t'>Notice</div>Rules are generated as text only. Nothing is executed on any system. Review before use.</div>", unsafe_allow_html=True)
    a, b = st.columns(2)
    a.markdown("#### Linux (iptables)")
    a.code(ipt_all)
    a.download_button("Download iptables rules", ipt_all, "block_rules.sh")
    b.markdown("#### Windows (netsh)")
    b.code(win_all)
    b.download_button("Download netsh rules", win_all, "block_rules.bat")
    st.markdown("#### Incident report")
    summary = {"flows": f"{len(scored):,}", "flagged": f"{int(scored.is_botnet.sum()):,}",
               "flagged %": f"{flag_pct:.1f}", "infected hosts": len(infected), "threat level": level}
    rep = ui.report_html(summary, devices, dests, ipt_all)
    st.download_button("Download incident report (open, then Print > Save as PDF)", rep, "incident_report.html", mime="text/html")