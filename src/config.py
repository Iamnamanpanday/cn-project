SEED = 42

# ---------- synthetic data (old pipeline) ----------
DATA_PATH = "data/flows.csv"
MODEL_DIR = "models"
FEATURES = [
    "flow_duration", "fwd_packets", "bwd_packets", "pkt_len_mean", "pkt_len_std",
    "pkts_per_sec", "bytes_per_sec", "iat_mean", "syn_count", "ack_count",
    "rst_count", "unique_dst_ips", "dst_port", "protocol",
]

# ---------- real IoT-23 data (new pipeline) ----------
REAL_PATH = "data/iot23_small.csv"

# per-flow features (what one connection looks like)
FLOW_FEATURES = [
    "duration", "orig_pkts", "resp_pkts", "orig_bytes", "resp_bytes", "missed_bytes",
    "bytes_per_sec", "pkts_per_sec", "avg_pkt_size", "byte_ratio", "dst_port",
    "is_tcp", "is_udp", "is_icmp",
    "state_S0", "state_SF", "state_REJ", "state_RST", "state_OTH",
    "hist_S", "hist_A", "hist_D", "hist_F", "hist_R",
]
# per-device behaviour in the last minute (communication pattern of the SOURCE device)
WINDOW_FEATURES = [
    "src_flows_1m", "src_unique_dst_ips_1m", "src_unique_dst_ports_1m", "src_fail_ratio_1m",
]
REAL_FEATURES = FLOW_FEATURES + WINDOW_FEATURES