import numpy as np
import pandas as pd
import os
from src.config import SEED, DATA_PATH

rng = np.random.default_rng(SEED)

DEVICE_TYPES = {
    "camera":     dict(pps=(40, 10),   plen=(700, 100), ports=[443, 554, 8080]),
    "thermostat": dict(pps=(2, 1),     plen=(150, 40),  ports=[443, 1883, 8883]),
    "bulb":       dict(pps=(1, 0.5),   plen=(90, 20),   ports=[443, 1883]),
    "smart_plug": dict(pps=(1.5, 0.7), plen=(100, 25),  ports=[443, 1883, 53]),
}
C2_SERVERS = ["185.220.101.5", "45.155.205.9", "91.92.251.7"]
VICTIMS = ["203.0.113.10", "203.0.113.20"]
CLOUD = [f"34.120.{i}.{j}" for i in range(1, 4) for j in range(1, 6)]


def benign_flow(dtype):
    d = DEVICE_TYPES[dtype]
    pps = max(0.2, rng.normal(*d["pps"]))
    plen = max(40, rng.normal(*d["plen"]))
    return dict(
        flow_duration=rng.gamma(2, 5),
        fwd_packets=rng.poisson(max(1, pps * 3)),
        bwd_packets=rng.poisson(max(1, pps * 2.5)),
        pkt_len_mean=plen, pkt_len_std=abs(rng.normal(plen * 0.2, 10)) + 1,
        pkts_per_sec=pps, bytes_per_sec=pps * plen,
        iat_mean=1 / pps * rng.uniform(0.8, 1.2),
        syn_count=rng.poisson(1), ack_count=rng.poisson(8), rst_count=rng.poisson(0.1),
        unique_dst_ips=int(rng.integers(1, 4)),
        dst_port=int(rng.choice(d["ports"])),
        protocol=int(rng.choice([0, 1], p=[0.8, 0.2])),
        dst_ip=str(rng.choice(CLOUD)), label=0, attack_type="benign",
    )


def botnet_flow():
    kind = rng.choice(["scan", "flood", "c2"], p=[0.45, 0.35, 0.20])
    if kind == "scan":
        pps = rng.normal(150, 40)
        return dict(
            flow_duration=rng.gamma(1, 1), fwd_packets=rng.poisson(80),
            bwd_packets=rng.poisson(2), pkt_len_mean=rng.normal(70, 15),
            pkt_len_std=abs(rng.normal(8, 3)) + 1, pkts_per_sec=pps,
            bytes_per_sec=pps * 70, iat_mean=1 / max(pps, 1),
            syn_count=rng.poisson(60), ack_count=rng.poisson(2),
            rst_count=rng.poisson(10), unique_dst_ips=int(rng.integers(50, 300)),
            dst_port=int(rng.choice([23, 2323, 37215])), protocol=0,
            dst_ip=f"{rng.integers(1,223)}.{rng.integers(0,255)}.{rng.integers(0,255)}.{rng.integers(1,254)}",
            label=1, attack_type="scan",
        )
    if kind == "flood":
        pps = rng.normal(900, 200)
        return dict(
            flow_duration=rng.gamma(2, 2), fwd_packets=rng.poisson(600),
            bwd_packets=rng.poisson(1), pkt_len_mean=rng.normal(512, 40),
            pkt_len_std=abs(rng.normal(5, 2)) + 1, pkts_per_sec=pps,
            bytes_per_sec=pps * 512, iat_mean=1 / max(pps, 1),
            syn_count=rng.poisson(5), ack_count=rng.poisson(1),
            rst_count=rng.poisson(1), unique_dst_ips=1,
            dst_port=int(rng.choice([80, 53])), protocol=int(rng.choice([0, 1])),
            dst_ip=str(rng.choice(VICTIMS)), label=1, attack_type="flood",
        )
    # c2 beacon: quiet and small
    pps = max(rng.normal(1.5, 0.5), 0.2)
    return dict(
        flow_duration=rng.gamma(2, 3), fwd_packets=rng.poisson(4),
        bwd_packets=rng.poisson(4), pkt_len_mean=rng.normal(110, 15),
        pkt_len_std=abs(rng.normal(12, 4)) + 1, pkts_per_sec=pps,
        bytes_per_sec=pps * 110, iat_mean=rng.normal(30, 3),
        syn_count=1, ack_count=rng.poisson(4), rst_count=0, unique_dst_ips=1,
        dst_port=int(rng.choice([48101, 443])), protocol=0,
        dst_ip=str(rng.choice(C2_SERVERS)), label=1, attack_type="c2",
    )


def generate(n_devices=40, n_infected=8, flows_per_device=300):
    rows = []
    infected = set(int(x) for x in rng.choice(n_devices, n_infected, replace=False))
    t0 = pd.Timestamp("2026-01-01 00:00:00")
    for i in range(n_devices):
        ip = f"192.168.1.{10 + i}"
        dtype = str(rng.choice(list(DEVICE_TYPES)))
        for k in range(flows_per_device):
            bad = i in infected and rng.random() < 0.7
            f = botnet_flow() if bad else benign_flow(dtype)
            f.update(src_ip=ip, device_type=dtype,
                     timestamp=t0 + pd.Timedelta(seconds=int(k * 12 + rng.integers(0, 10))))
            rows.append(f)
    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    return df, sorted(f"192.168.1.{10 + i}" for i in infected)


if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    df, infected = generate()
    df.to_csv(DATA_PATH, index=False)
    df.drop(columns=["label", "attack_type"]).sample(2000, random_state=1) \
      .sort_values("timestamp").to_csv("data/sample_upload.csv", index=False)
    print(f"Saved {len(df)} flows. Malicious: {df.label.sum()}")
    print("Infected devices:", infected)