"""
Shrink big IoT-23 files into a small balanced CSV (~10k rows).

Usage (from project root):
  python -m src.sample_data data/iot23/capture_a.log.labeled data/iot23/capture_b.log.labeled
Accepts Zeek conn.log.labeled files or plain CSVs that have a 'label' column.
"""
import sys
import os
import pandas as pd

PER_CLASS = 2500        # max rows per class PER FILE (3 files -> ~10-15k rows)
CHUNK = 200_000
OUT = "data/iot23_small.csv"


def read_chunks(path):
    if path.endswith(".csv"):
        yield from pd.read_csv(path, chunksize=CHUNK, low_memory=False)
        return
    # Zeek conn.log.labeled (tab separated, '#' header lines)
    fields = None
    with open(path, "r", errors="ignore") as f:
        for line in f:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                break
    if fields is None:
        raise ValueError(f"No '#fields' header in {path}. Paste me the first lines.")
    # last header is 'tunnel_parents   label   detailed-label' (space separated)
    last = fields[-1]
    for chunk in pd.read_csv(path, sep="\t", comment="#", names=fields, header=None,
                             chunksize=CHUNK, low_memory=False, na_values=["-"]):
        parts = chunk[last].astype(str).str.split(r"\s+", n=2, expand=True)
        chunk = chunk.drop(columns=[last])
        chunk["label"] = parts[1]
        chunk["detailed_label"] = parts[2] if parts.shape[1] > 2 else ""
        yield chunk


def sample_file(path):
    keep = []
    for chunk in read_chunks(path):
        chunk.columns = [c.strip() for c in chunk.columns]
        lab_col = next(c for c in chunk.columns if c.lower() == "label")
        chunk["is_bot"] = (~chunk[lab_col].astype(str).str.lower().str.startswith("benign")).astype(int)
        for _, g in chunk.groupby("is_bot"):
            keep.append(g.sample(min(len(g), PER_CLASS), random_state=1))
    df = pd.concat(keep)
    out = []
    for _, g in df.groupby("is_bot"):
        out.append(g.sample(min(len(g), PER_CLASS), random_state=1))
    df = pd.concat(out)
    df["capture"] = os.path.basename(path)
    return df


if __name__ == "__main__":
    files = sys.argv[1:]
    if not files:
        sys.exit("Give at least one file path.")
    parts = []
    for p in files:
        d = sample_file(p)
        print(f"{os.path.basename(p)}: {len(d)} rows  (malicious={int(d.is_bot.sum())})")
        parts.append(d)
    final = pd.concat(parts).sample(frac=1, random_state=1).reset_index(drop=True)
    final.to_csv(OUT, index=False)
    print(f"\nSaved {OUT}: {len(final)} rows, {os.path.getsize(OUT)/1e6:.1f} MB")
    print("Columns:", list(final.columns))