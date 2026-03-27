#!/usr/bin/env python3

import csv
import glob
import os
import sys
from collections import defaultdict

def aggregate_cdc(cdc_dir: str) -> None:
    pattern = os.path.join(cdc_dir, "cdc-histogram-*.csv")
    files = glob.glob(pattern)

    if not files:
        raise RuntimeError(f"No histogram files found in {cdc_dir}")

    segment_counts = defaultdict(int)
    duplicate_counts = defaultdict(int)

    for path in files:
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                size = int(row["chunk_size_bytes"])
                segment_counts[size] += int(row["count"])
                duplicate_counts[size] += int(row["duplicates"])

    out_path = os.path.join(cdc_dir, "cdc-aggregated.csv")

    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "chunk_size_bytes",
            "count",
            "duplicates",
        ])

        for size in sorted(segment_counts):
            writer.writerow([
                size,
                segment_counts[size],
                duplicate_counts[size],
            ])

    print(f"Wrote {out_path}")

def main() -> None:
    if len(sys.argv) != 2:
        print("usage: aggregate_cdc.py <cdc_directory>")
        sys.exit(1)

    aggregate_cdc(sys.argv[1])

if __name__ == "__main__":
    main()
