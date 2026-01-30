#!/usr/bin/env python3
"""Prepare CDC data for heatmap visualization."""

import csv
from collections import defaultdict

def bin_data(filename, bin_size=512):
    """Read CSV and bin data by chunk size."""
    bins = defaultdict(lambda: {'count': 0, 'duplicates': 0})

    with open(filename, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            chunk_size = int(row['chunk_size_bytes'])
            count = int(row['count'])
            dups = int(row['duplicates'])

            # Calculate bin
            bin_key = (chunk_size // bin_size) * bin_size
            bins[bin_key]['count'] += count
            bins[bin_key]['duplicates'] += dups

    return bins

def main():
    bin_size = 1024

    # Process each CDC algorithm
    algorithms = {
        'FastHash': 'fast_hash_cdc/cdc-aggregated.csv',
        'GearHash': 'gear_hash_cdc/cdc-aggregated.csv',
        'MinHash': 'min_hash_cdc/cdc-aggregated.csv'
    }

    all_bins = set()
    algo_data = {}

    # Collect data for each algorithm
    for algo_name, filename in algorithms.items():
        bins = bin_data(filename, bin_size)
        algo_data[algo_name] = bins
        all_bins.update(bins.keys())

    # Sort bins
    sorted_bins = sorted(all_bins)

    # Write matrix data for gnuplot
    with open('cdc_heatmap_data.txt', 'w') as f:
        # Write header
        f.write("# chunk_size_kb algorithm duplicate_rate\n")

        # Write data
        for algo_idx, algo_name in enumerate(['FastHash', 'GearHash', 'MinHash']):
            for bin_key in sorted_bins:
                chunk_kb = bin_key / 1024.0
                data = algo_data[algo_name].get(bin_key, {'count': 0, 'duplicates': 0})
                if data['count'] > 0:
                    dup_rate = data['duplicates'] / data['count']
                else:
                    dup_rate = 0
                f.write(f"{chunk_kb} {algo_idx} {dup_rate}\n")
            f.write("\n")  # Blank line between algorithms

    print(f"Processed data written to cdc_heatmap_data.txt")
    print(f"Chunk size range: {min(sorted_bins)} to {max(sorted_bins)} bytes")
    print(f"Number of bins: {len(sorted_bins)}")

if __name__ == '__main__':
    main()
