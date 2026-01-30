#!/usr/bin/env python3
"""Prepare CDC data as a matrix for heatmap visualization."""

import csv
from collections import defaultdict
import numpy as np

def bin_data(filename, bin_size=1024):
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
    algorithms = ['FastHash', 'GearHash', 'MinHash']
    algo_files = {
        'FastHash': 'fast_hash_cdc/cdc-aggregated.csv',
        'GearHash': 'gear_hash_cdc/cdc-aggregated.csv',
        'MinHash': 'min_hash_cdc/cdc-aggregated.csv'
    }

    all_bins = set()
    algo_data = {}

    # Collect data for each algorithm
    for algo_name, filename in algo_files.items():
        bins = bin_data(filename, bin_size)
        algo_data[algo_name] = bins
        all_bins.update(bins.keys())

    # Sort bins
    sorted_bins = sorted(all_bins)
    num_bins = len(sorted_bins)
    num_algos = len(algorithms)

    # Create matrix
    matrix = np.zeros((num_algos, num_bins))

    for algo_idx, algo_name in enumerate(algorithms):
        for bin_idx, bin_key in enumerate(sorted_bins):
            data = algo_data[algo_name].get(bin_key, {'count': 0, 'duplicates': 0})
            if data['count'] > 0:
                dup_rate = data['duplicates'] / data['count']
            else:
                dup_rate = 0
            matrix[algo_idx][bin_idx] = dup_rate

    # Write matrix format for gnuplot
    with open('cdc_heatmap_matrix.txt', 'w') as f:
        # Write column headers (chunk sizes in KB)
        f.write("# ")
        for bin_key in sorted_bins:
            f.write(f"{bin_key/1024.0:.1f} ")
        f.write("\n")

        # Write data rows (one per algorithm)
        for algo_idx, algo_name in enumerate(algorithms):
            for bin_idx in range(num_bins):
                f.write(f"{matrix[algo_idx][bin_idx]:.6f} ")
            f.write("\n")

    print(f"Matrix written to cdc_heatmap_matrix.txt")
    print(f"Dimensions: {num_algos} algorithms x {num_bins} bins")
    print(f"Chunk size range: {min(sorted_bins)//1024} to {max(sorted_bins)//1024} KB")

if __name__ == '__main__':
    main()
