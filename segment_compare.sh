#!/usr/bin/bash

BASE="$HOME/projects/blk-archive"

BIN="$BASE/target/release/blk-stash"

INPUT="$HOME/Downloads"

GEAR="$BASE/gear_hash_cdc"
FAST="$BASE/fast_hash_cdc"
MIN="$BASE/min_hash_cdc"


if [ ! -d "$GEAR" ]; then
    echo "Running gear hash tests..."
    rm -rf "$GEAR" || exit 1
    $BIN create -a "$GEAR" || exit 1
    $BIN pack -a "$GEAR"  "$INPUT/"*.iso || exit 1
    mv "$BASE/"*.csv "$GEAR" || exit 1
else
    echo "Skipping gear hash tests (directory exists)"
fi

rm -rf "$FAST" || exit 1
$BIN create -a "$FAST" --cdc-algorithm fastcdc || exit 1
$BIN pack -a "$FAST"  "$INPUT/"*.iso || exit 1
mv "$BASE/"*.csv "$FAST" || exit 1

rm -rf "$MIN" || exit 1
$BIN create -a "$MIN" --cdc-algorithm mincdc || exit 1
$BIN pack -a "$MIN"  "$INPUT/"*.iso || exit 1
mv "$BASE/"*.csv "$MIN" || exit 1


"$BASE/aggregate_cdc.py" "$GEAR"
"$BASE/aggregate_cdc.py" "$FAST"
"$BASE/aggregate_cdc.py" "$MIN"


gnuplot -p "$BASE/compare-cdc.gp" || exit 1
gnuplot -p "$BASE/compare-cdc-ridge.gp" || exit 1


# Create the heatmap visualization
"$BASE/prepare_heatmap_matrix.py"
gnuplot -p "$BASE/cdc_heatmap_matrix.gp"

gnome-open "$BASE/cdc-comparison.png" &
gnome-open "$BASE/cdc-comparison-ridge.png" &
gnome-open "$BASE/cdc-heatmap.png" &
