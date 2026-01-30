#!/usr/bin/env gnuplot

# Ridge plot visualization for CDC chunk size frequencies
# Run as: gnuplot -p compare-cdc-ridge.gp

set terminal png size 1920,1200 enhanced font 'Arial,12'
set output 'cdc-comparison-ridge.png'

set datafile separator ","

set title 'CDC Algorithm Comparison: Chunk Size Distribution (Ridge Plot)'
set xlabel 'Chunk Size (bytes)'
set ylabel 'Frequency (Count)'

set grid ytics
set key top right
set logscale xy

# Use filled curves to show distributions more clearly
set style fill transparent solid 0.5

# Plot both algorithms with offset for ridge effect
plot '/home/tasleson/projects/blk-archive/gear_hash_cdc/cdc-aggregated.csv' skip 1 \
     using 1:2 with filledcurves x1 title 'Current (Gear Hash)' lc rgb '#0000FF', \
     '' skip 1 using 1:2 with lines lw 2 lc rgb '#0000AA' notitle, \
     '/home/tasleson/projects/blk-archive/min_hash_cdc/cdc-aggregated.csv' skip 1 \
     using 1:2 with filledcurves x1 title 'minCDC crate' lc rgb '#54e009', \
     '' skip 1 using 1:2 with lines lw 2 lc rgb '#01840a' notitle, \
     '/home/tasleson/projects/blk-archive/fast_hash_cdc/cdc-aggregated.csv' skip 1 \
     using 1:2 with filledcurves x1 title 'FastCDC Crate' lc rgb '#FF0000', \
     '' skip 1 using 1:2 with lines lw 2 lc rgb '#AA0000' notitle
