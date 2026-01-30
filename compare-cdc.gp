#!/usr/bin/env gnuplot

set terminal png size 1920,1200 enhanced font 'Arial,12'
set output 'cdc-comparison.png'

# Tell gnuplot the files are comma-separated
set datafile separator ","

# Create two vertically stacked charts
set multiplot layout 2,1

# Top chart: Chunk size frequency distribution
set title 'CDC Algorithm Comparison: Chunk Size Frequency Distribution'
set xlabel 'Chunk Size (bytes, log scale)'
set ylabel 'Number of Chunks (log scale)'
set logscale xy
set grid
set key top right

plot '/home/tasleson/projects/blk-archive/gear_hash_cdc/cdc-aggregated.csv' skip 1 using 1:2 with linespoints title 'Current (GearHash)' lw 2 pt 7 lc rgb 'blue', \
     '/home/tasleson/projects/blk-archive/fast_hash_cdc/cdc-aggregated.csv' skip 1 using 1:2 with linespoints title 'FastCDC crate' lw 2 pt 7 lc rgb 'red', \
     '/home/tasleson/projects/blk-archive/min_hash_cdc/cdc-aggregated.csv' skip 1 using 1:2 with linespoints title 'minCDC crate' lw 2 pt 7 lc rgb 'green'

# Bottom chart: Duplicate distribution by chunk size
set title 'CDC Algorithm Comparison: Duplicate Distribution by Chunk Size'
set xlabel 'Chunk Size (bytes, log scale)'
set ylabel 'Number of Duplicates for each segment size (log scale)'
set logscale xy
set grid
set key top right

plot '/home/tasleson/projects/blk-archive/gear_hash_cdc/cdc-aggregated.csv' skip 1 using 1:3 with linespoints title 'Current (GearHash)' lw 2 pt 7 lc rgb 'blue', \
     '/home/tasleson/projects/blk-archive/fast_hash_cdc/cdc-aggregated.csv' skip 1 using 1:3 with linespoints title 'FastCDC crate' lw 2 pt 7 lc rgb 'red', \
     '/home/tasleson/projects/blk-archive/min_hash_cdc/cdc-aggregated.csv' skip 1 using 1:3 with linespoints title 'minCDC crate' lw 2 pt 7 lc rgb 'green'

unset multiplot
