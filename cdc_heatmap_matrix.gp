#!/usr/bin/gnuplot

set terminal pngcairo size 1600,600 enhanced font 'Arial,12'
set output 'cdc-heatmap.png'

set title "CDC Algorithm Comparison: Duplicate Rate by Chunk Size" font 'Arial,16'

# Set up for matrix/image plotting
set xlabel "Chunk Size (KB)" font 'Arial,14'
set ylabel "CDC Algorithm" font 'Arial,14'

# Color palette
#set palette defined (0 "white", 0.05 "#ffffcc", 0.1 "#ffeda0", 0.15 "#fed976", \
#                      0.2 "#feb24c", 0.25 "#fd8d3c", 0.3 "#fc4e2a", \
#                      0.35 "#e31a1c", 0.4 "#bd0026", 0.7 "#800026")

set palette defined ( \
    0.0 "#440154", \
    0.25 "#3b528b", \
    0.5 "#21918c", \
    0.75 "#5ec962", \
    1.0 "#fde725" \
)


set cbrange [0.28:0.40]
set cblabel "Duplicate Rate" font 'Arial,12'

# Y-axis labels for the three algorithms (bottom to top)
set ytics ("FastHash" 0, "GearHash" 1, "MinHash" 2) font 'Arial,12'
set yrange [-0.5:2.5]
unset format y

# X-axis will be set based on data
set autoscale xfix
set format x "%.0f"

# Margins
set lmargin 12
set rmargin 12
set bmargin 4
set tmargin 3

# Plot matrix as image
plot 'cdc_heatmap_matrix.txt' matrix with image notitle

print "Heatmap saved to cdc-heatmap.png"
