#set terminal postscript enhanced color
set terminal png
set output "bw.png"
set size 1.0,1.0
set key left top
#set key box
set title "Fig.1: Target rate / Observed rate"
set xlabel "Target Bandwidth (Gbps)"
set ylabel "Observed Bandwidth Gbps)"
set xrange [0:10]
set yrange [0:10]
#set logscale x
#set ytics nomirror
set style line 1 lt 1 lw 2
set style line 2 lt 3 lw 2
set style line 3 lt 2 lw 2
set style line 4 lt 4 lw 2
plot \
"bw.psp.9.85g.log" usi 1:2 axis x1y1 ti "PSPacer" ls 1 w l, \
"bw.htb.log" usi 1:2 axis x1y1 ti "HTB" ls 2 w l
