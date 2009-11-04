#set terminal postscript enhanced color
set terminal png
set output "bw.diff.2.png"
set size 1.0,1.0
set key left top
#set key box
set title "Fig.2: Target rate / Difference"
set xlabel "Target Bandwidth (Gbps)"
set ylabel "Observed Bandwidth - Target Bandwidth (Gbps)"
#set xrange [1:4097]
set xrange [0:10]
#set yrange [0:10]
set yrange [-1.0:1.0]
#set logscale x
#set ytics nomirror
set style line 1 lt 1 lw 2
set style line 2 lt 3 lw 2
set style line 3 lt 2 lw 2
set style line 4 lt 4 lw 2
plot \
"bw.psp.9.85g.log" usi 1:($2-$1) axis x1y1 ti "PSPacer" ls 1 w l, \
"bw.htb.2.6.31-14.log" usi 1:($2-$1) axis x1y1 ti "HTB" ls 2 w l
