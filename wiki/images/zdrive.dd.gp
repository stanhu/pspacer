set terminal postscript enhanced monochrome
set terminal png
set output "p84.dd.btrfs.2.png"
set size 0.7,0.7
set key right bottom
#set key box
set title "Fig.3: dd on btrfs (/dev/sdb1)"
set xlabel "block size (byte)"
set ylabel "Bandwidth (MB/s)"
#set xrange [1:4096]
#set xrange [1:15000]
set yrange [1:700]
#set ytics 200
set logscale x
#set ytics nomirror
plot \
"p84.dd.btrfs.2.log" usi 1:2 axis x1y1 ti "seq. write" w l lw 2, \
"p84.dd.btrfs.2.log" usi 1:3 axis x1y1 ti "seq. read" w l lw 2
