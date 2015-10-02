# Summary #
I have observed a HTB accuracy problem on the Linux kernel 2.6.30 and the Myri-10G 10 GbE NIC.
HTB can control the transmission rate at Gigabit speed, however it can not work well at 10 Gigabit speed.

I guess that HTB has a problem related to the time granularity.
I want to know what is happen, and what should be do for fixing it.

Any comments and suggestions will be welcome.

Patrick McHardy replied at the netdev list:

> This is not an easy problem to fix. Userspace, the kernel and the
> netlink API use 32 bit for timing related values, which is too small
> to use more than microsecond resolution.

The packet scheduler might be possible to use a finer resolution keeping the 32 bit timing variable, but Stephen Hemminger warned that:

> The downside is that by using nanosecond resolution the rates are upper
> bounded at 4.2seconds / packet.

The scheduler timer resolution improves after the kernel 2.6.31 (See Jarek Poplawski's PSCHED\_SHIFT patch).
The result is shown in 'Experimental result 2.'

Eric Dumazet suggested to change the class mtu parameter when using TSO.  The result is shown in 'Experimental result 3.'  Setting large mtu is effective, but some precision is lost for small packets because of the estimation error in qdisc\_l2t(). The rate table has only 256 slots.

# Experiment #

## Experimental setting ##
We use 2 PCs, comprised of two Intel Quad-core Xeon E5430 2.66~GHz,
Intel 5100 chipset, 4 GB memory (DDR2-667), and Myricom Myri-10G
Ethernet interface, which plugged into a PCI-Express x8 lane.  The MTU
size is set to 9000 bytes.
Each PC is running the Ubuntu 9.04 server edition and the Linux kernel
2.6.30.  The version of iproute2 is ss080725.
Some networking sysctl parameters were changed from the
default value, as follows:

| net.core.netdev\_max\_backlog | 250000 |
|:------------------------------|:-------|
| net.core.wmem\_max                 | 16777216 |
| net.core.rmem\_max                  | 16777216 |
| net.ipv4.tcp\_rmem                    | 4096 87380 16777216 |
| net.ipv4.tcp\_wmem                   | 4096 65536 16777216 |

The clock source is set to 'tsc.'
```
$ sudo cat /sys/devices/system/clocksource/clocksource0/current_clocksource
tsc

$ cat /proc/net/psched
000003e8 00000400 000f4240 3b9aca00
```

## Experimental result 1 ##
I measured the average bandwidth over a period of 5 seconds by using
the Iperf benchmark. The target rate, which is controlled by both
PSPacer and HTB, was set from 100 Mbps to 10 Gbps every
100 Mbps.

Note: PSPacer does not rely on any timer mechanisms.

HTB is formed in a stepwise shape, as shown in Fig.1.

![http://pspacer.googlecode.com/svn/wiki/images/bw.png](http://pspacer.googlecode.com/svn/wiki/images/bw.png)

Fig.2 shows the difference between the target rate and the observed average bandwidth.
HTB shows larger difference and wider variance than
PSPacer. The observed bandwidth is up to 0.8 Gbps more than the
target rate.

![http://pspacer.googlecode.com/svn/wiki/images/bw.diff.png](http://pspacer.googlecode.com/svn/wiki/images/bw.diff.png)

## Experimental result 2 ##
I upgraded the ubuntu from version 9.04 to 9.10.  The kernel is 2.6.31-14, and iproute2 is ss090324.
The results are shown in Fig.3 and 4.

Note: The 2nd field of /proc/net/psched is different with the previous setting (ubuntu 9.04).
It means the timer resolution improves from 1 usec to 1/16 usec (see Related links).
```
$ cat /proc/net/psched 
000003e8 00000040 000f4240 3b9aca00
```

The accuracy improves compared with the case of ubuntu 9.04, but it is not perfect.

![http://pspacer.googlecode.com/svn/wiki/images/bw.htb.png](http://pspacer.googlecode.com/svn/wiki/images/bw.htb.png)

![http://pspacer.googlecode.com/svn/wiki/images/bw.diff.htb.png](http://pspacer.googlecode.com/svn/wiki/images/bw.diff.htb.png)

## Experimental result 3 ##

In my experimental setting, TSO (TCP segmentation offload) is enabled.  The myri10ge driver is passing 64KB packets to the NIC.

I changed the class mtu parameter to 64000 instead of 9000.
Fig.5 shows the results.  It's not so bad!

![http://pspacer.googlecode.com/svn/wiki/images/bw.diff.htb.2.png](http://pspacer.googlecode.com/svn/wiki/images/bw.diff.htb.2.png)

## test script ##
```
$ cat iperf.bench.sh
#!/bin/bash

DEV=eth1
MTU=9000
DEST=192.168.0.2
rate=100

# set up HTB.
sudo /sbin/tc qdisc add dev $DEV root handle 1: htb default 1
sudo /sbin/tc class add dev $DEV parent 1: classid 1:1 htb rate ${rate}mbit mtu $MTU
sudo /sbin/tc qdisc add dev eth1 parent 1:1 handle 10: pfifo

# run iperf.
while test $rate -lt 10000; do
	f=`echo "scale=3;$rate/1000" | bc`
	echo -n "$f "
	sudo /sbin/tc class change dev $DEV parent 1: classid 1:1 htb mtu $MTU rate ${rate}mbit
	iperf -t 5 -l 128k -c $DEST | grep "bits/sec" | awk '{print $8}'
	#iperf -t 60 -l 128k -c $DEST | grep "bits/sec" | awk '{print $7}'
	sleep 1
	rate=$((rate+100))
done

# clean up HTB.
sudo /sbin/tc qdisc del dev $DEV root
```

# Related link #
  * [HTB accuracy on 10GbE](http://www.spinics.net/lists/netdev/msg111137.html) (netdev list)
  * [pkt\_sched: Change PSCHED\_SHIFT from 10 to 6](http://www.spinics.net/lists/netdev/msg99304.html) (netdev list)
  * [tc\_core: Use double in tc\_core\_time2tick()](http://marc.info/?l=linux-netdev&m=124453482324409&w=2) (netdev list)