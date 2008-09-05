#!/bin/sh
# TC variable is set to the path of tc(8) binary. NOTE: It is different 
# between distribution; In the case of Redhat and Debian, it is /sbin/tc, 
# and in the case of SuSE, it is /usr/sbin/tc.
if test -f /sbin/tc; then
    TC=/sbin/tc
elif test -f /usr/sbin/tc; then
    TC=/usr/sbin/tc
else
    echo "Can not find tc(8)."
    exit 1
fi

# add qdisc, class and filter
function add()
{
	# root qdisc
	$TC qdisc add dev $1 root handle 1: psp default 2
	# class
	$TC class add dev $1 parent 1: classid 1:1 psp mode 0
	$TC class add dev $1 parent 1: classid 1:2 psp rate $2
	# leaf qdisc
	$TC qdisc add dev $1 parent 1:1 handle 10: pfifo
	$TC qdisc add dev $1 parent 1:2 handle 20: pfifo
	# filter
	#U32="$TC filter add dev $1 protocol ip parent 1: pref 1 u32"
	#$U32 match ip dport 5120 0xfff0 classid 1:2
}

# remove all
function del()
{
	#$TC filter del dev $1 parent 1: pref 1 u32
	$TC qdisc del dev $1 parent 1:2 handle 20:
	$TC qdisc del dev $1 parent 1:1 handle 10:
	$TC class del dev $1 parent 1:  classid 1:2
	$TC class del dev $1 parent 1:  classid 1:1
	$TC qdisc del dev $1 root handle 1:
}

# change target rate
function change()
{
	$TC class change dev $1 parent 1: classid 1:2 psp rate $2
}

# show statistics
function show()
{
	$TC qdisc show dev $1
	$TC class show dev $1
}

case "$1" in
	add)
		add $2 $3
		;;
	del)
		del $2
		;;
	change)
		change $2 $3
		;;
	show)
		show $2
		;;
	*)
		echo "Usage $0 {add <dev> <rate>|del <dev>|change <dev> <rate>|show <dev>}"
		;;
esac

