/*
 * net/sched/sch_psp.h	PSPacer: Precise Software Pacer
 *
 *		Copyright (C) 2004-2008 National Institute of Advanced
 *		Industrial Science and Technology (AIST), Japan.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	TAKANO Ryousei, <takano-ryousei@aist.go.jp>
 */

#include <linux/version.h>

/* TODO: move to linux/pkt_sched.h */
/* PSP section */
#define TC_PSP_MAXDEPTH	(8)

struct tc_psp_copt
{
	__u32	level;
	__u32	mode;
#define TC_PSP_MODE_NORMAL	(0)
#define TC_PSP_MODE_STATIC	(1)
#define TC_PSP_MODE_DYNAMIC	(2)
#define TC_PSP_MAJ_MODE_MASK	(0x000000FFU)
#define TC_PSP_MIN_MODE_MASK	(0x0000FF00U)
	__u32	rate;		/* bytes/sec */
};

struct tc_psp_qopt
{
	__u32	defcls;
	__u32	rate;		/* bytes/sec */
	__u32	direct_pkts;
	__u32	ifg;
};

struct tc_psp_xstats
{
	__u32	bytes;		/* gap packet statistics */
	__u32	packets;
};

enum
{
	TCA_PSP_UNSPEC,
	TCA_PSP_COPT,
	TCA_PSP_QOPT,
	__TCA_PSP_MAX,
};

#define TCA_PSP_MAX (__TCA_PSP_MAX - 1)

/* for compat */
#ifndef NLMSG_TAIL
#define NLMSG_TAIL(nmsg) \
	((struct rtattr *)(((void *)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))
#endif
#ifndef parse_rtattr_nested
#define parse_rtattr_nested(tb, max, rta) \
	(parse_rtattr((tb), (max), RTA_DATA(rta), RTA_PAYLOAD(rta)))
#endif

#if defined(__KERNEL__)

/* for compat */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)
static inline void *qdisc_priv(struct Qdisc *q)
{
	return (void *)q->data;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
#define QSTATS(x) (x)->stats
#define BSTATS(x) (x)->stats
#else
/* TODO */
#define QSTATS(x) (x)->qstats
#define BSTATS(x) (x)->bstats
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
static inline void 
skb_get_timestamp(const struct sk_buff *skb, struct timeval *stamp)
{
	stamp->tv_sec  = skb->stamp.tv_sec;
	stamp->tv_usec = skb->stamp.tv_usec;
}

static inline void 
skb_set_timestamp(struct sk_buff *skb, const struct timeval *stamp)
{
	skb->stamp.tv_sec  = stamp->tv_sec;
	skb->stamp.tv_usec = stamp->tv_usec;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
#define skb_tail_pointer(skb) ((skb)->tail)
#define skb_reset_network_header(skb) ((skb)->nh.raw = (skb)->data)
#define ip_hdr(skb) ((skb)->nh.iph)
#define tcp_hdr(skb) ((skb)->h.th)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#define nlattr rtattr
#define nla_parse(tb, max, head, len, policy) \
	rtattr_parse(tb, max, head, len)
#define nla_parse_nested(tb, max, nla, policy) \
	rtattr_parse_nested(tb, max, nla)
#define nla_len(x) RTA_PAYLOAD(x)
#define nla_data(x) RTA_DATA(x)
#define NLA_PUT(skb, type, len, data) RTA_PUT(skb, type, len, data)
#define nla_put_failure rtattr_failure
#define nla_nest_end(skb,nla) \
	nla->rta_len = skb_tail_pointer(skb) - b
#define nla_nest_start(skb,opt) \
	(struct nlattr *)b; NLA_PUT((skb), (opt), 0, NULL)
#define nla_nest_cancel(skb, nla) \
	skb_trim((skb), b - (skb)->data)
#define _OPT(x) ((x) - 1)
#else
#define _OPT(x) (x)
#endif

#ifndef rtattr_parse_nested
#define rtattr_parse_nested(tb, max, rta) \
	rtattr_parse((tb), (max), RTA_DATA((rta)), RTA_PAYLOAD((rta)))
#endif

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(x, y) (((x) + ((y) - 1)) / (y))
#endif

#ifndef __read_mostly /* include/linux/cache.h */
#define __read_mostly
#endif

#ifndef BITS_PER_BYTE /* include/linux/bitops.h */
#define BITS_PER_BYTE 8
#endif

#ifndef ETH_P_PAUSE /* include/linux/if_ether.h */
#define ETH_P_PAUSE 0x8808
#endif

#ifndef uninitialized_var
#define uninitialized_var(x) (x)
#endif

#endif /* __KERNEL__ */
