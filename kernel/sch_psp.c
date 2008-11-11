/*
 * net/sched/sch_psp.c	PSPacer: Precise Software Pacer
 *
 *		Copyright (C) 2004-2008 National Institute of Advanced
 *		Industrial Science and Technology (AIST), Japan.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Ryousei Takano, <takano-ryousei@aist.go.jp>
 *
 * Changes:
 * Denis Kaganovich, <mahatma@bspu.unibel.by> - fixes, retransmission/tcp/trees
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/ethtool.h>
#include <linux/if_arp.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/pkt_sched.h>
#include <asm/div64.h>

#include <linux/random.h>
#include <net/ip.h>
#include <linux/jhash.h>
#ifdef CONFIG_IPV6
#include <linux/ipv6.h>
#endif

#include "sch_psp.h"

/*
 * PSPacer achieves precise rate regulation results, and no microscopic
 * burst transmission which exceeds the limit is generated.
 *
 * The basic idea is that transmission timing can be precisely controlled,
 * if packets are sent back-to-back at the wire rate.  PSPacer controls
 * the packet transmision intervals by inserting additional packets,
 * called gap packets, between adjacent packets.  The transmission interval
 * can be controlled accurately by adjusting the number and size of the gap
 * packets. PSPacer uses the 802.3x PAUSE frame as the gap packet.
 *
 * For the purpose of adjusting the gap size, this Qdisc maintains a byte
 * clock which is recorded by a total transmitted byte per connection.
 * Each sub-class has a class local clock which is used to make decision
 * whether to send a packet or not.  If there is not any packets to send,
 * gap packets are inserted.
 *
 * References:
 * [1] R.Takano, T.Kudoh, Y.Kodama, M.Matsuda, H.Tezuka, and Y.Ishikawa,
 *     "Design and Evaluation of Precise Software Pacing Mechanisms for
 *     Fast Long-Distance Networks", PFLDnet2005.
 * [2] http://www.gridmpi.org/gridtcp.jsp
 */

#define FCS    (4)		/* Frame Check Sequence(4) */
#define MIN_TARGET_RATE (1000)	/* 1 KBytes/sec */

/* remove next 8 lines before kernel inclusion ;) */
//#define CONFIG_NET_SCH_PSP_PKT_GAP
//#define CONFIG_NET_SCH_PSP_NO_SYN_FAIRNESS
//#define CONFIG_NET_SCH_PSP_NO_TTL
//#define CONFIG_NET_SCH_PSP_RRR
//#define CONFIG_NET_SCH_PSP_EST
//#define CONFIG_NET_SCH_PSP_FORCE_GAP
//#define CONFIG_NET_SCH_PSP_FAST_SORT
//#define CONFIG_NET_SCH_PSP_RATESAFE

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
#define PSP_HSIZE (16)
#else
#define PSP_HSIZE q->clhash.hashsize
#endif

#define ENABLE_PSP_DIRECT

#ifdef CONFIG_NET_SCH_PSP_NO_TTL
#undef TTL
#else
#define TTL (15*30*30*1000)	/* tcp hash entry ttl or undef, msec */
#endif

/* SYN_WEIGHT: syn fairness */
#ifdef CONFIG_NET_SCH_PSP_NO_SYN_FAIRNESS
#undef SYN_WEIGHT
#else
#define SYN_WEIGHT (1)		/* 1 syn == len<<SYN_WEIGHT retransmissions (or undef) */
#endif

#define EWMA_DEFAULT (1000000)	/* nsec */

#undef gap_u64			/* I prefer undef for 32bit and normal gaps */

#define STRICT_TCP		/* safer but slower for multihomed link + variable window */

#ifdef gap_u64
typedef u64 clock_delta;
#else
typedef unsigned long clock_delta;
#endif

static int debug __read_mostly;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "add the size to packet header for debugging (0|1)");

/*
 * phy_rate is the maximum qdisc rate. If the kernel supports ethtool ioctl,
 * it is corrected. Otherwise it statically sets to the Gigabit rate.
 */
unsigned long phy_rate = 125000000;

u32 psp_rand = 0;

#define NODEVAL 2
#define TREE_MAX 128
struct __node {
	struct __node *b[2];
	u64 v[NODEVAL];
#ifdef CONFIG_NET_SCH_PSP_RRR
	int rrr;
#endif
	u64 clock;
};
typedef struct __node **node;

struct hashitem {
#ifdef TTL
	struct list_head tcplist;
#endif
#define HASH_ZERO (4*NODEVAL+12)
	u32 v[NODEVAL];
	u32 ack_seq;
	u64 clock;
#ifdef CONFIG_IPV6
	union {
		struct {
			struct in6_addr saddr6, daddr6;
		};
#endif
		struct {
			__be32 saddr, daddr;
		};
#ifdef CONFIG_IPV6
	};
#endif
	__u32 ports;
	u32 seq, end;
	union {
		__u16 misc[3];
		struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
			__u16 res1:4,
			    doff:4,
			    fin:1,
			    syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
			__u16 doff:4,
			    res1:4,
			    cwr:1,
			    ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif
			__be16 window;
			__sum16 check;
		};
	};
#ifdef CONFIG_IPV6
	u8 asize;
#endif
#ifdef CONFIG_NET_SCH_PSP_RRR
	int rrr;
#endif
};

#define HINT_BITS 5

struct psp_skb_cb {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	struct qdisc_skb_cb q_cb;
#endif
	u64 clock;
	u32 backsize;
	struct list_head hint[];
};

#define NHINTS ((48-sizeof(struct psp_skb_cb))/sizeof(struct list_head))
#define psp_tstamp(skb) (((struct psp_skb_cb *)(&(skb)->cb))->clock)
#define SKB_BACKSIZE(skb) (((struct psp_skb_cb *)(&(skb)->cb))->backsize)

#define HBITS 16
#define HSIZE (1ULL<<HBITS)

struct est_data {
	unsigned long av;
	u64 data;
	u64 time;
};

struct psp_class {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	u32 classid;		/* class id */
#define class_id(cl) (cl)->classid
#else
	struct Qdisc_class_common common;
#define class_id(cl) (cl)->common.classid
#endif
	int refcnt;		/* reference count */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
	struct tc_stats stats;	/* generic stats */
#else
	struct gnet_stats_basic bstats;	/* basic stats */
	struct gnet_stats_queue qstats;	/* queue stats */
#endif
	int level;		/* class level in hierarchy */
	struct psp_class *parent;	/* parent class */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	struct list_head hlist;	/* hash list */
	struct list_head sibling;	/* sibling classes */
	struct list_head children;	/* child classes */
#else
	unsigned int children;
#endif

	struct Qdisc *qdisc;	/* leaf qdisc */

	struct tcf_proto *filter_list;	/* filter list */
	int filter_cnt;		/* filter count */
	u32 hw_gap;		/* inter frame gap + preamble + FCS */
	u32 hz;			/* destination device timer frequence */
	unsigned int mtu;	/* class MTU size
				   (included ethernet header) */

	struct list_head dlist;	/* drop list */
	struct list_head plist;	/* normal/pacing class qdisc list */
	struct list_head elist;	/* estimators */

	u32 state;		/* reserved(8)|activity(8)|mode(16) */
#define MODE_MASK       (0x0000ffff)
#define MAJOR_MODE_MASK (0x000000ff)
#define MINOR_MODE_MASK (0x0000ff00)
#define FLAG_ACTIVE     (0x00010000)	/*  the class has packets or not */
#define FLAG_DMARK      (0x00020000)	/*  reset mark */
	int direction;		/* fast access to submode +0x800 */

	int autorate;		/* estimated rate 0/1 */
	unsigned long rate;	/* current target rate (bytes/sec) */
	unsigned long max_rate;	/* maximum target rate */
	unsigned long allocated_rate;	/* allocated rate to children */
	u64 clock;		/* class local byte clock */
	unsigned long tail, tail1;	/* rate division tail */

	void *tcphash;		/* tcp "tracking" hash */
#ifdef TTL
	struct list_head tcplist;
#endif
	struct __node *tree_heap;
	struct __node *iptree;	/* ip address tree */
#ifdef CONFIG_IPV6
	struct __node *ip6tree;	/* ip6 address tree */
#endif
	struct sk_buff *skb;	/* prefetched packet */

	struct est_data bps;	/* rate estimator data */
	struct est_data pps;
	struct Qdisc *sch;	/* master qdisc, for estimator */
	struct psp_class *back;	/* for interactive estimation */
	struct psp_class *forward;
	int back_dev;
	u32 back_id;
	struct est_data back_bps;

	u64 phaze_bytes;
	u64 time;		/* to sync */
	unsigned long ewma;

	struct list_head rlist;	/* retransmission round-robin */
	int weight, weight_sum;

	clock_delta t;		/* last pkt hw transfer time */
	struct psp_class *prev;	/* walk runtime */
};

struct psp_sched_data {
	int defcls;		/* default class id */
	struct psp_class *defclass;	/* default class */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	struct list_head root;	/* root class list */
	struct list_head hash[PSP_HSIZE];	/* class hash */
#else
	struct Qdisc_class_hash clhash;
#endif
	struct list_head drop_list;	/* active leaf class list (for
					   dropping) */
	struct list_head pacing_list;	/* gap leaf class list (in
					   order of the gap size) */
	struct list_head normal_list;	/* no gap leaf class list */
	struct psp_class *mode3;	/* just hardware estimator */

	struct sk_buff_head requeue;	/* requeued packet */
	long direct_pkts;

	struct tcf_proto *filter_list;	/* filter list */
	int filter_cnt;		/* filter count */

	u32 ifg;		/* inter frame gap */
	unsigned long hw_gap;	/* estimated cpu over-gap */
#define HW_GAP(q) (8 + ((q)->ifg))	/* preamble + IFG */
	int autorate;		/* estimated rate 0/1 */
	unsigned long max_rate;	/* physical rate */
	unsigned long allocated_rate;	/* sum of allocated rate */
	unsigned long default_rate;	/* default_rate */
	unsigned int mtu;	/* interface MTU size
				   (included ethernet header) */
#ifdef TTL
	u32 ttl;
#endif
#define MTU(sch) (qdisc_dev(sch)->mtu+qdisc_dev(sch)->hard_header_len)
	u64 clock;		/* wall clock */
	u64 clock0;

	int phaze_idle;
	u64 time;
	clock_delta phaze_time;
	unsigned long ewma;
	struct est_data bps;	/* rate estimator data */
	struct est_data pps;

	struct sk_buff *gap;	/* template of gap packets */
	struct tc_psp_xstats xstats;	/* psp specific stats */
#ifdef CONFIG_NET_SCH_PSP_FORCE_GAP
	struct psp_class *last, *wait;
#endif
};

/* A gap packet header (struct ethhdr + h_opcode). */
struct gaphdr {
	unsigned char h_dest[ETH_ALEN];	/* destination eth addr */
	unsigned char h_source[ETH_ALEN];	/* source eth addr */
	__be16 h_proto;		/* MAC control */
	__be16 h_opcode;	/* MAC control opcode */
	__be16 h_param;		/* pause time */
	union {
		__be16 h_len;	/* (NON STANDARD) It is used
				   for debugging only. */
		unsigned char reserved[42];	/* must be zero */
	};
} __attribute__ ((packed));

/* random-period timer, msec * HZ /1000 */
static int est_min = 50 * HZ / 1000;
static int est_max = 200 * HZ / 1000;
static int est_ewma = 1000 * HZ / 1000;
static int etime = 1;
static struct timer_list etimer;
static struct list_head elist = {
	.next = &elist,
	.prev = &elist
};

/* The destination address must be specified as 01:80:c2:00:00:01. */
static const unsigned char gap_dest[ETH_ALEN] = { 0x01, 0x80, 0xc2, 0x00,
	0x00, 0x01
};

static inline u64 mul_div(const unsigned long x, const unsigned long y,
			  const unsigned long z)
{
#if 0
	u64 tmp = ~(u64) 0;

	if (y == 0)
		return 0;
	do_div(tmp, y);
	if (tmp < (tmp = x)) {
		do_div(tmp, z);
		tmp *= y;
	} else {
		tmp *= y;
		do_div(tmp, z);
	}
#else
	u64 tmp = x;

	tmp *= y;
	do_div(tmp, z);
#endif
	return tmp;
}

static inline u64 mul_div_up(const unsigned long x, const unsigned long y,
			     const unsigned long z)
{
#if 0
	u64 tmp = ~(u64) 0;

	if (y == 0)
		return 0;
	do_div(tmp, y);
	if (tmp < (tmp = x)) {
		tmp += z - 1;
		do_div(tmp, z);
		tmp *= y;
	} else {
		tmp = tmp * y + z - 1;
		do_div(tmp, z);
	}
#else
	u64 tmp = x;

	tmp = tmp * y + z - 1;
	tmp += z - 1;
	do_div(tmp, z);
#endif
	return tmp;
}

static inline struct Qdisc *q_create_dflt(struct Qdisc *sch, u32 classid)
{
	return qdisc_create_dflt(qdisc_dev(sch),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
				 sch->dev_queue,
#endif
				 &pfifo_qdisc_ops
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
				 , classid
#endif
	    );
}

static struct sk_buff *alloc_gap_packet(struct Qdisc *sch, int size)
{
	struct sk_buff *skb;
	struct net_device *dev = qdisc_dev(sch);
	struct gaphdr *gap;
	int pause_time = 0;

	skb = alloc_skb(size, GFP_KERNEL);
	if (!skb)
		return NULL;

	skb_reset_network_header(skb);
	skb_put(skb, size);

	/*
	 * fill the payload of a gap packet with zero, where size indicates
	 * the interface MTU size.
	 */
	memset(skb->data, 0, size);

	gap = (struct gaphdr *)skb->data;
	memcpy(gap->h_dest, gap_dest, ETH_ALEN);
	memcpy(gap->h_source, dev->dev_addr, ETH_ALEN);
	gap->h_proto = __constant_htons(ETH_P_PAUSE);
	gap->h_opcode = __constant_htons(0x0001);
	gap->h_param = htons(pause_time);

	skb->dev = qdisc_dev(sch);
	skb->protocol = __constant_htons(ETH_P_802_3);

	return skb;
}

#ifdef ENABLE_PSP_DIRECT
#define PSP_DIRECT (struct psp_class *)(-1)
#else
#define PSP_DIRECT NULL
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
static inline unsigned int psp_hash(u32 h)
{
	h ^= h >> 8;
	h ^= h >> 4;
	return h & (PSP_HSIZE - 1);
}
#endif

static inline struct psp_class *psp_find(u32 handle, struct Qdisc *sch)
{
	struct psp_sched_data *q = qdisc_priv(sch);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	struct psp_class *cl;

	list_for_each_entry(cl, &q->hash[psp_hash(handle)], hlist) {
		if (cl->classid == handle)
			return cl;
	}
#else
	struct Qdisc_class_common *clc;

	if ((clc = qdisc_class_find(&q->clhash, handle)))
		return container_of(clc, struct psp_class, common);
#endif
	return NULL;
}

static inline void bind_default(struct Qdisc *sch)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl;
	if (
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
		   !q->root.next ||
#else
		   !q->clhash.hash ||
#endif
		   !(cl =
		     psp_find(TC_H_MAKE(TC_H_MAJ(sch->handle), q->defcls), sch))
		   || cl->level > 0)
		cl = PSP_DIRECT;
	q->defclass = cl;
}

#ifdef CONFIG_NET_SCH_PSP_FAST_SORT

#if HINT_BITS == 4
/* no sense with "-funroll-loops", but I help you too (; */
#define HINT(s,i) ((s)->clock >> (((i) + 1) << 2))
#else
#define HINT(s,i) ((s)->clock >> (HINT_BITS * ((i) + 1)))
#endif

static inline void hints_init(struct sk_buff *skb)
{
	struct psp_skb_cb *s = (struct psp_skb_cb *)&skb->cb;
#if 0
	int i;

	for (i = NHINTS - 1; i >= 0; i--)
		INIT_LIST_HEAD(&s->hint[i]);
#else
	s->hint[0].prev = NULL;
#endif
}

static inline void hints_delete(struct sk_buff *skb)
{
	struct psp_skb_cb *s = (struct psp_skb_cb *)&skb->cb;
	int i;

	if (s->hint[0].prev) {
		for (i = NHINTS - 1; i >= 0; i--)
			list_del(&s->hint[i]);
		s->hint[0].prev = NULL;
	}
}

static inline void __skb_queue_tstamp(struct sk_buff_head *list,
				      struct sk_buff *newsk)
{
	struct sk_buff *prev = list->prev;
	struct psp_skb_cb *s = (struct psp_skb_cb *)&newsk->cb;
	struct psp_skb_cb *slast, *s1;
	int i;
	u64 h, h1;

	if (prev == (struct sk_buff *)list) {
		for (i = NHINTS - 1; i >= 0; i--)
			INIT_LIST_HEAD(&s->hint[i]);
		goto queue;
	}
	s1 = slast = (struct psp_skb_cb *)&prev->cb;
	for (i = NHINTS - 1; i >= 0; i--) {
		/* s - new packet cb, s1 - found hint/packet cb */
		h = HINT(s, i);
	      next_hint:
		h1 = HINT(s1, i);
		if (h1 > h) {
			/* look next */
			s1 = container_of(s1->hint[i].next, struct psp_skb_cb,
					  hint[i]);
			if (s1 != slast)
				goto next_hint;
			/* end/start of list, we are the new hint */
			list_add_tail(&s->hint[i], &s1->hint[i]);
			s1 = container_of(s->hint[i].prev, struct psp_skb_cb,
					  hint[i]);
		} else if (h1 < h) {
			list_add_tail(&s->hint[i], &s1->hint[i]);
			if (s1 != slast)
				s1 = container_of(s->hint[i].prev,
						  struct psp_skb_cb, hint[i]);
		} else if (s->clock >= s1->clock && !list_empty(&s1->hint[i])) {
			list_replace_init(&s1->hint[i], &s->hint[i]);
			if (s1 != slast)
				s1 = container_of(s->hint[i].prev,
						  struct psp_skb_cb, hint[i]);
		} else
			INIT_LIST_HEAD(&s->hint[i]);
	}

	for (prev = container_of((void *)s1, struct sk_buff, cb);
	     prev != (struct sk_buff *)list
	     && psp_tstamp(prev) > s->clock; prev = prev->prev)
		/* nothing */ ;
      queue:
	__skb_queue_after(list, prev, newsk);
}

/* something wrong? */
static inline struct sk_buff_head *fifo_requeue_tail(struct sk_buff *skb)
{				/* must be tail */
	struct sk_buff_head *list = (struct sk_buff_head *)skb->next;
	struct sk_buff *prev = skb->prev;
	struct psp_skb_cb *s = (struct psp_skb_cb *)&skb->cb;
	struct psp_skb_cb *slast, *s1;
	int i;
	u64 h, h1;

	if (list == (struct sk_buff_head *)skb || !list)
		return NULL;
	if (list == (struct sk_buff_head *)prev) {
		for (i = NHINTS - 1; i >= 0; i--)
			INIT_LIST_HEAD(&s->hint[i]);
		return list;
	}
	slast = (struct psp_skb_cb *)&prev->cb;
	for (i = NHINTS - 1; i >= 0; i--) {
		/* s - new packet cb, s1 - tail (first) hint cb */
		h = HINT(s, i);
		s1 = container_of(slast->hint[i].prev, struct psp_skb_cb,
				  hint[i]);
		h = HINT(s1, i);
		if (h1 > h)
			list_add_tail(&s->hint[i], &slast->hint[i]);
		else if (s1 == slast)
			INIT_LIST_HEAD(&s->hint[i]);
		else
			list_replace_init(&s1->hint[i], &s->hint[i]);
	}
	__skb_queue_head(list, __skb_dequeue_tail(list));
	return list;
}

static inline void hints_unlink_tail(struct sk_buff_head *list)
{
	/* old - old tail (to remove), new - new tail */
	struct sk_buff *old = list->prev;
	struct sk_buff *new = old->prev;
	int i;

	if ((struct sk_buff_head *)new != list) {
		struct psp_skb_cb *s = (struct psp_skb_cb *)&old->cb;
		struct psp_skb_cb *s1 = (struct psp_skb_cb *)&new->cb;

		for (i = NHINTS - 1; i >= 0; i--) {
			if (s->hint[i].next == &s1->hint[i])
				list_del_init(&s->hint[i]);
			else if (list_empty(&s->hint[i]))
				INIT_LIST_HEAD(&s1->hint[i]);
			else
				list_replace_init(&s->hint[i], &s1->hint[i]);
		}
	}
}

#else
#define hints_delete(skb) ;
#define hints_init(skb) ;
#define hints_unlink_tail(list) ;
static inline void __skb_queue_tstamp(struct sk_buff_head *list,
				      struct sk_buff *newsk)
{
	struct sk_buff *prev;

	for (prev = ((struct sk_buff *)list)->prev;
	     prev != (struct sk_buff *)list
	     && psp_tstamp(prev) > psp_tstamp(newsk); prev = prev->prev)
		/* nothing */ ;
	__skb_queue_after(list, prev, newsk);
}

static inline struct sk_buff_head *fifo_requeue_tail(struct sk_buff *skb)
{				/* must be tail */
	struct sk_buff_head *list = (struct sk_buff_head *)skb->next;

	if (list && list != (struct sk_buff_head *)skb) {
		__skb_queue_head(list, __skb_dequeue_tail(list));
		return list;
	}
	return NULL;
}
#endif

#define classtrace 10

static struct psp_class *psp_classify(struct sk_buff *skb, struct Qdisc *sch,
				      int *qerr)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl, *pcl = NULL, *cls[classtrace + 2];
	int ncl = 0;
	struct tcf_result res;
	struct tcf_proto *tcf;
	int result;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	*qerr = NET_XMIT_BYPASS;
#else
	*qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
#endif

	if (TC_H_MAJ(skb->priority ^ sch->handle) == 0) {
		if ((cl = psp_find(skb->priority, sch)) != NULL
		    && cl->level == 0) {
			return cl;
		} else if (skb->priority == sch->handle)
			return PSP_DIRECT;
	}

	tcf = q->filter_list;
	while (tcf && (result = tc_classify(skb, tcf, &res)) >= 0) {
#ifdef CONFIG_NET_CLS_ACT
		switch (result) {
		case TC_ACT_QUEUED:
		case TC_ACT_STOLEN:
			*qerr = NET_XMIT_SUCCESS;
		case TC_ACT_SHOT:
			return NULL;
		}
#endif
		cl = (struct psp_class *)res.class;
		if (cl == NULL) {
			cl = psp_find(res.classid, sch);
			if (cl == NULL)
				break;	/* filter selected invalid classid */
			if (res.classid == sch->handle)
				return PSP_DIRECT;
		}

		if (cl->level == 0)
			return cl;	/* hit leaf class */

		/* loop? ;) */
		if (pcl) {
			struct psp_class *cl1;
			for (cl1 = cl->parent; cl1 != NULL && pcl != cl1;
			     cl1 = cl1->parent) {
			}
			if (!cl1) {	/* not child? check other */
				int i = 0;
				while (i < ncl && cls[i] != cl) {
					i++;
				}
				if (i != ncl || ncl >= classtrace)
					break;
				cls[ncl++] = cl;
			}
		}
		pcl = cl;

		/* apply inner filter chain */
		tcf = cl->filter_list;
	}

	/* classification failed, try default class */
	return q->defclass;
}

static inline void psp_activate(struct psp_sched_data *q, struct psp_class *cl)
{
	cl->state |= FLAG_ACTIVE;
	list_add_tail(&cl->dlist, &q->drop_list);
}

static inline void psp_deactivate(struct psp_sched_data *q,
				  struct psp_class *cl)
{
	cl->state &= ~FLAG_ACTIVE;
	list_del_init(&cl->dlist);
}

static inline int deq(struct Qdisc *sch, struct psp_sched_data *q,
		      struct psp_class *cl, int qlen)
{
	int res = 0;

	if (cl) {
		if (!(res = (QSTATS(cl).qlen -= qlen)))
			psp_deactivate(q, cl);
		sch->q.qlen -= qlen;
		while ((cl = cl->parent))
			if (!(QSTATS(cl).qlen -= qlen))
				psp_deactivate(q, cl);
	}
	return res;
}

struct psp_class *psp_get_back(struct psp_class *cl)
{
	struct net_device *dev = dev_get_by_index(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
							 dev_net(qdisc_dev
								 (cl->sch)),
#endif
							 cl->back_dev);
	struct Qdisc *sch2;
	struct psp_class *back;

	if (!dev)
		return cl->back = NULL;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,26)
	sch2 = dev->qdisc;
#else
	sch2 = netdev_get_tx_queue(dev, 0)->qdisc;
#endif
	if (sch2 || sch2->ops != cl->sch->ops)
		return cl->back = NULL;
	back = psp_find(cl->back_id, sch2);
	back->forward = cl;
	cl->back = back;
	return back;
}

/*
 * estimate class-related rates and rate-related values
 */
#define NEXT(type,saved,val) ({type x=(val)-(saved); (saved)+=x; x;})
#define RATE(r,time,val) ({ \
    u64 d=(r).av*(u64)(est_ewma-(time))+(u64)(val)*HZ; \
    do_div(d,est_ewma); \
    (r).av=d; })

static inline void psp_class_est(struct psp_class *cl, unsigned long time)
{
	struct Qdisc *sch = cl->sch;
	struct psp_sched_data *q = qdisc_priv(sch);
	unsigned long rmin, rmax, rb, rp, rbb, rbmax;
	int mtu;

	switch (cl->state & MAJOR_MODE_MASK) {
	case TC_PSP_MODE_ESTIMATED_GAP_DATA:
		rb = RATE(cl->bps, time, BSTATS(sch).bytes + q->xstats.bytes);
		rp = RATE(cl->pps, time, BSTATS(cl).packets);
		mtu = q->mtu;
		rmax = q->max_rate;
		break;
	case TC_PSP_MODE_ESTIMATED:
		/* q->clock are corrected by this mode */
		rb = RATE(cl->bps, time,
			  BSTATS(sch).bytes + q->xstats.bytes
			  + (BSTATS(sch).packets +
			     q->xstats.packets) * (HW_GAP(q) + FCS));
		rp = RATE(cl->pps, time,
			  BSTATS(sch).packets + q->xstats.packets);
		mtu = q->mtu;
		rmax = q->max_rate;
		break;
	case TC_PSP_MODE_ESTIMATED_DATA:
	case TC_PSP_MODE_ESTIMATED_GAP:
		rb = RATE(cl->bps, time, q->clock);
		rp = RATE(cl->pps, time,
			  BSTATS(sch).packets + q->xstats.packets);
		mtu = q->mtu;
		rmax = q->max_rate;
		break;
	case TC_PSP_MODE_ESTIMATED_INTERACTIVE:
		/* estimate back traffic class rate */
		rbmax = rbb = 0;
		if (cl->back || psp_get_back(cl)) {
			rbb = RATE(cl->back_bps, time, BSTATS(cl->back).bytes);
			rbmax = cl->back->max_rate;
		}
		/* fall default */
	default:
		rb = RATE(cl->bps, time, BSTATS(cl).bytes);
		rp = RATE(cl->pps, time, BSTATS(cl).packets);
		mtu = qdisc_dev(sch)->mtu;
		rmax = cl->parent ? cl->parent->max_rate : q->max_rate;
		break;
	}

	if (rb > rmax) {
		rb = rmax;
		rp = min_t(unsigned long, rp, rmax / mtu);
	} else if (rb <
		   (rmin =
		    max_t(unsigned long, cl->allocated_rate, cl->max_rate))) {
		rb = rmin;
		rp = max_t(unsigned long, rp, rmin / mtu);
	}
	rp = rp ? : 1;
	switch (cl->state & MAJOR_MODE_MASK) {
	case TC_PSP_MODE_ESTIMATED_GAP_DATA:
		cl->hw_gap =
		    max_t(long, ((long)(rmax - rb) / rp) - HW_GAP(q) - FCS, 0);
		break;
	case TC_PSP_MODE_ESTIMATED_GAP:
		cl->hw_gap = q->hw_gap =
		    max_t(long, ((long)(rmax - rb) / rp) - HW_GAP(q) - FCS, 0);
		break;
	case TC_PSP_MODE_ESTIMATED:
	case TC_PSP_MODE_ESTIMATED_DATA:
		break;
	case TC_PSP_MODE_ESTIMATED_INTERACTIVE:
		rb = rbb ? mul_div(rbmax, min(rb, cl->rate), rbb) : rmax;
		break;
	default:
		break;
	}
	cl->rate = rb;
}

static void psp_estimator(unsigned long arg)
{
	struct psp_class *cl;
	unsigned long time = min_t(unsigned long, etime, est_ewma);

	list_for_each_entry(cl, &elist, elist)
	    psp_class_est(cl, time);
	mod_timer(&etimer,
		  jiffies + (etime =
			     random32() % (est_max - est_min) + est_min));
}

static void est_add(struct psp_class *cl)
{
#ifndef CONFIG_NET_SCH_PSP_EST
	if (!list_empty(&cl->elist))
		return;
	if (list_empty(&elist)) {
		etime = 1;
		setup_timer(&etimer, &psp_estimator, 1);
		psp_estimator(1);
	}
	list_add_tail(&cl->elist, &elist);
#endif
}

static void est_del(struct psp_class *cl)
{
	if (list_empty(&cl->elist))
		return;
	list_del(&cl->elist);
	if (list_empty(&elist))
		del_timer(&etimer);
}

static void add_leaf_class(struct psp_sched_data *q, struct psp_class *cl)
{
	struct psp_class *p;

	/* chain normal/pacing class list */
	cl->state |= FLAG_DMARK;
	switch (cl->state & MAJOR_MODE_MASK) {
	case TC_PSP_MODE_TEST:
	case TC_PSP_MODE_NORMAL:
		list_add_tail(&cl->plist, &q->normal_list);
		break;

	case TC_PSP_MODE_ESTIMATED:
		q->mode3 = cl;
	case TC_PSP_MODE_ESTIMATED_GAP:
	case TC_PSP_MODE_ESTIMATED_DATA:
		est_add(cl);
	case TC_PSP_MODE_STATIC_RATE:
	case TC_PSP_MODE_STATIC:
		list_for_each_entry(p, &q->pacing_list, plist) {
			if (cl->rate > p->rate)
				break;
		}
		list_add_tail(&cl->plist, &p->plist);
		break;
	}
}

/*
 * update byte clocks
 * when a packet is sent out:
 *     Qdisc clock += packet length
 *     if the class is the pacing class:
 *         update gapsize
 *         class clock += packet length + gapsize
 */

#if 0
#define _TIMER ({struct timeval now; do_gettimeofday(&now); now.tv_sec*(u64)USEC_PER_SEC+now.tv_usec; })
#define _TIMER_HZ USEC_PER_SEC
#elif 1
#define _TIMER ktime_to_ns(ktime_get_real())
#define _TIMER_HZ NSEC_PER_SEC
#else
#define _TIMER jiffies
#define _TIMER_HZ HZ
#endif

static inline unsigned long calc_rate_(struct est_data *e, clock_delta time,
				       clock_delta val, unsigned long hz,
				       unsigned long ewma)
{
	u64 r = ((u64) val) * hz;
	if (time > ewma) {
		do_div(r, time);
		e->av = r;
	} else {
		if (e->av)
			r += ((u64) e->av) * (ewma - time);
		else
			ewma = time;
		if (ewma) {
			do_div(r, ewma);
			e->av = r;
		} else
			r = 0;
	}
	return r;
}

static inline unsigned long calc_rate_ewma_(struct est_data *e,
					    clock_delta time, clock_delta val,
					    unsigned long hz,
					    unsigned long ewma)
{
	u64 r = 0;
	if (time) {
		r = ((u64) val) * hz;
		do_div(r, time);
		r += e->av * (ewma - 1);
		do_div(r, ewma);
		e->av = r;
	};
	return r;
}

static inline unsigned long calc_rate(struct est_data *e, u64 time, u64 val,
				      unsigned long hz, unsigned long ewma)
{
	clock_delta t = time - e->time;
	unsigned long rate = calc_rate_(e, t, val - e->data, hz, ewma);

	if (rate || t >= ewma) {
		e->time = time;
		e->data = val;
	}
	return rate;
}

static inline unsigned long calc_rate_ewma(struct est_data *e, u64 time,
					   u64 val, unsigned long hz,
					   unsigned long ewma)
{
	clock_delta t = time - e->time;
	unsigned long rate = calc_rate_ewma_(e, t, val - e->data, hz, ewma);

	if (rate) {
		e->time = time;
		e->data = val;
	}
	return rate;
}

static inline void reset_est(struct est_data *e, u64 time, u64 val)
{
	e->time = time;
	e->data = val;
}

/* estimate master rate */
static inline unsigned long estimate_qdisc_rate(struct Qdisc *sch,
						struct psp_sched_data *q)
{
	if (q->clock != q->clock0) {
		/* enqueue -> dequeue series, very precise time to rate estimation */
		u64 t = _TIMER;

		q->phaze_time = t - q->time;
		q->time = t;	/* save this time to classes */
		if (q->phaze_idle)
			reset_est(&q->bps, t, q->clock);
		else if (calc_rate(&q->bps, t, q->clock, _TIMER_HZ, q->ewma))
			sch->rate_est.bps = q->bps.av;
	}
	return q->bps.av;
}

static inline void estimate_class_rate(struct est_data *e, u64 cnt,
				       struct psp_sched_data *q,
				       unsigned long ewma)
{
	if (q->phaze_idle)
		reset_est(e, q->clock, cnt);
	else
		calc_rate(e, q->clock, cnt, q->max_rate, ewma);
}

static inline void update_clocks(struct sk_buff *skb, struct Qdisc *sch,
				 struct psp_class *cl)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	clock_delta len[2] = { skb->len, SKB_BACKSIZE(skb) };
	u64 t, clock[3];
	struct psp_class *cl1 = NULL;
	unsigned int d, npkt;

#ifdef CONFIG_NET_SCH_PSP_FORCE_GAP
	q->last = cl;
#endif

	/* to first parent */
	for (; cl; cl = cl->parent) {
		cl->prev = cl1;
		cl1 = cl;
	}
	clock[0] = clock[1] =
	    /* update qdisc clock */
	    q->clock0 = q->clock += skb->len + HW_GAP(q) + FCS;
	/* list classes from parent to child */
	for (cl = cl1; cl; cl = cl->prev) {
		d = cl->direction;
		npkt = DIV_ROUND_UP(len[d], cl->mtu);
		t = len[d] + npkt * cl->hw_gap;
		if ((cl->state & FLAG_DMARK)) {
			/* reset class clock */
			cl->state &= ~FLAG_DMARK;
			/* reset to parent ethernet + its transfer time */
			cl->clock = clock[d];
		}
		if (t == 0)
			goto gap0;
#ifdef CONFIG_NET_SCH_PSP_EST
		estimate_class_rate(&cl->bps, cl->phaze_bytes, q,
				    cl->ewma * npkt);
		cl->phaze_bytes += t;
		cl->qdisc->rate_est.bps = cl->bps.av;
#endif
		if (cl->autorate) {
#ifndef CONFIG_NET_SCH_PSP_EST
			estimate_class_rate(&cl->bps, cl->phaze_bytes, q,
					    cl->ewma * npkt);
			cl->phaze_bytes += t;
#endif
			cl->rate = min_t(unsigned long, q->max_rate,
					 cl->bps.av <
					 MIN_TARGET_RATE ? 0 : cl->bps.av);
		}
		if (cl->rate == 0)
			goto normal;
#define MUL_DIV_ROUND(res,x,y,z,tail) res=(x)*(y)+tail; tail=do_div(res,(z));
#define MUL_DIV_ROUND_UP(res,x,y,z,tail) res=(x)*(y)+(z)-1-tail; tail=((z)-do_div(res,(z)))%(z);
		switch (cl->state & MAJOR_MODE_MASK) {
		case TC_PSP_MODE_ESTIMATED_DATA:
			/* broken ;) */
			MUL_DIV_ROUND_UP(t, t, q->max_rate, cl->rate, cl->tail);
			/* t0 = t; */
			cl->clock += t;
			break;
		case TC_PSP_MODE_ESTIMATED:
		case TC_PSP_MODE_ESTIMATED_GAP:
		case TC_PSP_MODE_STATIC:
			/* hardware/ethernet */
#ifdef CONFIG_NET_SCH_PSP_RATESAFE
			MUL_DIV_ROUND(t, t, q->max_rate, cl->rate, cl->tail);
#else
			t = t * q->max_rate + cl->rate - 1;
			do_div(t, cl->rate);
#endif
			clock[d] = clock[d + 1] = cl->clock += (cl->t = t);
			break;
		case TC_PSP_MODE_STATIC_RATE:
			/* software/router/isp */
			if (cl->hz == 0) {
#ifdef CONFIG_NET_SCH_PSP_RATESAFE
				MUL_DIV_ROUND_UP(t, t, q->max_rate, cl->rate,
						 cl->tail);
#else
				MUL_DIV_ROUND(t, t, q->max_rate, cl->rate,
					      cl->tail);
#endif
			} else {
#ifdef CONFIG_NET_SCH_PSP_RATESAFE
				MUL_DIV_ROUND_UP(t, t, cl->hz, cl->rate,
						 cl->tail1);
				MUL_DIV_ROUND_UP(t, t, q->max_rate, cl->hz,
						 cl->tail);
#else
				/* rounds up to destination timer quantum, rate down */
				t = t * cl->hz + cl->rate - 1;
				do_div(t, cl->rate);
				t = t * q->max_rate + cl->hz - 1;
				do_div(t, cl->hz);
#endif
			}
			cl->clock += t;
			break;
		case TC_PSP_MODE_TEST:
			cl->rate = cl->max_rate = cl->bps.av;
		default:
		      normal:
			cl->clock = clock[d];
			break;
		}
	      gap0:
		/* moved from psp_dequeue() */
		if (--QSTATS(cl).qlen == 0) {
			QSTATS(cl).backlog = 0;
			psp_deactivate(q, cl);
		} else
			QSTATS(cl).backlog -=
			    min_t(unsigned long, len[d], QSTATS(cl).backlog);
	}
}

/*
 * lookup next target class
 * Firstly, search the pacing class list:
 *     If the Qdisc's clock < the class's clock then the class is selected.
 * Secondly, search the normal class list.
 *
 * Finally, a gap packet is inserted, because there is not any packets
 * to send out.  And it returns the size of the gap packet.
 */

/* lookup first by time class from list,
   return minimum time diff for future class,
   or class pointer for current/past
 */

static inline clock_delta cut_gap(struct psp_sched_data *q, clock_delta gap)
{
	/*
	 * calculate the gap packet size:
	 *     npkts = DIV_ROUND_UP(nearest, mtu + HW_GAP + FCS)
	 *     gap = (nearest / npkts) - (HW_GAP + FCS)
	 */
#ifdef gap_u64
	int tmp = q->mtu + HW_GAP(q) + FCS;
	u64 npkts = gap + tmp - 1;

	do_div(npkts, tmp);
	do_div(gap, npkts);
	return gap;
#else
	return gap / DIV_ROUND_UP(gap, q->mtu + HW_GAP(q) + FCS);
#endif
	/* -(HW_GAP+FCS) - later */
}

static inline struct sk_buff *psp_prefetch(struct psp_class *cl)
{
	struct sk_buff *skb = cl->skb = cl->qdisc->ops->dequeue(cl->qdisc);

#ifdef CONFIG_NET_SCH_PSP_FAST_SORT
	/* for prio + pfifo */
	if (skb)
		hints_delete(skb);
#endif
	return skb;
}

/* Real class clock += tt - next_tt
 * where: tt - last packet total parents' ethernet transfer time,
 *        next_tt - next packet total parents' transfer time.
 * Summary there are zero on timeline, but actual for packet send time.
 * Inductive: send time: clock - next_tt;
 *            after reset: clock += tt;
 *            nothing more.
 *
 * Lookup class, next packet and next_tt:
 */

static inline struct psp_class *lookup_early_class(const struct psp_sched_data
						   *q, struct list_head *list,
						   clock_delta * diff)
{
	struct psp_class *cl, *next = NULL;
	s64 d, nextdiff, cdiff, nextcdiff;
	struct sk_buff *skb;
	clock_delta tt[3];
	unsigned long len[2];
	struct psp_class *cl2, *cl1;
	u64 t;

	/* signed diff still correct around clock overflow... */
	list_for_each_entry(cl, list, plist) {
		if (!(cl->state & FLAG_ACTIVE)) {
			cdiff = cl->clock - q->clock;
			if (cdiff <= 0) {
				cl->state |= FLAG_DMARK;
				cl->clock = q->clock;	/* ...but not too far */
				continue;
			}
			if (cl->level)
				continue;
			d = cdiff;
			for (cl1 = cl->parent; cl1; cl1 = cl1->parent)
				d = max_t(s64, d, cl1->clock - q->clock);
		} else if ((!cl->level)
			   /* packet alredy prefetched... */
			   && ((skb = cl->skb)
			       /* or pfifo simple lookup success... */
			       || ((skb = cl->qdisc->q.next)
				   && skb != (void *)&cl->qdisc->q)
			       /* or prefetch packet from unknown leaf */
			       || (skb = psp_prefetch(cl)))) {
			cl1 = NULL;
			for (cl2 = cl; cl2; cl2 = cl2->parent) {
				cl2->prev = cl1;
				cl1 = cl2;
			}
			tt[0] = tt[1] = (len[0] = skb->len) + HW_GAP(q) + FCS;
			len[1] = SKB_BACKSIZE(skb);
			cdiff = (s64) (cl1->clock - q->clock) - tt[0];
			/* not counted (backrate) pkt: push */
			if ((t = len[cl1->direction]) == 0 && cdiff > 0)
				cdiff = 0;
#ifdef CONFIG_NET_SCH_PSP_PKT_GAP
			d = max_t(s64, cdiff, psp_tstamp(skb) - q->clock);
#else
			d = cdiff;
#endif
			while ((cl2 = cl1->prev)) {
				if (cl1->t && cl1->rate) {
					t = (t + DIV_ROUND_UP((unsigned long)t,
							      cl1->mtu) *
					     cl1->hw_gap) * q->max_rate;
					do_div(t, cl1->rate);
					tt[cl1->direction] += t;
					tt[cl1->direction + 1] += t;
				}
				/* skip classes unrated for this pkt */
				while ((t = len[cl2->direction]) == 0)
					if ((cl2 = cl2->prev) == NULL)
						goto cmp;
				cl1 = cl2;
				cdiff = (s64) (cl2->clock - q->clock) -
				    tt[cl2->direction];
				if (cdiff > d)
					d = cdiff;
			}
		} else		/* not leaf or exception */
			continue;
	      cmp:
		if (next == NULL || nextdiff > d
		    || (nextdiff == d && nextcdiff > cdiff)) {
			next = cl;
			nextdiff = d;
			nextcdiff = cdiff;
		}
	}
	if (next && nextdiff > 0) {
		next = NULL;
		*diff = min_t(s64, *diff, nextdiff);
	}
	return next;
}

#if 0
/* this part of code only for compatibility with Takano's NORMAL
    class behaviour (may be faster with very large number of concurrent
    NORMAL classes), sometimes verifyed */
static struct psp_class *lookup_next_class(struct Qdisc *sch,
					   clock_delta * gapsize)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl, *found = NULL;
	clock_delta nearest = q->mtu;

	/* pacing class */
	found = lookup_early_class(q, &q->pacing_list, &nearest);
	if (found)
		return found;

	/* normal class */
	list_for_each_entry(cl, &q->normal_list, plist) {
		if (!(cl->state & FLAG_ACTIVE))
			continue;

		list_move_tail(&cl->plist, &q->normal_list);
		return cl;
	}
	*gapsize = cut_gap(q, nearest);
	return NULL;
}

#else

static inline struct psp_class *lookup_next_class(struct Qdisc *sch,
						  unsigned long *gapsize)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl;
	clock_delta nearest = q->mtu;

	/* pacing class, then normal class */
	if ((cl = lookup_early_class(q, &q->pacing_list, &nearest)) == NULL) {
		if ((cl =
		     lookup_early_class(q, &q->normal_list, &nearest)) == NULL)
			*gapsize = cut_gap(q, nearest);
	}

	return cl;
}
#endif

#ifdef CONFIG_NET_SCH_PSP_RRR
static void rrr_set(struct psp_class *cl, int w)
{
	struct psp_class *cl1;

	list_for_each_entry(cl1, &cl->rlist, rlist)
	    cl1->weight_sum += w - cl->weight;
	cl1->weight_sum += w - cl->weight;
	cl->weight = w;
}

static void rrr_move(struct psp_class *cl, struct psp_class *master)
{
	int w = cl->weight;

	rrr_set(cl, 0);
	list_del(&cl->rlist);
	if (!master)
		return;
	cl->weight_sum = master->weight_sum;
	list_add_tail(&cl->rlist, &master->rlist);
	rrr_set(cl, w);
}
#endif

#if defined(__LITTLE_ENDIAN_BITFIELD)
#define ip_bit(nr,a) ((((unsigned char *)(a))[(nr)>>3]>>(7-((nr)&7)))&1)
#elif defined (__BIG_ENDIAN_BITFIELD)
#define ip_bit(nr,a) ((((unsigned char *)(a))[(nr)>>3]>>((nr)&7))&1)
#else
#error  "Please fix <asm/byteorder.h>"
#endif

static inline int tohash(u32 x)
{
	int i;
	for (i = HBITS; i < 32; i += HBITS)
		x ^= x >> i;
	return x & (HSIZE - 1);
}

#if 0
typedef struct hashitem tcphash[HSIZE];

static inline struct hashitem *tcphash_get(void *h, unsigned long key)
{
	return &(*((tcphash *) h))[key];
}

static inline void *tcphash_init(void)
{
	tcphash *h = kzalloc(sizeof(*h), GFP_KERNEL);

	return h;
}

static inline void tcphash_free(void *h)
{
	kfree(h);
}
#else
/* splitting array to 4K pages */
#define HBITS_ 4
#define HSIZE_ (1<<HBITS_)
#define HBITS__ (HBITS-((HBITS/HBITS_-(HBITS%HBITS_==0))*HBITS_))
#define HSIZE__ (1<<HBITS__)
typedef void *tcphash_[HSIZE_];
typedef struct hashitem tcphash__[HSIZE__];
static inline struct hashitem *tcphash_get(void *h, unsigned long key)
{
	int i;

	for (i = 0; i < (HBITS - HBITS__) / HBITS_; i++) {
		h = (*((tcphash_ *) h))[key & (HSIZE_ - 1)];
		key >>= HBITS_;
	}
	return &((*(tcphash__ *) h)[key & (HSIZE__ - 1)]);
}

static void _tcphash_free(void *h, int p)
{
	int i;

	if (h) {
		if (p < HBITS - HBITS__) {
			p += HBITS_;
			for (i = 0; i < HSIZE_; i++)
				_tcphash_free((*((tcphash_ *) h))[i], p);
		}
		kfree(h);
	}
}

static void *_tcphash_init(int p)
{
	if (p < HBITS - HBITS__) {
		int i;
		tcphash_ *h = kmalloc(sizeof(*h), GFP_KERNEL);

		if (h) {
			p += HBITS_;
			for (i = 0; i < HSIZE_; i++)
				if (!((*h)[i] = _tcphash_init(p))) {
					for (i--; i >= 0; i--)
						_tcphash_free((*h)[i], p);
					kfree(h);
					return NULL;
				}
		}
		return h;
	} else
		return kzalloc(sizeof(tcphash__), GFP_KERNEL);
}

static inline void *tcphash_init(void)
{
	return _tcphash_init(0);
}

static inline void tcphash_free(void *h)
{
	_tcphash_free(h, 0);
}
#endif

static void tree_free(node n)
{
	if (*n) {
		tree_free(&(*n)->b[0]);
		tree_free(&(*n)->b[1]);
		kfree(*n);
		*n = NULL;
	}
}

static void tree_heap_free(struct psp_class *cl)
{
	struct __node *n;
	while (cl->tree_heap) {
		n = cl->tree_heap;
		cl->tree_heap = n->b[0];
		kfree(n);
	}
}

#if 1
#define tree_node_alloc(cl) ({\
	struct __node *n;\
\
	if ((n = (cl)->tree_heap)) {\
		(cl)->tree_heap = n->b[0];\
		memset(n, 0, sizeof(struct __node));\
	} else\
		if(!(n = kzalloc(sizeof(struct __node), GFP_ATOMIC)))\
			goto err;\
	n;\
})

static inline void tree_node_free(struct psp_class *cl, struct __node *n)
{
	n->b[0] = cl->tree_heap;
	cl->tree_heap = n;
}
#else
#define tree_node_alloc(cl) kzalloc(sizeof(struct __node), GFP_KERNEL)
#define tree_node_free(cl,n) kfree(n);
#endif

#define node_val_copy(dst,src) memcpy((dst)->v,(src)->v,sizeof((dst)->v))

static inline void tree_node_fix(struct psp_class *cl, node n)
{
	int i;
	struct __node *n1 = *n;

	if (n1->b[0]) {
		if (n1->b[1]) {
			for (i = 0; i < NODEVAL; i++)
				n1->v[i] =
				    (n1->b[0]->v[i] + n1->b[1]->v[i]) >> 1;
		} else
			node_val_copy(n1, n1->b[0]);
	} else if (n1->b[1])
		node_val_copy(n1, n1->b[1]);
	else {
		*n = NULL;
		tree_node_free(cl, n1);
	}
}

#if 1
/* to be profiled */
static inline void tree_node_gap(struct __node *n1, u64 clock,
				 clock_delta * gap, int len)
{
/*	*gap = (*gap + ((clock - n1->clock) * n1->v[1]) / (n1->v[0] + n1->v[1])) >> 1; */
	u64 x1 = n1->v[1];
	u64 x = n1->v[0] + x1;

	while (x > 0xffffffffULL) {
		x >>= 1;
		x1 >>= 1;
	}
#if 1
	x1 *= (clock - n1->clock);
	do_div(x1, x);
	*gap = (*gap + x1) >> 1;
#else
	x1 *= len;
	do_div(x1, x);
	*gap = max_t(clock_delta, *gap, x1);
#endif
}

#else
static inline void tree_node_gap(struct __node *n1, u64 clock,
				 clock_delta * gap, int len)
{
	u64 x1 = n1->v[1];
	u64 x = n1->v[0] + 1;

	while ((x|x1) > 0xffffffffULL) {
		x >>= 1;
		x1 >>= 1;
	}
	x1 *= len;
	do_div(x1, x);
	*gap = max_t(clock_delta, *gap, x1);
}
#endif

static inline void tree_del(struct psp_class *cl, node n, void *key, int size,
			    u32 v0, u32 v1)
{
	node nn[TREE_MAX];
	struct __node *n1;
	int i = 0;

	for (; i < size && (n1 = *n); i++) {
		nn[i] = n;
		n = &n1->b[ip_bit(i, key)];
	}
	if ((n1 = *n)) {
		n1->v[1] -= v1;
		if ((n1->v[0] -= v0) == 0 && n1->v[1] == 0)
			tree_node_fix(cl, n);
		for (i--; i >= 0; i--)
			tree_node_fix(cl, nn[i]);
	}
}

/* egression against broken RRR changes */
#ifdef CONFIG_NET_SCH_PSP_RRR
static int
#else
static node
#endif
tree_get(node n, void *key1, void *key2, int size, int len,
		     clock_delta * gap)
{
	node nn[TREE_MAX], nx;
	struct __node *n1;
	int i = 0, j;
	u64 clock = len;
#ifdef CONFIG_NET_SCH_PSP_RRR
	int rrr = 0;
#endif

	if ((n1 = *(nx = n))) {
		clock += n1->clock;
		for (; i < size && n1; i++) {
			nn[i] = nx;
			n1 = *(nx = &n1->b[ip_bit(i, key1)]);
#ifdef CONFIG_NET_SCH_PSP_RRR
			if (!n1)
				rrr = (*nn[i])->rrr;
#endif
		}
		if (n1) {
			tree_node_gap(n1, clock, gap, len);
#ifdef CONFIG_NET_SCH_PSP_RRR
			rrr = n1->rrr;
#endif
		}
	}
	for (j = i - 1; j >= 0; j--)
		tree_node_gap(*nn[j], clock, gap, len);
	if (key2) {
		clock_delta gap2 = 0;

#ifdef CONFIG_NET_SCH_PSP_RRR
		rrr = (rrr + tree_get(n, key2, NULL, size, len, &gap2)) >> 1;
#else
		tree_get(n, key2, NULL, size, len, &gap2);
#endif
		*gap = max_t(clock_delta, *gap, gap2);
	}
	for (j = 0; j < i; j++)
		(*nn[j])->clock = clock;
	if (n1)
		n1->clock = clock;
#ifdef CONFIG_NET_SCH_PSP_RRR
	return rrr;
#else
	return nx;
#endif
}

#ifdef CONFIG_NET_SCH_PSP_RRR
static int
#else
static node
#endif
tree_add(struct psp_class *cl, node n, void *key1, void *key2,
		     int size, int index, int val, clock_delta * gap)
{
	node nn[TREE_MAX], nx;
	struct __node *n1;
	int i = 0, j;
	u64 clock = val;
#ifdef CONFIG_NET_SCH_PSP_RRR
	int rrr = 0;
#endif

	if ((n1 = *(nx = n))) {
		clock += n1->clock;
		for (; i < size && n1; i++) {
			nn[i] = nx;
			n1 = *(nx = &n1->b[ip_bit(i, key1)]);
#ifdef CONFIG_NET_SCH_PSP_RRR
			if (!n1)
				rrr = (*nn[i])->rrr;
#endif
		}
#ifdef CONFIG_NET_SCH_PSP_RRR
		if (n1)
			rrr = n1->rrr;
#endif
	}
	if (!n1) {
		for (; i < size; i++) {
			nn[i] = nx;
			(*nx) = n1 = tree_node_alloc(cl);
			n1->clock = clock;
#ifdef CONFIG_NET_SCH_PSP_RRR
			n1->rrr = rrr;
#endif
			nx = &n1->b[ip_bit(i, key1)];
		}
		(*nx) = n1 = tree_node_alloc(cl);
		n1->clock = clock;
#ifdef CONFIG_NET_SCH_PSP_RRR
		n1->rrr = rrr;
#endif
	}
	n1->v[index] += val;
	tree_node_gap(n1, clock, gap, val);
#ifdef CONFIG_NET_SCH_PSP_RRR
	rrr = n1->rrr += index;
#endif
	for (j = i - 1; j >= 0; j--) {
		tree_node_fix(cl, nn[j]);
		tree_node_gap(*nn[j], clock, gap, val);
#ifdef CONFIG_NET_SCH_PSP_RRR
		(*nn[j])->rrr = rrr;
#endif
	}
	if (key2) {
		clock_delta gap2 = 0;

#ifdef CONFIG_NET_SCH_PSP_RRR
		rrr =
		    (rrr +
		     tree_add(cl, n, key2, NULL, size, index, val, &gap2)) >> 1;
#else
		tree_add(cl, n, key2, NULL, size, index, val, &gap2);
#endif
		*gap = max_t(clock_delta, *gap, gap2);
	}

	for (j = 0; j < i; j++)
		(*nn[j])->clock = clock;
	n1->clock = clock;
#ifdef CONFIG_NET_SCH_PSP_RRR
	return rrr;
#else
	return nx;
#endif
      err:
	printk(KERN_ERR "psp: unable to allocate tcp tree node\n");
#ifdef CONFIG_NET_SCH_PSP_RRR
	return rrr;
#else
	return nx;
#endif
}

static inline int retrans_check(struct sk_buff *skb, struct psp_class *cl,
				struct psp_sched_data *q)
{
	int x, asz, naddr = 0;
	unsigned char *th;
	void *addr[2] = { NULL, NULL }, *saddr;
	struct hashitem *h;
#define TH ((struct tcphdr *)th)
	int res = 0;		/* 0-not retransmission, 1-retransmission */
	clock_t early = 0;
	int len = skb->len;
	int rrr = 0;
	node iptree;
	unsigned int hdr_size;
	u32 seq, aseq;
	clock_delta gap = 0;
	node nn;

	if (skb->protocol == __constant_htons(ETH_P_IP)) {
		const struct iphdr *iph = ip_hdr(skb);

		iptree = &cl->iptree;
		saddr = (void *)&iph->saddr;
		if (cl->state & TC_PSP_MODE_RETRANS_DST)
			addr[naddr++] = (void *)&iph->daddr;
		if (cl->state & TC_PSP_MODE_RETRANS_SRC)
			addr[naddr++] = saddr;
		asz = 4;
		if (iph->frag_off & htons(IP_MF | IP_OFFSET)
		    || iph->protocol != IPPROTO_TCP
#ifndef CONFIG_IPV6
		    || iph->version != 4
#endif
		    )
			goto ip;
		th = (unsigned char *)iph + (iph->ihl << 2);
		x = jhash_3words(iph->saddr, iph->daddr, *(u32 *) th, psp_rand);
	} else
#ifdef CONFIG_IPV6
	if (skb->protocol == __constant_htons(ETH_P_IPV6)) {
		struct ipv6hdr *iph = ipv6_hdr(skb);

		iptree = &cl->ip6tree;
		saddr = &iph->saddr;
		if (cl->state & TC_PSP_MODE_RETRANS_DST)
			addr[naddr++] = &iph->daddr;
		if (cl->state & TC_PSP_MODE_RETRANS_SRC)
			addr[naddr++] = saddr;
		asz = 16;
		if (iph->nexthdr != IPPROTO_TCP)
			goto ip;
		x = jhash(&iph->saddr, 32, psp_rand);
		th = (unsigned char *)&iph[1];
		x = jhash2((u32 *) th, 1, x);
	} else
#endif
		return -1;
	hdr_size = th - skb->data + (TH->doff << 2);
	seq = be32_to_cpu(TH->seq);
	aseq = be32_to_cpu(TH->ack_seq);
	h = tcphash_get(cl->tcphash, tohash(x));
#ifdef SYN_WEIGHT
	if (TH->syn) {
		/* slowdown syn */
		res = 1;
		/* len<<=SYN_WEIGHT; */
		if (h->syn && !(h->ack ^ TH->ack))
			/* second syn */
			len <<= SYN_WEIGHT;
	}
#endif
#ifdef TTL
	if (!h->tcplist.next)
		goto clean;
	__list_del(h->tcplist.prev, h->tcplist.next);
#endif
	if (
#ifdef CONFIG_IPV6
		   h->asize == asz &&
#endif
		   !memcmp(&h->saddr, saddr, asz << 1)) {
#ifdef SYN_WEIGHT
		if ((h->syn & TH->syn) && !(h->ack ^ TH->ack)) {
			/* syn-flood: syn from&to same IP */
			res = 1;
			len <<= SYN_WEIGHT;
		}
#endif
		if (h->ports == *(u32 *) th) {
			if (seq == h->seq) {
				/* same sequence */
				if (TH->ack && aseq != h->ack_seq)
					goto next_aseq;
				/* sequences equal or unused, comparing other tcp data */
				if (memcmp(&h->misc, th + 12, sizeof(h->misc)))
					goto next_pkt;
				if (TH->ack && (TH->fin | TH->rst) == 0
				    && (x = q->mtu - hdr_size)) {
					/* ack retransmission */
					SKB_BACKSIZE(skb) =
					    be16_to_cpu(TH->window);
					SKB_BACKSIZE(skb) +=
					    DIV_ROUND_UP(SKB_BACKSIZE(skb), x)
					    * hdr_size;
					SKB_BACKSIZE(skb) >>= 1;
				}
			      retrans:	/* same tcp packet - retransmission */
#ifdef SYN_WEIGHT
				if (res)	/* packet alredy slowed */
					goto continue_connection;
#endif
				/* QSTATS(cl).overlimits += len; */
				res = 1;
				if (!(cl->state & TC_PSP_MODE_RETRANS_FAST))
					goto continue_connection;
				early = h->clock;
				goto continue_connection;
			}
			if (seq > h->seq) {
				/* new sequence */
#ifdef SYN_WEIGHT
				if (res)
					goto next_seq;	/* packet alredy slowed */
#endif
				if (seq == h->end)
					/* speedup first packet of sequence */
					goto tcp_fast;
				else if (seq < h->end) {
					/* too many data in sequence */
					if ((h->end - h->seq) >> 1 <=
					    (h->end - seq))
						/* retransmission ("<" - lost before, "=" - after) */
						/* current packet are not retrans, but count them */
						goto tcp_fast_retrans;
				} else {
					/* packet lost or sequence not fully tracked */
#ifdef STRICT_TCP
					/* or sequences with same window trapped to other path */
					if (h->end > h->seq
					    && (seq - h->end) % (h->end -
								 h->seq) == 0)
#endif
						goto tcp_fast;
				}
			} else {
				/* old sequence */
				if (h->seq - seq <= h->v[0])
					/* trap to transferred size, retransmission */
					goto retrans;
				/* unsure, new connection or untracked retrans */
			}
			goto next_seq;
		      tcp_fast_retrans:
			res = 1;
		      tcp_fast:
			if (!(cl->state & TC_PSP_MODE_RETRANS_FAST))
				goto next_seq;
			early = h->clock;
			goto next_seq;
		}
	}
      new_connection:
	/* change hashed connection to new */
	if (cl->state & TC_PSP_MODE_RETRANS_DST)
		tree_del(cl, iptree, &h->daddr, asz << 3, h->v[0], h->v[1]);
	if (cl->state & TC_PSP_MODE_RETRANS_SRC)
		tree_del(cl, iptree, &h->saddr, asz << 3, h->v[0], h->v[1]);
#ifdef HASH_ZERO
	memset(&h->v, 0, HASH_ZERO);
#else
	memset(h, 0, sizeof(struct hashitem));
#endif
#ifdef TTL
      clean:
#endif
	memcpy(&h->saddr, saddr, asz << 1);
	h->ports = *(u32 *) th;
#ifdef CONFIG_IPV6
	h->asize = asz;
#endif
      next_seq:
	h->end = h->seq = seq;
	if (TH->ack) {
	      next_aseq:
		if (aseq > h->ack_seq && (TH->fin | TH->rst) == 0
		    && (x = q->mtu - hdr_size)) {
			SKB_BACKSIZE(skb) = be16_to_cpu(TH->window);
			SKB_BACKSIZE(skb) +=
			    DIV_ROUND_UP(SKB_BACKSIZE(skb), x) * hdr_size;
		}
		h->ack_seq = aseq;
	}
      next_pkt:
	memcpy(&h->misc, th + 12, sizeof(h->misc));
	/* h->end+=(TH->syn?1:(skb->len-hdr_size))+TH->fin; *//* rfc793 */
	h->end += skb->len - hdr_size + TH->syn + TH->fin;
      continue_connection:
	if ((u32) (h->v[res] += len) < (u32) len)
		goto overflow;
#ifdef TTL
	list_add_tail(&h->tcplist, &cl->tcplist);
#endif
	if (cl->state & (TC_PSP_MODE_RETRANS_SRC | TC_PSP_MODE_RETRANS_DST)) {
#ifdef CONFIG_NET_SCH_PSP_RRR
		rrr =
#endif
		    nn =
		    tree_add(cl, iptree, addr[0], addr[1], asz << 3, res, len,
			     &gap);
//              if((!nn) || (*nn)->v[0]<h->v[0] || (*nn)->v[1]<h->v[1])
//                      printk(KERN_DEBUG "bad add: %i:%i %llu %llu\n",res,len,(*nn)->v[0],(*nn)->v[1]);
	}
#ifdef CONFIG_NET_SCH_PSP_RRR
	if (res)
		h->rrr = rrr;
	else
		rrr = h->rrr;
#endif
#if 1
	h->clock = skb->len + (psp_tstamp(skb) =
			       max_t(u64, psp_tstamp(skb) + gap, h->clock));
#else
	h->clock = skb->len + (psp_tstamp(skb) = h->clock + gap);
#endif
	early += psp_tstamp(skb);
	if (early > psp_tstamp(skb))	/* overflow protection */
		psp_tstamp(skb) = early >> 1;
#ifdef TTL
	if ((!list_empty(&cl->tcplist))
	    && cl->clock > (h =
			    (struct hashitem *)cl->tcplist.next)->clock +
	    q->ttl) {
#ifdef CONFIG_IPV6
		asz = h->asize;
#endif
		if (cl->state & TC_PSP_MODE_RETRANS_DST)
			tree_del(cl, iptree, &h->daddr, asz << 3, h->v[0],
				 h->v[1]);
		if (cl->state & TC_PSP_MODE_RETRANS_SRC)
			tree_del(cl, iptree, &h->saddr, asz << 3, h->v[0],
				 h->v[1]);
		__list_del(h->tcplist.prev, h->tcplist.next);
#ifdef HASH_ZERO
		h->tcplist.next = NULL;
		memset(&h->v, 0, HASH_ZERO);
#else
		memset(h, 0, sizeof(struct hashitem));
#endif
	};
#endif
	/* cl->phaze_bytes -= len * res; */
	return rrr;
      overflow:
	h->v[res] -= len;
	goto new_connection;
      ip:
	if (cl->state & (TC_PSP_MODE_RETRANS_SRC | TC_PSP_MODE_RETRANS_DST))
#ifdef CONFIG_NET_SCH_PSP_RRR
		rrr =
#endif
		    tree_get(iptree, addr[0], addr[1], asz << 3, len, &gap);
	psp_tstamp(skb) += gap;
#if 0
	SKB_BACKSIZE(skb) = len;	/* ???: think, non-tcp packet produce same traf */
#endif
	return rrr;
}

static inline struct sk_buff_head *fifo_tstamp_sort(struct sk_buff *skb)
{				/* must be tail */
	struct sk_buff_head *list = (struct sk_buff_head *)skb->next;

	if (list && list != (struct sk_buff_head *)skb) {
		__skb_queue_tstamp(list, __skb_dequeue_tail(list));
		return list;
	}

	return NULL;
}

static int psp_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl, *cl1;
	int err, l, len[2] = { skb->len, 0 }, npkt = 1, drops = 0;
#ifdef CONFIG_NET_SCH_PSP_PKT_GAP
	struct sk_buff *skb1 = NULL;
#endif

	if (q->clock0 == q->clock)
		q->phaze_idle = !sch->q.qlen;

	cl = psp_classify(skb, sch, &err);
#ifdef ENABLE_PSP_DIRECT
	if (cl == PSP_DIRECT) {
		/* enqueue to helper queue */
		__skb_queue_tail(&q->requeue, skb);
		q->direct_pkts++;
	} else
#endif
	if (cl == NULL) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
		if (err == NET_XMIT_BYPASS)
#else
		if (err & __NET_XMIT_BYPASS)
#endif
			QSTATS(sch).drops++;
		kfree_skb(skb);
		return err;
	} else {
		SKB_BACKSIZE(skb) = 0;

		q->clock0 = (psp_tstamp(skb) =
			     q->clock0) + skb->len + HW_GAP(q) + FCS;
		for (cl1 = cl; cl1; cl1 = cl1->parent) {
			if (cl1->state & TC_PSP_MODE_RETRANS) {
#ifdef CONFIG_NET_SCH_PSP_RRR
				int rrr =
#endif
				    retrans_check(skb, cl1, q);
				len[1] = SKB_BACKSIZE(skb);
#ifdef CONFIG_NET_SCH_PSP_RRR
				/* change dst mac, etc - "tc pedit" */
				if (!list_empty(&cl->rlist)) {
					struct psp_class *cl2 = NULL;
					rrr %= cl->weight_sum;
					if ((rrr -= cl->weight) >= 0)
						list_for_each_entry(cl2,
								    &cl->rlist,
								    rlist) {
						if ((rrr -= cl2->weight) < 0) {
							cl = cl2;
							break;
						}
						}
				}
#endif
#ifdef CONFIG_NET_SCH_PSP_PKT_GAP
				/* prefetched skb later then this? */
				if (cl->skb
				    && psp_tstamp(skb) < psp_tstamp(cl->skb)) {
					struct psp_class *cl2;
					int len1[2] = { cl->skb->len,
						SKB_BACKSIZE(cl->skb)
					};

					for (cl2 = cl; cl2; cl2 = cl2->parent) {
						l = cl->direction;
						l = len[l] - len1[l];
						BSTATS(cl2).bytes += l;
						QSTATS(cl2).backlog += l;
					}
					BSTATS(sch).bytes += len[0] - len1[0];
					skb1 = skb;
					skb = cl->skb;
					cl->skb = skb1;
					len[0] = len1[0];
					len[1] = len1[1];
				}
#endif
				break;
			}
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
		qdisc_skb_cb(skb)->pkt_len = len[cl->direction];
		if ((err = qdisc_enqueue(skb, cl->qdisc)) != NET_XMIT_SUCCESS) {
			if (net_xmit_drop_count(err))
#else
		err = cl->qdisc->ops->enqueue(skb, cl->qdisc);
		if (unlikely(err != NET_XMIT_SUCCESS)) {
#endif
			drops++;
			npkt = len[0] = len[1] = 0;
			goto stat;
		}
		hints_init(skb);
		if (cl1) {
			struct sk_buff_head *list;
			struct Qdisc *leaf;

#ifndef CONFIG_NET_SCH_PSP_FAST_SORT
#ifdef CONFIG_NET_SCH_PSP_PKT_GAP
			if (skb1)
				list = fifo_requeue_tail(skb);
			else
#endif
#endif
				list = fifo_tstamp_sort(skb);
#ifdef CONFIG_NET_SCH_PSP_FAST_SORT
			/* drop any pfifo over-[limit] */
			if (list && list->qlen == qdisc_dev(sch)->tx_queue_len) {
				leaf = container_of(list, struct Qdisc, q);
#else
			/* if there are OUR pfifo - drop [limit] oldest packet */
			if (list == &(leaf = cl->qdisc)->q
			    && list->qlen == qdisc_dev(sch)->tx_queue_len) {
				leaf = cl->qdisc;
#endif
				hints_unlink_tail(list);
				l = leaf->ops->drop(cl->qdisc);
				len[0] -= l;	/* ??? */
				len[1] -= l;
				npkt = 0;
				drops = 1;
			}
		}
	      stat:
		for (; cl; cl = cl->parent) {
			l = len[cl->direction];
			QSTATS(cl).qlen += npkt;
			BSTATS(cl).packets += npkt;
			BSTATS(cl).bytes += l;
			QSTATS(cl).drops += drops;
			QSTATS(cl).backlog += l;
			if ((!(cl->state & FLAG_ACTIVE)) && npkt)
				psp_activate(q, cl);
		}
	}

	sch->q.qlen += npkt;
	BSTATS(sch).packets += npkt;
	BSTATS(sch).bytes += len[0];
	QSTATS(sch).drops += drops;

	return err;
}

static int psp_requeue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct psp_sched_data *q = qdisc_priv(sch);

	__skb_queue_head(&q->requeue, skb);
	sch->q.qlen++;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
	QSTATS(sch).requeues++;
#endif
	return NET_XMIT_SUCCESS;
}

static struct sk_buff *psp_dequeue(struct Qdisc *sch)
{
	struct sk_buff *skb;
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl = NULL;
	clock_delta gapsize;

	q->mtu = MTU(sch);

#ifdef CONFIG_NET_SCH_PSP_EST
	estimate_qdisc_rate(sch, q);
	if (q->autorate)
		q->max_rate = q->bps.av;
#else
	if (q->autorate)
		q->max_rate = estimate_qdisc_rate(sch, q);
#endif

	if (sch->q.qlen == 0) {
		if (q->mode3 && q->clock < q->mode3->clock)
			/* reset qdisc clock */
			q->clock = q->mode3->clock;
		return NULL;
	}

	/* requeue */
	skb = __skb_dequeue(&q->requeue);
	if (skb != NULL) {
		sch->q.qlen--;
		return skb;
	}
	/* normal/pacing class */
#ifdef CONFIG_NET_SCH_PSP_FORCE_GAP
	if ((cl = q->wait))
		q->wait = NULL;
	else
#endif
		cl = lookup_next_class(sch, &gapsize);
	if (cl != NULL) {
#ifdef CONFIG_NET_SCH_PSP_FORCE_GAP
		if (q->last)
			goto min_gap;
#endif
		skb = cl->skb;
		cl->skb = NULL;
		if (skb == NULL) {
			skb = cl->qdisc->ops->dequeue(cl->qdisc);
			if (skb == NULL)
				goto nothing;	/* nothing to send */
			hints_delete(skb);
		}
		sch->q.qlen--;
		update_clocks(skb, sch, cl);
		return skb;
	}

	/* per-packet gap on interface */
	gapsize -= min_t(unsigned long, gapsize, q->hw_gap);
	/* clone a gap packet */
	gapsize =
	    max_t(int, gapsize,
		  sizeof(struct gaphdr) + (HW_GAP(q) + FCS)) - (HW_GAP(q) +
								FCS);
      gap:
	skb = skb_clone(q->gap, GFP_ATOMIC);
	if (unlikely(!skb))
		goto noclone;
	skb_trim(skb, gapsize);
	q->xstats.bytes += gapsize;
	q->xstats.packets++;
	q->clock += q->hw_gap;
	update_clocks(skb, sch, NULL);
	return skb;
#ifdef CONFIG_NET_SCH_PSP_FORCE_GAP
      min_gap:
	/* remember class and insert minimal gap before */
	q->wait = cl;
	gapsize = sizeof(struct gaphdr);
	goto gap;

#endif
      noclone:
	printk(KERN_ERR "psp: cannot clone a gap packet.\n");
      nothing:
	return NULL;
}

static unsigned int psp_drop(struct Qdisc *sch)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl;
	unsigned int len;

	list_for_each_entry(cl, &q->drop_list, dlist) {
		if (cl->qdisc->ops->drop != NULL &&
		    (len = cl->qdisc->ops->drop(cl->qdisc)) > 0) {
			if (deq(sch, q, cl, 1) == 0)
				list_move_tail(&cl->dlist, &q->drop_list);

			QSTATS(cl).drops++;
			QSTATS(sch).drops++;
			return len;
		}
	}
	return 0;
}

static void psp_reset(struct Qdisc *sch)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl;
	unsigned int i;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	struct hlist_node *n;
#endif

	for (i = 0; i < PSP_HSIZE; i++) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
		list_for_each_entry(cl, &q->hash[i], hlist) {
#else
		hlist_for_each_entry(cl, n, &q->clhash.hash[i], common.hnode) {
#endif
			QSTATS(cl).qlen = 0;
			QSTATS(cl).backlog = 0;
			if (cl->skb) {
				kfree_skb(cl->skb);
				cl->skb = NULL;
			}
			if (cl->level == 0) {
				qdisc_reset(cl->qdisc);
			}
		}
	}

#ifdef CONFIG_NET_SCH_PSP_FORCE_GAP
	q->last = q->wait = NULL;
#endif
	__skb_queue_purge(&q->requeue);
	INIT_LIST_HEAD(&q->drop_list);
	sch->q.qlen = 0;
}

static u64 _phy_rate(struct Qdisc *sch)
{
	struct ethtool_cmd cmd = { ETHTOOL_GSET };
#ifdef NETIF_F_TSO
	if (qdisc_dev(sch)->ethtool_ops
	    && qdisc_dev(sch)->ethtool_ops->get_settings) {
		if (qdisc_dev(sch)->ethtool_ops->
		    get_settings(qdisc_dev(sch), &cmd) == 0) {
			phy_rate = (u64) cmd.speed * (1000000 / BITS_PER_BYTE);
		}
	}
#endif
	return phy_rate;
}

static int psp_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[_OPT(TCA_PSP_QOPT + 1)];
	struct tc_psp_qopt *qopt;

	if (opt == NULL || nla_parse_nested(tb, TCA_PSP_QOPT, opt, NULL) ||
	    tb[_OPT(TCA_PSP_QOPT)] == NULL ||
	    nla_len(tb[_OPT(TCA_PSP_QOPT)]) < sizeof(*qopt)) {
		return -EINVAL;
	}

	qopt = nla_data(tb[_OPT(TCA_PSP_QOPT)]);

	if (qopt->chk != sizeof(*qopt)) {
		printk(KERN_ERR
		       "psp: qdisc options size / tc version mismatch (%u/%u)\n",
		       qopt->chk, sizeof(*qopt));
		return -EINVAL;
	}

	sch_tree_lock(sch);
	if (qopt->defcls) {
		q->defcls = qopt->defcls;
		bind_default(sch);
	}
#define chopt(x,y) if((y)) (x)=(y);
	chopt(q->ifg, qopt->ifg);
	chopt(est_min, mul_div(qopt->est_min, HZ, USEC_PER_SEC));
	chopt(est_max, mul_div(qopt->est_max, HZ, USEC_PER_SEC));
	chopt(est_ewma, qopt->ewma);
	chopt(q->ewma, qopt->ewma);
	if ((q->autorate = (qopt->rate == 1))) {
		q->bps.av = sch->rate_est.bps = _phy_rate(sch);
		qopt->rate = 0;
	}
	if (qopt->rate)
		q->default_rate = q->max_rate = qopt->rate;
	else
		q->default_rate = q->max_rate = _phy_rate(sch);
#ifdef TTL
	q->ttl = mul_div(TTL, q->max_rate, MSEC_PER_SEC);
#endif
	sch_tree_unlock(sch);

	return 0;
}

static int psp_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	int i;

	memset(q, 0, sizeof(*q));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23)
	/*
	 * NOTE: PSPacer can only work as a root qdisc since it produces
	 * (gap) packets itself and thereby violates the rule that a qdisc
	 * can only hand out packets that were enqueued to it.
	 * Using it as a leaf qdisc causes that qlen counters become
	 * inconsistent between itself and the upper qdiscs.
	 */
	if (sch->parent != TC_H_ROOT) {
		printk(KERN_ERR "psp: PSPacer cannot work as a leaf qdisc.\n");
		return -EINVAL;
	}
	_phy_rate(sch);
#endif

	if (dev->type != ARPHRD_ETHER) {
		printk(KERN_ERR "psp: PSPacer only supports Ethernet NICs.\n");
		return -EINVAL;
	}
#ifdef NETIF_F_TSO
	if (dev->features & NETIF_F_TSO) {
		printk(KERN_ERR "psp: PSPacer does not support TSO. You have"
		       " to disable it by using \"ethtool -K %s tso off\"\n",
		       dev->name);
		return -EINVAL;
	}
#endif
	q->defclass = PSP_DIRECT;
	q->ifg = 12;		/* default ifg is 12 byte. */
	q->ewma = mul_div(EWMA_DEFAULT, _TIMER_HZ, NSEC_PER_SEC);
	i = psp_change(sch, opt);
	if (i) {
		printk(KERN_ERR "psp: change failed.\n");
		return i;
	}

	q->mtu = MTU(sch);
	q->gap = alloc_gap_packet(sch, q->mtu);
	if (q->gap == NULL)
		return -ENOBUFS;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	INIT_LIST_HEAD(&q->root);
	for (i = 0; i < PSP_HSIZE; i++)
		INIT_LIST_HEAD(q->hash + i);
#else
	i = qdisc_class_hash_init(&q->clhash);
	if (i < 0)
		return i;
#endif
	INIT_LIST_HEAD(&q->drop_list);
	INIT_LIST_HEAD(&q->pacing_list);
	INIT_LIST_HEAD(&q->normal_list);
	skb_queue_head_init(&q->requeue);

	if (!psp_rand)
		psp_rand = random32();

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
/* The older kernels lack tcf_destroy_chain(). */
static void psp_destroy_chain(struct tcf_proto **fl)
{
	struct tcf_proto *tp;

	while ((tp = *fl) != NULL) {
		*fl = tp->next;
		tcf_destroy(tp);
	}
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
#define psp_destroy_chain(fl) tcf_destroy_chain(*(fl))
#else
#define psp_destroy_chain tcf_destroy_chain
#endif

static void psp_destroy_class(struct Qdisc *sch, struct psp_class *cl)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *pos, *next;

#define UNCLASS(f,z) if(q->f == cl) q->f = z;
	UNCLASS(defclass, PSP_DIRECT);
#ifdef CONFIG_NET_SCH_PSP_FORCE_GAP
	UNCLASS(last, NULL);
	UNCLASS(wait, NULL);
#endif
	if (cl->parent)
		cl->parent->allocated_rate -= cl->max_rate;
	else
		q->allocated_rate -= cl->max_rate;
	est_del(cl);
	if (q->mode3 == cl)
		q->mode3 = NULL;
	if (cl->back) {
		if (cl->back->forward == cl)
			cl->back->forward = NULL;
		cl->back = NULL;
	}
	if (cl->forward) {
		if (cl->forward->back == cl)
			cl->forward->back = NULL;
		cl->forward = NULL;
	}
#ifdef CONFIG_NET_SCH_PSP_RRR
	rrr_move(cl, NULL);
#endif

	psp_destroy_chain(&cl->filter_list);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	list_for_each_entry_safe(pos, next, &cl->children, sibling)
	    psp_destroy_class(sch, pos);

	list_del(&cl->hlist);
	list_del(&cl->sibling);
	psp_deactivate(q, cl);
	if (cl->level == 0) {
		list_del(&cl->plist);
		qdisc_destroy(cl->qdisc);
	}
#endif
	if (cl->skb) {
		kfree_skb(cl->skb);
		cl->skb = NULL;
	}
	UNCLASS(defclass, PSP_DIRECT);
#ifdef CONFIG_NET_SCH_PSP_FORCE_GAP
	UNCLASS(last, NULL);
	UNCLASS(wait, NULL);
#endif
	tcphash_free(cl->tcphash);
	tree_free(&cl->iptree);
#ifdef CONFIG_IPV6
	tree_free(&cl->ip6tree);
#endif
	tree_heap_free(cl);
	kfree(cl);
}

static void psp_destroy(struct Qdisc *sch)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	struct psp_class *next;
#else
	struct hlist_node *n, *next;
	unsigned int i;
#endif

	psp_destroy_chain(&q->filter_list);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	list_for_each_entry_safe(cl, next, &q->root, sibling)
	    psp_destroy_class(sch, cl);
#else
	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry_safe(cl, n, next, &q->clhash.hash[i],
					  common.hnode)
		    psp_destroy_class(sch, cl);
	}
	qdisc_class_hash_destroy(&q->clhash);
#endif
	__skb_queue_purge(&q->requeue);

	/* free gap packet */
	kfree_skb(q->gap);
}

static int psp_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct psp_sched_data *q = qdisc_priv(sch);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	unsigned char *b = skb_tail_pointer(skb);
#endif
	struct nlattr *nla;
	struct tc_psp_qopt qopt;

	memset(&qopt, 0, sizeof(qopt));
	qopt.chk = sizeof(qopt);
	qopt.defcls = q->defcls;
	qopt.ifg = q->ifg;
	qopt.rate = q->max_rate;
	qopt.direct_pkts = q->direct_pkts;
	nla = nla_nest_start(skb, TCA_OPTIONS);
	if (nla == NULL)
		goto nla_put_failure;
	NLA_PUT(skb, TCA_PSP_QOPT, sizeof(qopt), &qopt);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
	QSTATS(sch).qlen = sch->q.qlen;
	NLA_PUT(skb, TCA_STATS, sizeof(BSTATS(sch)), &BSTATS(sch));
	NLA_PUT(skb, TCA_XSTATS, sizeof(q->xstats), &q->xstats);
#endif
	nla_nest_end(skb, nla);
	return skb->len;

      nla_put_failure:
	nla_nest_cancel(skb, nla);
	return -1;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
static int psp_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct psp_sched_data *q = qdisc_priv(sch);

	return gnet_stats_copy_app(d, &q->xstats, sizeof(q->xstats));
}
#endif

static int psp_dump_class(struct Qdisc *sch, unsigned long arg,
			  struct sk_buff *skb, struct tcmsg *tcm)
{
	struct psp_class *cl = (struct psp_class *)arg;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	unsigned char *b = skb_tail_pointer(skb);
#endif
	struct nlattr *nla;
	struct tc_psp_copt copt;

	tcm->tcm_parent = cl->parent ? class_id(cl->parent) : TC_H_ROOT;
	tcm->tcm_handle = class_id(cl);
	if (cl->level == 0) {
		tcm->tcm_info = cl->qdisc->handle;
	}

	nla = nla_nest_start(skb, TCA_OPTIONS);
	if (nla == NULL)
		goto nla_put_failure;
	memset(&copt, 0, sizeof(copt));
	copt.chk = sizeof(copt);
	copt.level = cl->level;
	copt.mode = cl->state & MODE_MASK;
	copt.rate = cl->rate;
	NLA_PUT(skb, TCA_PSP_COPT, sizeof(copt), &copt);
	NLA_PUT(skb, TCA_PSP_QOPT, 0, NULL);	/* ??? */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
	NLA_PUT(skb, TCA_STATS, sizeof(cl->stats), &cl->stats);
#endif
	nla_nest_end(skb, nla);
	return skb->len;

      nla_put_failure:
	nla_nest_cancel(skb, nla);
	return -1;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
static int psp_dump_class_stats(struct Qdisc *sch, unsigned long arg,
				struct gnet_dump *d)
{
	struct psp_class *cl = (struct psp_class *)arg;

	if (gnet_stats_copy_basic(d, &cl->bstats) < 0 ||
	    gnet_stats_copy_queue(d, &cl->qstats) < 0)
		return -1;

	return 0;
}
#endif

static int psp_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
		     struct Qdisc **old)
{
	struct psp_class *cl = (struct psp_class *)arg;

	if (cl == NULL)
		return -ENOENT;
	if (cl->level != 0)
		return -EINVAL;
	if (new == NULL) {
		new = q_create_dflt(sch, class_id(cl));
		if (new == NULL)
			new = &noop_qdisc;
	}

	sch_tree_lock(sch);
	*old = xchg(&cl->qdisc, new);
	sch->q.qlen -= (*old)->q.qlen;
	for (; cl; cl = cl->parent) {
		QSTATS(cl).qlen -= (*old)->q.qlen;
		QSTATS(cl).backlog = 0;
	}
	qdisc_reset(*old);
	sch_tree_unlock(sch);
	return 0;
}

static struct Qdisc *psp_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct psp_class *cl = (struct psp_class *)arg;

	return (cl != NULL && cl->level == 0) ? cl->qdisc : NULL;
}

static unsigned long psp_get(struct Qdisc *sch, u32 classid)
{
	struct psp_class *cl = psp_find(classid, sch);

	if (cl)
		cl->refcnt++;
	return (unsigned long)cl;
}

static void psp_put(struct Qdisc *sch, unsigned long arg)
{
	struct psp_class *cl = (struct psp_class *)arg;

	if (--cl->refcnt == 0)
		psp_destroy_class(sch, cl);
}

static int psp_change_class(struct Qdisc *sch, u32 classid, u32 parentid,
			    struct nlattr **tca, unsigned long *arg)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl = (struct psp_class *)*arg, *parent;
	struct nlattr *opt = tca[_OPT(TCA_OPTIONS)];
	struct nlattr *tb[_OPT(TCA_PSP_MAX + 1)];
	struct tc_psp_copt *copt;
	unsigned long *all_rate;
	struct psp_class *rrr = NULL;

	if (opt == NULL ||
	    nla_parse(tb, TCA_PSP_MAX, nla_data(opt), nla_len(opt), NULL))
		return -EINVAL;

	copt = nla_data(tb[_OPT(TCA_PSP_COPT)]);

	if (copt->chk != sizeof(*copt)) {
		printk(KERN_ERR
		       "psp: class options size / tc version mismatch (%u/%u)\n",
		       copt->chk, sizeof(*copt));
		return -EINVAL;
	}

	parent = (parentid == TC_H_ROOT ? NULL : psp_find(parentid, sch));
	all_rate = parent ? &parent->allocated_rate : &q->allocated_rate;

	if (copt->rrr) {
		u32 m = TC_H_MAKE(TC_H_MAJ(sch->handle), copt->rrr);

		if (!(m == classid || (rrr = psp_find(m, sch))))
			return -EINVAL;
	}

	if (cl == NULL) {	/* create new class */
		struct Qdisc *new_q;

		cl = kmalloc(sizeof(struct psp_class), GFP_KERNEL);
		if (cl == NULL)
			return -ENOBUFS;
		memset(cl, 0, sizeof(struct psp_class));
		cl->sch = sch;
		cl->refcnt = 1;
		cl->ewma = mul_div(EWMA_DEFAULT, q->max_rate, NSEC_PER_SEC);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
		INIT_LIST_HEAD(&cl->sibling);
		INIT_LIST_HEAD(&cl->hlist);
		INIT_LIST_HEAD(&cl->children);
#else
		cl->children = 0;
#endif
		INIT_LIST_HEAD(&cl->dlist);
		INIT_LIST_HEAD(&cl->plist);
		INIT_LIST_HEAD(&cl->elist);
#ifdef TTL
		INIT_LIST_HEAD(&cl->tcplist);
#endif

#ifdef CONFIG_NET_SCH_PSP_RRR
		INIT_LIST_HEAD(&cl->rlist);
		cl->weight = 1;
		cl->weight_sum = 1;
#endif

		new_q = q_create_dflt(sch, classid);
		sch_tree_lock(sch);
		cl->qdisc = new_q ? new_q : &noop_qdisc;
		class_id(cl) = classid;
		cl->parent = parent;
		if (parent && parent->level == 0) {
			unsigned int qlen = parent->qdisc->q.qlen;

			/* turn parent into inner node */
			qdisc_reset(parent->qdisc);
			deq(sch, q, cl, qlen);
			qdisc_destroy(parent->qdisc);
			parent->qdisc = &noop_qdisc;
			list_del(&parent->plist);
			parent->level = cl->level + 1;
		}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
		list_add_tail(&cl->hlist, q->hash + psp_hash(classid));
		list_add_tail(&cl->sibling,
			      (parent ? &parent->children : &q->root));
#else
		qdisc_class_hash_insert(&q->clhash, &cl->common);
		if (parent)
			parent->children++;
#endif
	} else {
		*all_rate -= cl->rate;
		sch_tree_lock(sch);
	}

	/* setup mode and target rate */
	cl->state = (cl->state & ~MODE_MASK) | (copt->mode & MODE_MASK);
	cl->direction = ((cl)->state & TC_PSP_MODE_TCP) / TC_PSP_MODE_TCP;
	if (copt->rate < MIN_TARGET_RATE && copt->rate != 1)
		copt->rate = MIN_TARGET_RATE;
	chopt(cl->ewma, copt->ewma);
	cl->max_rate = (cl->autorate = (copt->rate == 1)) ? 0 : copt->rate;
	cl->hw_gap = copt->hw_gap;
	cl->mtu = copt->mtu ? : MTU(sch);
#if 0
	cl->bps.av = cl->bps.rate ? : all_rate;
#endif
#ifdef CONFIG_NET_SCH_PSP_RRR
	if (copt->weight)
		rrr_set(cl, copt->weight);
	if (copt->rrr)
		rrr_move(cl, rrr);
#endif
	est_del(cl);
	if (q->mode3 == cl)
		q->mode3 = NULL;

	switch (cl->state & MAJOR_MODE_MASK) {
	case TC_PSP_MODE_TEST:
	case TC_PSP_MODE_NORMAL:
		break;
	case TC_PSP_MODE_ESTIMATED:
		if (!parent)
			q->mode3 = cl;
	case TC_PSP_MODE_ESTIMATED_GAP:
	case TC_PSP_MODE_ESTIMATED_GAP_DATA:
	case TC_PSP_MODE_ESTIMATED_DATA:
		/* max_gap now are min_gap */
		cl->max_rate =
		    max_t(unsigned long, copt->rate, MIN_TARGET_RATE);
		est_add(cl);
		break;
	case TC_PSP_MODE_STATIC_RATE:
		cl->hz = cl->hw_gap;
		cl->hw_gap = 0;
	case TC_PSP_MODE_STATIC:
		if (cl->hw_gap == 0)
			cl->hw_gap = HW_GAP(q) + FCS;
		cl->rate = cl->max_rate;
		/* let it be oversubscribed! */
		break;
	default:
		printk(KERN_ERR "psp: unknown major mode=%x.\n",
		       cl->state & MAJOR_MODE_MASK);
		goto invalid_parameter;
		break;
	}
	*all_rate += cl->max_rate;

	if (cl->level == 0) {
		if (!list_empty(&cl->plist))
			list_del(&cl->plist);
		add_leaf_class(q, cl);
	}
	if (cl->state & TC_PSP_MODE_RETRANS) {
		if (!cl->tcphash)
			cl->tcphash = tcphash_init();
	} else if (cl->tcphash) {
		tcphash_free(cl->tcphash);
		cl->tcphash = NULL;
		tree_free(&cl->iptree);
#ifdef CONFIG_IPV6
		tree_free(&cl->ip6tree);
#endif
		tree_heap_free(cl);
	}
	bind_default(sch);
	sch_tree_unlock(sch);
	*arg = (unsigned long)cl;
	return 0;
      invalid_parameter:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	list_del_init(&cl->hlist);
#endif
	psp_deactivate(q, cl);
	if (--cl->refcnt == 0)
		psp_destroy_class(sch, cl);
	sch_tree_unlock(sch);
	return -EINVAL;
}

static int psp_delete(struct Qdisc *sch, unsigned long arg)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl = (struct psp_class *)arg, *cl1;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	if (!list_empty(&cl->children) || cl->filter_cnt)
#else
	if (cl->children || cl->filter_cnt)
#endif
		return -EBUSY;

	sch_tree_lock(sch);

	if (cl->level == 0)
		qdisc_reset(cl->qdisc);

	sch->q.qlen -= QSTATS(cl).qlen;
	for (cl1 = cl->parent; cl1; cl1 = cl1->parent) {
		QSTATS(cl1).qlen -= QSTATS(cl).qlen;
		QSTATS(cl1).backlog -= QSTATS(cl).backlog;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	list_del_init(&cl->hlist);
#else
	qdisc_class_hash_remove(&q->clhash, &cl->common);
	cl->parent->children--;
#endif
	psp_deactivate(q, cl);
	list_del_init(&cl->plist);
	if (--cl->refcnt == 0)
		psp_destroy_class(sch, cl);

	sch_tree_unlock(sch);
	return 0;
}

static void psp_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	unsigned int i;
	struct psp_class *cl;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	struct hlist_node *n;
#endif

	if (arg->stop)
		return;

	for (i = 0; i < PSP_HSIZE; i++) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
		list_for_each_entry(cl, &q->hash[i], hlist) {
#else
		hlist_for_each_entry(cl, n, &q->clhash.hash[i], common.hnode) {
#endif
			if (arg->count < arg->skip) {
				arg->count++;
				continue;
			}
			if (arg->fn(sch, (unsigned long)cl, arg) < 0) {
				arg->stop = 1;
				return;
			}
			arg->count++;
		}
	}
}

static struct tcf_proto **psp_find_tcf(struct Qdisc *sch, unsigned long arg)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl = (struct psp_class *)arg;
	struct tcf_proto **fl = cl ? &cl->filter_list : &q->filter_list;

	return fl;
}

static unsigned long psp_bind_filter(struct Qdisc *sch, unsigned long parent,
				     u32 classid)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl = psp_find(classid, sch);

	if (cl)
		cl->filter_cnt++;
	else
		q->filter_cnt++;
	return (unsigned long)cl;
}

static void psp_unbind_filter(struct Qdisc *sch, unsigned long arg)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl = (struct psp_class *)arg;

	if (cl)
		cl->filter_cnt--;
	else
		q->filter_cnt--;
}

static struct Qdisc_class_ops psp_class_ops = {
	.graft = psp_graft,
	.leaf = psp_leaf,
	.get = psp_get,
	.put = psp_put,
	.change = psp_change_class,
	.delete = psp_delete,
	.walk = psp_walk,
	.tcf_chain = psp_find_tcf,
	.bind_tcf = psp_bind_filter,
	.unbind_tcf = psp_unbind_filter,
	.dump = psp_dump_class,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
	.dump_stats = psp_dump_class_stats,
#endif
};

static struct Qdisc_ops psp_qdisc_ops __read_mostly = {
	.id = "psp",
	.cl_ops = &psp_class_ops,
	.priv_size = sizeof(struct psp_sched_data),
	.enqueue = psp_enqueue,
	.dequeue = psp_dequeue,
	.requeue = psp_requeue,
	.drop = psp_drop,
	.init = psp_init,
	.reset = psp_reset,
	.destroy = psp_destroy,
	.change = psp_change,
	.dump = psp_dump,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
	.dump_stats = psp_dump_stats,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	.owner = THIS_MODULE,
#endif
};

static int __init psp_module_init(void)
{
	return register_qdisc(&psp_qdisc_ops);
}

static void __exit psp_module_exit(void)
{
	unregister_qdisc(&psp_qdisc_ops);
}

module_init(psp_module_init)
    module_exit(psp_module_exit)
    MODULE_LICENSE("GPL");
