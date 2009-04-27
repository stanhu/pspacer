/*
 * net/sched/sch_psp.c	PSPacer: Precise Software Pacer
 *
 *		Copyright (C) 2004-2009 National Institute of Advanced
 *		Industrial Science and Technology (AIST), Japan.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Ryousei Takano, <takano-ryousei@aist.go.jp>
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
#include <net/pkt_sched.h>
#include <asm/div64.h>

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
 * [2] http://www.gridmpi.org/pspacer.jsp
 */

#define FCS    (4)		/* Frame Check Sequence(4) */
#define MIN_GAP (64)		/* Minimum size of gap packet */
#define MIN_TARGET_RATE (1000)	/* 1 KBytes/sec */

#define PSP_HSIZE (16)

static int debug __read_mostly;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "add the size to packet header for debugging (0|1)");

/*
 * phy_rate is the maximum qdisc rate. If the kernel supports ethtool ioctl,
 * it is corrected. Otherwise it statically sets to the Gigabit rate.
 */
u64 phy_rate = 125000000;

struct psp_class {
	u32 classid;			/* class id */
	int refcnt;			/* reference count */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
	struct tc_stats stats;		/* generic stats */
#else
	struct gnet_stats_basic bstats;	/* basic stats */
	struct gnet_stats_queue qstats;	/* queue stats */
#endif
	int level;			/* class level in hierarchy */
	struct psp_class *parent;	/* parent class */
	unsigned int children;		/* number of clildren */

	struct Qdisc *qdisc;		/* leaf qdisc */

	struct tcf_proto *filter_list;	/* filter list */
	int filter_cnt;			/* filter count */

	struct list_head hlist;		/* hash list */
	struct list_head dlist;		/* drop list */
	struct list_head plist;		/* normal/pacing class qdisc list */

	u32 state;			/* reserved(8)|activity(8)|mode(16) */
#define MODE_MASK       (0x0000ffff)
#define MAJOR_MODE_MASK (0x000000ff)
#define MINOR_MODE_MASK (0x0000ff00)
#define FLAG_ACTIVE     (0x00010000)	/*  the class has packets or not */
#define FLAG_DMARK      (0x00020000)	/*  reset mark */

	u64 rate;			/* current target rate (bytes/sec) */
	u64 max_rate;			/* maximum target rate */
	u64 allocated_rate;		/* allocated rate to children */
	u64 clock;			/* class local byte clock */
};

struct psp_sched_data {
	int defcls;				/* default class id */
	struct list_head hash[PSP_HSIZE];	/* class hash */
	struct list_head drop_list;		/* active leaf class list (for
						   dropping) */
	struct list_head pacing_list;		/* gap leaf class list (in
						   order of the gap size) */
	struct list_head normal_list;		/* no gap leaf class list */

	struct sk_buff_head direct_queue;	/* direct packet */
	long direct_pkts;

	struct tcf_proto *filter_list;		/* filter list */

	u32 ifg;				/* inter frame gap */
#define HW_GAP(q) (8 + ((q)->ifg))		/* preamble + IFG */
	u64 max_rate;				/* physical rate */
	u64 allocated_rate;			/* sum of allocated rate */
	unsigned int mtu;			/* interface MTU size
						   (included ethernet heaer) */
	u64 clock;				/* wall clock */

	struct sk_buff *gap;			/* template of gap packets */
	struct tc_psp_xstats xstats;		/* psp specific stats */
};

/* A gap packet header (struct ethhdr + pause frame related stuff). */
struct gaphdr {
	unsigned char h_dest[ETH_ALEN];		/* destination eth addr */
	unsigned char h_source[ETH_ALEN];	/* source eth addr */
	__be16 h_proto;				/* MAC control */
	__be16 h_opcode;			/* MAC control opcode */
	__be16 h_param;				/* pause time */
	union {
		__be16 h_len;			/* (NON STANDARD) It is used
						   for debugging only. */
		unsigned char reserved[42];	/* must be zero */
	};
} __attribute__((packed));

/* The destination address must be specified as 01:80:c2:00:00:01. */
static const unsigned char gap_dest[ETH_ALEN] = {0x01, 0x80, 0xc2, 0x00,
						 0x00, 0x01};


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

/*
 * recalculate gapsize (ipg: inter packet gap)
 *     ipg = (max_rate / target_rate - 1) * base
 */
static inline u64 recalc_gapsize(struct psp_sched_data *q,
				 struct psp_class *cl, unsigned int len)
{
	unsigned int base = len + FCS;
	u64 ipg;

	if (cl->rate == 0) /* XXX */
		return 0;

	ipg = q->max_rate * base;
	do_div(ipg, cl->rate);
	ipg -= base;
	if (ipg > HW_GAP(q))
		return ipg - HW_GAP(q); /* gap between real/gap packets */

	printk(KERN_WARNING "psp: ipg(%lld) is smaller than HW_GAP.\n", ipg);
	return 0;
}

#define PSP_DIRECT (struct psp_class *)(-1)
static inline unsigned int psp_hash(u32 h)
{
	h ^= h >> 8;
	h ^= h >> 4;
	return h & (PSP_HSIZE - 1);
}

static inline struct psp_class *psp_find(u32 handle, struct Qdisc *sch)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl;

	list_for_each_entry(cl, &q->hash[psp_hash(handle)], hlist) {
		if (cl->classid == handle)
			return cl;
	}
	return NULL;
}

static struct psp_class *psp_classify(struct sk_buff *skb, struct Qdisc *sch,
				      int *qerr)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl;
	struct tcf_result res;
	struct tcf_proto *tcf;
	int result;

	if (skb->priority == sch->handle)
		return PSP_DIRECT;
	if (TC_H_MAJ(skb->priority ^ sch->handle) == 0 &&
	    (cl = psp_find(skb->priority, sch)) != NULL)
		if (cl->level == 0)
			return cl;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	*qerr = NET_XMIT_BYPASS;
#else
	*qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
#endif
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
				break; /* filter selected invalid classid */
		}

		if (cl->level == 0)
			return cl; /* hit leaf class */

		/* apply inner filter chain */
		tcf = cl->filter_list;
	}

	/* classification failed, try default class */
	cl = psp_find(TC_H_MAKE(TC_H_MAJ(sch->handle), q->defcls), sch);
	if (cl == NULL || cl->level != 0)
		return PSP_DIRECT;

	return cl;
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

static void add_leaf_class(struct psp_sched_data *q, struct psp_class *cl)
{
	struct psp_class *p;

	/* chain normal/pacing class list */
	switch (cl->state & MAJOR_MODE_MASK) {
	case TC_PSP_MODE_NORMAL:
		list_add_tail(&cl->plist, &q->normal_list);
		break;

	case TC_PSP_MODE_STATIC:
		cl->state |= FLAG_DMARK;
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
static void update_clocks(struct sk_buff *skb, struct Qdisc *sch,
			  struct psp_class *cl)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	unsigned int len = skb->len;
	u64 gapsize;

	/* update qdisc clock */
	q->clock += (len + HW_GAP(q) + FCS);
	if (cl == NULL || (cl->state & MAJOR_MODE_MASK) == TC_PSP_MODE_NORMAL)
		return;

	gapsize = recalc_gapsize(q, cl, len);

	/* update class clock */
	if (!(cl->state & FLAG_DMARK)) {
		cl->clock += (len + HW_GAP(q) + FCS) + gapsize;
	} else {
		/* reset class clock */
		cl->state &= ~FLAG_DMARK;
		cl->clock = q->clock + gapsize;
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
static struct psp_class *lookup_next_class(struct Qdisc *sch, u64 *gapsize)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl, *found = NULL;
	u64 diff, nearest, npkts, tmp;

	/* pacing class */
	nearest = q->mtu;
	list_for_each_entry(cl, &q->pacing_list, plist) {
		if (found == NULL && cl->clock > q->clock) {
			diff = cl->clock - q->clock;
			if (nearest > diff && diff >= MIN_GAP)
				nearest = diff;
			continue;
		}
		if (!(cl->state & FLAG_ACTIVE)) {
			cl->state |= FLAG_DMARK;
			continue;
		}

		if (found == NULL)
			found = cl;
	}
	if (found)
		return found;

	/* normal class */
	list_for_each_entry(cl, &q->normal_list, plist) {
		if (!(cl->state & FLAG_ACTIVE))
			continue;

		list_move_tail(&cl->plist, &q->normal_list);
		return cl;
	}

	/*
	 * calculate the gap packet size:
	 *     npkts = DIV_ROUND_UP(nearest, mtu + HW_GAP + FCS)
	 *     gap = (nearest / npkts) - (HW_GAP + FCS)
	 */
	tmp = q->mtu + HW_GAP(q) + FCS;
	npkts = nearest + tmp - 1;
	do_div(npkts, tmp);
	do_div(nearest, npkts);
	*gapsize = nearest - (HW_GAP(q) + FCS);
	return NULL;
}

static int psp_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl;
	int uninitialized_var(err);

	cl = psp_classify(skb, sch, &err);
	if (cl == PSP_DIRECT) {
		/* enqueue to helper queue */
		__skb_queue_tail(&q->direct_queue, skb);
		q->direct_pkts++;
	} else if (cl == NULL) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
		if (err == NET_XMIT_BYPASS)
#else
		if (err & __NET_XMIT_BYPASS)
#endif
			QSTATS(sch).drops++;
		kfree_skb(skb);
		return err;
	} else {
		err = qdisc_enqueue(skb, cl->qdisc);
		if (unlikely(err != NET_XMIT_SUCCESS)) {
			if (net_xmit_drop_count(err)) {
				QSTATS(sch).drops++;
				QSTATS(cl).drops++;
			}
			return err;
		}

		BSTATS(cl).packets++;
		BSTATS(cl).bytes += qdisc_pkt_len(skb);
		if (!(cl->state & FLAG_ACTIVE))
			psp_activate(q, cl);
	}

	sch->q.qlen++;
	BSTATS(sch).packets++;
	BSTATS(sch).bytes += qdisc_pkt_len(skb);
	return NET_XMIT_SUCCESS;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
static int psp_requeue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct psp_sched_data *q = qdisc_priv(sch);

	__skb_queue_head(&q->direct_queue, skb);
	sch->q.qlen++;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
	QSTATS(sch).requeues++;
#endif
	return NET_XMIT_SUCCESS;
}
#endif

static struct sk_buff *psp_dequeue(struct Qdisc *sch)
{
	struct sk_buff *skb = NULL;
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl;
	u64 gapsize = 0;

	if (sch->q.qlen == 0)
		return NULL;

	/* direct queue */
	skb = __skb_dequeue(&q->direct_queue);
	if (skb != NULL) {
		sch->q.qlen--;
		return skb;
	}

	/* normal/pacing class */
	cl = lookup_next_class(sch, &gapsize);
	if (cl != NULL) {
		skb = cl->qdisc->ops->dequeue(cl->qdisc);
		if (skb == NULL)
			return NULL; /* nothing to send */

		sch->q.qlen--;
		goto update_clocks;
	}

	/* clone a gap packet */
	skb = skb_clone(q->gap, GFP_ATOMIC);
	if (unlikely(!skb)) {
		printk(KERN_ERR "psp: cannot clone a gap packet.\n");
		return NULL;
	}
	skb_trim(skb, gapsize);
	q->xstats.bytes += gapsize;
	q->xstats.packets++;
        if (debug)
		((struct gaphdr *)skb->data)->h_len = htons(gapsize);

 update_clocks:
	update_clocks(skb, sch, cl);
	if (cl && cl->qdisc->q.qlen == 0)
		psp_deactivate(q, cl);
	return skb;
}

static unsigned int psp_drop(struct Qdisc *sch)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl;
	unsigned int len;

	list_for_each_entry(cl, &q->drop_list, dlist) {
		if (cl->qdisc->ops->drop != NULL &&
		    (len = cl->qdisc->ops->drop(cl->qdisc)) > 0) {
			if (cl->qdisc->q.qlen == 0)
				psp_deactivate(q, cl);
			else
				list_move_tail(&cl->dlist, &q->drop_list);

			QSTATS(cl).drops++;
			QSTATS(sch).drops++;
			sch->q.qlen--;
			return len;
		}
	}
	return 0;
}

static void psp_reset(struct Qdisc *sch)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl;
	int i;

	for (i = 0; i < PSP_HSIZE; i++) {
		list_for_each_entry(cl, &q->hash[i], hlist) {
			if (cl->level == 0)
				qdisc_reset(cl->qdisc);
		}
	}

	__skb_queue_purge(&q->direct_queue);
	INIT_LIST_HEAD(&q->drop_list);
	sch->q.qlen = 0;
}

static int psp_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[_OPT(TCA_PSP_MAX + 1)];
	struct tc_psp_qopt *qopt;

	if (opt == 0 || nla_parse_nested(tb, TCA_PSP_MAX, opt, NULL) ||
	    tb[_OPT(TCA_PSP_QOPT)] == NULL ||
	    nla_len(tb[_OPT(TCA_PSP_QOPT)]) < sizeof(*qopt)) {
		return -EINVAL;
	}

	qopt = nla_data(tb[_OPT(TCA_PSP_QOPT)]);

	sch_tree_lock(sch);
	if (qopt->defcls)
		q->defcls = qopt->defcls;
	if (qopt->ifg)
		q->ifg = qopt->ifg;
	if (qopt->rate)
		q->max_rate = qopt->rate;
	else
		q->max_rate = phy_rate;
	sch_tree_unlock(sch);

	return 0;
}

static int psp_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	struct ethtool_cmd cmd = { ETHTOOL_GSET };
	int i, ret;

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
#endif

	if (dev->type != ARPHRD_ETHER) {
		printk(KERN_ERR "psp: PSPacer only supports Ethernet NICs.\n");
		return -EINVAL;
	}

#ifdef NETIF_F_TSO
	if (dev->features & NETIF_F_TSO) {
		printk(KERN_ERR "psp: TSO is enabled. PSPacer works with TSO,"
		       " but the transmission rate is not so accurate. You can"
		       " disable it by using \"ethtool -K %s tso off\"\n",
		       dev->name);
	}

	if (dev->ethtool_ops && dev->ethtool_ops->get_settings) {
		if (dev->ethtool_ops->get_settings(dev, &cmd) == 0) {
			phy_rate = (u64)cmd.speed * 1000000;
			do_div(phy_rate, BITS_PER_BYTE);
		}
	}
#endif

	q->ifg = 12; /* default ifg is 12 byte. */
	ret = psp_change(sch, opt);
	if (ret) {
		printk(KERN_ERR "psp: change failed.\n");
		return ret;
	}

	q->mtu = dev->mtu + dev->hard_header_len;
	q->gap = alloc_gap_packet(sch, q->mtu);
	if (q->gap == NULL)
		return -ENOBUFS;

	for (i = 0; i < PSP_HSIZE; i++)
		INIT_LIST_HEAD(q->hash + i);
	INIT_LIST_HEAD(&q->drop_list);
	INIT_LIST_HEAD(&q->pacing_list);
	INIT_LIST_HEAD(&q->normal_list);
	skb_queue_head_init(&q->direct_queue);

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
	if (cl->level == 0) {
		list_del(&cl->plist);
		qdisc_destroy(cl->qdisc);
	}

	if ((cl->state & MAJOR_MODE_MASK) == TC_PSP_MODE_STATIC) {
		if (cl->parent)
			cl->parent->allocated_rate -= cl->rate;
		else {
			struct psp_sched_data *q = qdisc_priv(sch);
			q->allocated_rate -= cl->rate;
		}
	}

	psp_destroy_chain(&cl->filter_list);
	kfree(cl);
}

static void psp_destroy(struct Qdisc *sch)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl, *next;
	unsigned int i;

	psp_destroy_chain(&q->filter_list);

	for (i = 0; i < PSP_HSIZE; i++) {
		list_for_each_entry(cl, &q->hash[i], hlist)
			psp_destroy_chain(&cl->filter_list);
	}
	for (i = 0; i < PSP_HSIZE; i++) {
		list_for_each_entry_safe(cl, next, &q->hash[i], hlist)
			psp_destroy_class(sch, cl);
	}
	__skb_queue_purge(&q->direct_queue);

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
	skb_trim(skb, skb_tail_pointer(skb) - skb->data);
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
	unsigned char *b = skb_tail_pointer(skb);
	struct nlattr *nla;
	struct tc_psp_copt copt;

	tcm->tcm_parent = cl->parent ? cl->parent->classid : TC_H_ROOT;
	tcm->tcm_handle = cl->classid;
	if (cl->level == 0) {
		tcm->tcm_info = cl->qdisc->handle;
		QSTATS(cl).qlen = cl->qdisc->q.qlen;
	}

	nla = nla_nest_start(skb, TCA_OPTIONS);
	if (nla == NULL)
		goto nla_put_failure;
	memset(&copt, 0, sizeof(copt));
	copt.level = cl->level;
	copt.mode = cl->state & MODE_MASK;
	copt.rate = cl->max_rate;
	NLA_PUT(skb, TCA_PSP_COPT, sizeof(copt), &copt);
	NLA_PUT(skb, TCA_PSP_QOPT, 0, NULL);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
	NLA_PUT(skb, TCA_STATS, sizeof(cl->stats), &cl->stats);
#endif
	nla_nest_end(skb, nla);
	return skb->len;

 nla_put_failure:
	skb_trim(skb, b - skb->data);
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
		new = qdisc_create_dfltq(qdisc_dev(sch), sch->dev_queue,
					 &pfifo_qdisc_ops, cl->classid);
		if (new == NULL)
			new = &noop_qdisc;
	}

	sch_tree_lock(sch);
	*old = xchg(&cl->qdisc, new);
	sch->q.qlen -= (*old)->q.qlen;
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
	unsigned int limit;

	if (opt == NULL ||
	    nla_parse(tb, TCA_PSP_MAX, nla_data(opt), nla_len(opt), NULL))
		return -EINVAL;

	copt = nla_data(tb[_OPT(TCA_PSP_COPT)]);

	parent = (parentid == TC_H_ROOT ? NULL : psp_find(parentid, sch));

	if (cl == NULL) { /* create new class */
		struct Qdisc *new_q;

		cl = kmalloc(sizeof(struct psp_class), GFP_KERNEL);
		if (cl == NULL)
			return -ENOBUFS;
		memset(cl, 0, sizeof(struct psp_class));
		cl->refcnt = 1;
		cl->children = 0;
		INIT_LIST_HEAD(&cl->hlist);
		INIT_LIST_HEAD(&cl->dlist);
		INIT_LIST_HEAD(&cl->plist);

		new_q = qdisc_create_dfltq(qdisc_dev(sch), sch->dev_queue,
					   &pfifo_qdisc_ops, classid);
		sch_tree_lock(sch);
		if (parent && parent->level != 0) {
			unsigned int qlen = parent->qdisc->q.qlen;

			/* turn parent into inner node */
			qdisc_reset(parent->qdisc);
			sch->q.qlen -= qlen;
			qdisc_destroy(parent->qdisc);
			psp_deactivate(q, cl);
			list_del(&parent->plist);

			parent->level = (parent->parent ? parent->parent->level
					 : TC_PSP_MAXDEPTH) - 1;
		}
		cl->qdisc = new_q ? new_q : &noop_qdisc;
		cl->classid = classid;
		cl->parent = parent;

		list_add_tail(&cl->hlist, q->hash + psp_hash(classid));
		if (parent)
			parent->children++;
	} else {
		if ((cl->state & MAJOR_MODE_MASK) == TC_PSP_MODE_STATIC)
			q->allocated_rate -= cl->rate;

		sch_tree_lock(sch);
	}

	/* setup mode and target rate */
	cl->state = (cl->state & ~MODE_MASK) | (copt->mode & MODE_MASK);
	if (copt->rate < MIN_TARGET_RATE)
		copt->rate = MIN_TARGET_RATE;
	cl->max_rate = copt->rate;

	switch (cl->state & MAJOR_MODE_MASK) {
	case TC_PSP_MODE_NORMAL:
		break;

	case TC_PSP_MODE_STATIC:
		limit = (parent ? parent->allocated_rate : q->allocated_rate) +
			cl->max_rate;
		if (limit > q->max_rate) {
			printk(KERN_ERR
			       "psp: target rate is oversubscribed.\n");
			goto invalid_parameter;
		}
		cl->rate = cl->max_rate;
		if (parent)
			parent->allocated_rate += cl->rate;
		else
			q->allocated_rate += cl->rate;
		break;

	default:
		printk(KERN_ERR "psp: unknown major mode=%x.\n",
		       cl->state & MAJOR_MODE_MASK);
		goto invalid_parameter;
	}

	if (cl->level == 0) {
		if (!list_empty(&cl->plist))
			list_del(&cl->plist);
		add_leaf_class(q, cl);
	}
	sch_tree_unlock(sch);
	*arg = (unsigned long)cl;
	return 0;

 invalid_parameter:
	list_del_init(&cl->hlist);
	psp_deactivate(q, cl);
	if (--cl->refcnt == 0)
		psp_destroy_class(sch, cl);
	sch_tree_unlock(sch);
	return -EINVAL;
}

static int psp_delete(struct Qdisc *sch, unsigned long arg)
{
	struct psp_sched_data *q = qdisc_priv(sch);
	struct psp_class *cl = (struct psp_class *)arg;

	if (cl->children || cl->filter_cnt)
		return -EBUSY;

	sch_tree_lock(sch);

	if (cl->level == 0) {
		unsigned int qlen = cl->qdisc->q.qlen;

		sch->q.qlen -= qlen;
		qdisc_reset(cl->qdisc);
	}

	list_del_init(&cl->hlist);
	if (cl->parent)
		cl->parent->children--;
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
	int i;

	if (arg->stop)
		return;

	for (i = 0; i < PSP_HSIZE; i++) {
		struct psp_class *cl;

		list_for_each_entry(cl, &q->hash[i], hlist) {
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
	struct psp_class *cl = psp_find(classid, sch);

	if (cl)
		cl->filter_cnt++;

	return (unsigned long)cl;
}

static void psp_unbind_filter(struct Qdisc *sch, unsigned long arg)
{
	struct psp_class *cl = (struct psp_class *)arg;

	if (cl)
		cl->filter_cnt--;
}

static struct Qdisc_class_ops psp_class_ops = {
	.graft		=	psp_graft,
	.leaf		=	psp_leaf,
	.get		=	psp_get,
	.put		=	psp_put,
	.change		=	psp_change_class,
	.delete		=	psp_delete,
	.walk		=	psp_walk,
	.tcf_chain	=	psp_find_tcf,
	.bind_tcf	=	psp_bind_filter,
	.unbind_tcf	=	psp_unbind_filter,
	.dump		=	psp_dump_class,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
	.dump_stats	=	psp_dump_class_stats,
#endif
};

static struct Qdisc_ops psp_qdisc_ops __read_mostly = {
	.id		=	"psp",
	.cl_ops		=	&psp_class_ops,
	.priv_size	=	sizeof(struct psp_sched_data),
	.enqueue	=	psp_enqueue,
	.dequeue	=	psp_dequeue,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
	.requeue	=	psp_requeue,
#else
	.peek		=	qdisc_peek_dequeued,
#endif
	.drop		=	psp_drop,
	.init		=	psp_init,
	.reset		=	psp_reset,
	.destroy	=	psp_destroy,
	.change		=	psp_change,
	.dump		=	psp_dump,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
	.dump_stats	=	psp_dump_stats,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	.owner		=	THIS_MODULE,
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
