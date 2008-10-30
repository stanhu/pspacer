/*
 * q_psp.c		PSPacer: Precise Software Pacer
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
 *
 * Changes:
 * Denis Kaganovich, <mahatma@bspu.unibel.by> - fixes, retransmission/tcp/trees
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "utils.h"
#include "tc_util.h"
#include "sch_psp.h"

#ifdef USE_COMPAT
/* for iproute-2.4.x and older. */
extern int xget_rate(unsigned *rate, const char *str);
#define GET_RATE xget_rate
#else
#define GET_RATE get_rate
#endif

static void explain(void)
{
	fprintf(stderr,
"Usage: ... qdisc add ... psp [ default N ] [rate RATE] [psp-est MIN MAX TIME\n"
" default  minor id of class to which unclassified packets are sent {0}\n"
" rate     physical interface bandwidth\n"
" ifg      inter frame gap size\n"
" psp-est  rate estimator(s) parameters (random interval MIN..MAX, TIME=ewma)\n"
" ewma     rate estimator EWMA time, nsec\n"
"\n... class add ... psp mode M [ rate MBPS ] [hw GAP] [back DEVICE CLASSID]\n"
" mode     target rate estimation method (NORMAL=%x STATIC HARDWARE=%x\n"
"          STATIC SOFTWARE=%x) {0}\n"
"          ESTIMATED=%x ESTIMATED_GAP=%x ESTIMATED_DATA=%x ESTIMATED_GAP_DATA=%x\n"
"          ESTIMATED_INTERACTIVE=%x (ESTIMATED_* is under construction)\n"
"          +0x%x destination retransmit correction\n"
"          +0x%x source retransmit correction\n"
"          +0x%x fast retransmit correction (tcp only)\n"
"          	+%x full retransmit correction\n"
"          +0x%x tcp backrate (by window vs. length), use under retransmit mode\n"
" rate     rate allocated to this class\n"
" hw       mode 1: 0 or destination ethernet hardware gap: ifg+preamble+FCS\n"
"          mode 2: 0 or destination device (router) timer HZ\n"
" back     back-direction psp device and classid (for ESTIMATED_INTERACTIVE)\n"
" rrr      minor id of master class for retransmission-round-robin\n"
" weight   class weight for retransmission-round-robin\n"
" ewma     rate estimator EWMA time, bytes (per QDISC rate)\n"
" mtu      class MTU (for backrate, xDSL/ATM, ...)\n",
	TC_PSP_MODE_NORMAL, TC_PSP_MODE_STATIC, TC_PSP_MODE_STATIC_RATE,
	TC_PSP_MODE_ESTIMATED, TC_PSP_MODE_ESTIMATED_GAP, TC_PSP_MODE_ESTIMATED_DATA, TC_PSP_MODE_ESTIMATED_GAP_DATA,
	TC_PSP_MODE_ESTIMATED_INTERACTIVE,
	TC_PSP_MODE_RETRANS_DST, TC_PSP_MODE_RETRANS_SRC, TC_PSP_MODE_RETRANS_FAST,
	TC_PSP_MODE_RETRANS_SRC | TC_PSP_MODE_RETRANS_DST | TC_PSP_MODE_RETRANS_FAST,
	TC_PSP_MODE_TCP);
}

static void explain1(char *arg)
{
	fprintf(stderr, "Illegal \"%s\"\n", arg);
	explain();
}

int _get_usecs(__u32 *time, const char *str)
{
    unsigned x;
    int res=get_time(&x,str);
    
    *time=x;
    *time=(*time)*1000000/TIME_UNITS_PER_SEC;
    return res;
}

static int psp_parse_opt(struct qdisc_util *qu, int argc, char **argv,
			 struct nlmsghdr *n)
{
	struct tc_psp_qopt qopt;
	struct rtattr *tail;

	memset(&qopt, 0, sizeof(qopt));
	qopt.chk = sizeof(qopt);
	qopt.ifg = 12;

	while (argc > 0) {
		if (matches(*argv, "rate") == 0) {
			NEXT_ARG();
			if (matches(*argv, "auto") == 0)
				qopt.rate=1;
			else if (GET_RATE(&qopt.rate, *argv)) {
				explain1("rate");
				return -1;
			}
		} else if (matches(*argv, "default") == 0) {
			NEXT_ARG();
			if (get_u32(&qopt.defcls, *argv, 16)) {
				explain1("default");
				return -1;
			}
		} else if (matches(*argv, "ifg") == 0) {
			NEXT_ARG();
			if (get_u32(&qopt.ifg, *argv, 10)) {
				explain1("ifg");
				return -1;
			}
		} else if (matches(*argv, "ewma") == 0) {
			NEXT_ARG();
			if (get_u32(&qopt.ewma, *argv, 16)) {
				explain1("ewma");
				return -1;
			}
		} else if (matches(*argv, "psp-est") == 0) {
			NEXT_ARG();
			if (_get_usecs(&qopt.est_min, *argv)) {
				explain1("psp-est");
				return -1;
			}
			NEXT_ARG();
			if (_get_usecs(&qopt.est_max, *argv)) {
				explain1("psp-est");
				return -1;
			}
			NEXT_ARG();
			if (_get_usecs(&qopt.ewma, *argv)) {
				explain1("psp-est");
				return -1;
			}
			if(qopt.est_min<=0 || qopt.est_max<qopt.est_min
			    || qopt.est_max<qopt.ewma) {
				explain1("psp-est");
				return -1;
			}			    
		} else if (matches(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		argc--;
		argv++;
	}

	tail = NLMSG_TAIL(n);
	addattr_l(n, 1024, TCA_OPTIONS, NULL, 0);
	addattr_l(n, 1024, TCA_PSP_QOPT, &qopt, sizeof(qopt));
	tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;
	return 0;
}

static int psp_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_PSP_MAX+1];
	struct tc_psp_copt *copt;
	struct tc_psp_qopt *qopt;
	char m1[64]={0};
	SPRINT_BUF(b);

	if (opt == NULL)
		return 0;

	memset(tb, 0, sizeof(tb));
	parse_rtattr_nested(tb, TCA_PSP_MAX, opt);

	if (tb[TCA_PSP_COPT]) {
		copt = RTA_DATA(tb[TCA_PSP_COPT]);
		if (RTA_PAYLOAD(tb[TCA_PSP_COPT]) < sizeof(*copt))
			return -1;
		fprintf(f, "level %d ", (int)copt->level);
		if((copt->mode & TC_PSP_MIN_MODE_MASK))
		    sprintf(m1,"(0x%x)",copt->mode);
		switch (copt->mode & TC_PSP_MAJ_MODE_MASK) {
		case TC_PSP_MODE_NORMAL:
			fprintf(f, "mode NORMAL%s ", m1);
			break;
		case TC_PSP_MODE_STATIC:
			fprintf(f, "mode STATIC%s (%s) ", m1,
				sprint_rate(copt->rate, b));
			break;
		case TC_PSP_MODE_STATIC_RATE:
			fprintf(f, "mode STATIC_RATE%s (%s) ", m1,
				sprint_rate(copt->rate, b));
			break;
		default:
			fprintf(f, "mode 0x%x (%s) ", copt->mode,
				sprint_rate(copt->rate, b));
			break;	
		}
	}
	if (tb[TCA_PSP_QOPT]) {
		qopt = RTA_DATA(tb[TCA_PSP_QOPT]);
		if (RTA_PAYLOAD(tb[TCA_PSP_QOPT])  < sizeof(*qopt))
			return -1;
		fprintf(f, "default %x direct pkts %u max rate %s ifg %u", 
			qopt->defcls, qopt->direct_pkts,
			sprint_rate(qopt->rate, b), qopt->ifg);
	}
	return 0;
}

static int psp_print_xstats(struct qdisc_util *qu, FILE *f,
			    struct rtattr *xstats)
{
	struct tc_psp_xstats *st;

	if (xstats == NULL)
		return 0;

	if (RTA_PAYLOAD(xstats) < sizeof(*st))
		return -1;

	st = RTA_DATA(xstats);
	fprintf(f, "  gap %u bytes %u pkts", st->bytes, st->packets);
	return 0;
}

static int psp_parse_class_opt(struct qdisc_util *qu, int argc, char **argv,
			       struct nlmsghdr *n)
{
	struct tc_psp_copt copt;
	struct rtattr *tail;
	char d[16];

	memset(&copt, 0, sizeof(copt));
	copt.chk = sizeof(copt);
	copt.mode = TC_PSP_MODE_STATIC; /* default mode */
	memset(&d, 0, sizeof(d));

	while (argc > 0) {
		if (matches(*argv, "rate") == 0) {
			NEXT_ARG();
			if (matches(*argv, "auto") == 0)
				copt.rate=1;
			else if (GET_RATE(&copt.rate, *argv)) {
				explain1("rate");
				return -1;
			}
		} else if (matches(*argv, "mode") == 0) {
			NEXT_ARG();
			if (get_u32(&copt.mode, *argv, 16)) {
				explain1("mode");
				return -1;
			}
		} else if (matches(*argv, "hw") == 0) {
			NEXT_ARG();
			if (get_u32(&copt.hw_gap, *argv, 10)) {
				explain1("hw");
				return -1;
			}
		} else if (matches(*argv, "mtu") == 0) {
			NEXT_ARG();
			if (get_u32(&copt.mtu, *argv, 10)) {
				explain1("mtu");
				return -1;
			}
		} else if (matches(*argv, "back") == 0) {
			NEXT_ARG();
			strncpy(d, *argv, sizeof(d)-1);
			if ((copt.back_dev = ll_name_to_index(d)) == 0) {
			    fprintf(stderr, "Cannot find device \"%s\"\n", d);
			    return 1;
			}
			NEXT_ARG();
			if (get_tc_classid(&copt.back_id, *argv))
			    invarg(*argv, "invalid class ID");
		} else if (matches(*argv, "rrr") == 0) {
			NEXT_ARG();
			if (get_u32(&copt.rrr, *argv, 16)) {
				explain1("rrr");
				return -1;
			}
		} else if (matches(*argv, "weight") == 0) {
			NEXT_ARG();
			if (get_u32(&copt.weight, *argv, 16)) {
				explain1("weight");
				return -1;
			}
		} else if (matches(*argv, "ewma") == 0) {
			NEXT_ARG();
			if (get_u32(&copt.ewma, *argv, 16)) {
				explain1("ewma");
				return -1;
			}
		} else if (matches(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		argc--; argv++;
	}

	if (copt.rate) {
	    if ((copt.mode&TC_PSP_MAJ_MODE_MASK) == TC_PSP_MODE_NORMAL) {
		fprintf(stderr, "You can not set to \"rate\" parameter "
			"in normal mode\n");
		explain1("rate");
		return -1;
	    }
	} else if ((copt.mode&TC_PSP_MAJ_MODE_MASK) == TC_PSP_MODE_STATIC) {
	    
		fprintf(stderr, "You need set to \"rate\" parameter "
			"in static target rate mode.\n");
		explain1("rate");
		return -1;
	}

	tail = NLMSG_TAIL(n);
	addattr_l(n, 1024, TCA_OPTIONS, NULL, 0);
	addattr_l(n, 1024, TCA_PSP_COPT, &copt, sizeof(copt));
	tail->rta_len = (void *)NLMSG_TAIL(n) - (void *)tail;
	return 0;
}

struct qdisc_util psp_qdisc_util = {
	.id		= "psp",
	.parse_qopt	= psp_parse_opt,
	.print_qopt	= psp_print_opt,
	.print_xstats	= psp_print_xstats,
	.parse_copt	= psp_parse_class_opt,
	.print_copt	= psp_print_opt
};

/* XXXX: backward compatibility for the kernel 2.6.9 and below */
struct qdisc_util psp_util = {
	.id		= "psp",
	.parse_qopt	= psp_parse_opt,
	.print_qopt	= psp_print_opt,
	.print_xstats	= psp_print_xstats,
	.parse_copt	= psp_parse_class_opt,
	.print_copt	= psp_print_opt
};
