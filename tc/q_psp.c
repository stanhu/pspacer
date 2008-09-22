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
"Usage: ... qdisc add ... psp [ default N ] [rate RATE]\n"
" default  minor id of class to which unclassified packets are sent {0}\n"
" rate     physical interface bandwidth\n"
" ifg      inter frame gap size\n\n"
"... class add ... psp mode M [ rate MBPS ]\n"
" mode     target rate estimation method (NORMAL=0 STATIC=1 DYNAMIC=2) {0}\n"
" rate     rate allocated to this class\n");
}

static void explain1(char *arg)
{
	fprintf(stderr, "Illegal \"%s\"\n", arg);
	explain();
}


static int psp_parse_opt(struct qdisc_util *qu, int argc, char **argv,
			 struct nlmsghdr *n)
{
	struct tc_psp_qopt qopt;
	struct rtattr *tail;

	memset(&qopt, 0, sizeof(qopt));
	qopt.ifg = 12;

	while (argc > 0) {
		if (matches(*argv, "rate") == 0) {
			NEXT_ARG();
			if (GET_RATE(&qopt.rate, *argv)) {
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
		switch (copt->mode) {
		case TC_PSP_MODE_NORMAL:
			fprintf(f, "mode NORMAL ");
			break;
		case TC_PSP_MODE_STATIC:
			fprintf(f, "mode STATIC (%s) ", 
				sprint_rate(copt->rate, b));
			break;
		case TC_PSP_MODE_DYNAMIC:
			fprintf(f, "mode DYNAMIC (%s) ",
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

	memset(&copt, 0, sizeof(copt));
	copt.mode = TC_PSP_MODE_STATIC; /* default mode */

	while (argc > 0) {
		if (matches(*argv, "rate") == 0) {
			NEXT_ARG();
			if (GET_RATE(&copt.rate, *argv)) {
				explain1("rate");
				return -1;
			}
		} else if (matches(*argv, "mode") == 0) {
			NEXT_ARG();
			if (get_u32(&copt.mode, *argv, 16)) {
				explain1("mode");
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

	if (copt.mode == TC_PSP_MODE_NORMAL && copt.rate != 0) {
		fprintf(stderr, "You can not set to \"rate\" parameter "
			"in normal mode\n");
		explain1("rate");
		return -1;
	} else if (copt.mode == TC_PSP_MODE_STATIC && copt.rate == 0) {
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
