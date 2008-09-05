/*
 * pspd.c		PSPacer control deamon
 *
 * Copyright (C) 2004-2008 National Institute of Advanced Industrial
 * Science and Technology (AIST), Japan.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Authors:	TAKANO Ryousei, <takano-ryousei@aist.go.jp>
 */

/* MEMO: Defines _GNU_SOURCE for using libnl. */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <assert.h>

#include <netlink-local.h>
#include <netlink/netlink.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/class.h>
#include <linux/pkt_sched.h>
#include <netlink/route/sch/psp.h>
#include "pspd.h"

#ifdef DEBUG
#define ASSERT(X) assert(X)
#else
#define ASSERT(X) ((void)0)
#endif
#define NEVERHERE (0)

static struct pspd_info info;
static int backlog_sweeping_mode = 1;
static int verbose;

static int pspd_init(void);
static int pspd_finalize(void);
static int pspd_exec_command(struct psp_msg *msg);
static void pspd_setup_interface(struct nl_object *obj, void *arg);
static void pspd_clean_interface(struct nl_object *obj, void *arg);
static void pspd_setup_qdisc(struct nl_object *obj, void *arg);
static void pspd_get_qdisc_opt(struct nl_object *obj, void *arg);
static void pspd_set_qdisc_opt(struct nl_object *obj, void *arg);
static void pspd_get_class_opt(struct nl_object *obj, void *arg);
static void pspd_set_class_opt(struct nl_object *obj, void *arg);


static void 
usage()
{
	printf("pspd [options]\n\n"
	       "OPTIONS:\n"
	       "-d\n"
	       "        forks myself and let the child process be"
	       " a background proecss.\n"
	       "-v\n"
	       "        prints verbose messages to the stderr.\n"
	       "-h\n"
	       "        prints this message.\n"
		);
}

static int
pspd_init(void)
{
	int nl_cbset = NL_CB_VERBOSE;
	char *nlcb = getenv("NLCB");
	char *nldbg = getenv("NLDBG");
	int cc;

	if (nlcb) {
		if (!strcasecmp(nlcb, "default"))
			nl_cbset = NL_CB_DEFAULT;
		else if (!strcasecmp(nlcb, "verbose"))
			nl_cbset = NL_CB_VERBOSE;
		else if (!strcasecmp(nlcb, "debug"))
			nl_cbset = NL_CB_DEBUG;
		else {
			fprintf(stderr, "Unknown value for NLCB, valid values:"
				" {default | verbose | debug}\n");
			goto errout;
		}
	}

	if (nldbg) {
		long dbg = strtol(nldbg, NULL, 0);

		if (dbg == LONG_MIN || dbg == LONG_MAX) {
			fprintf(stderr, "Invalid value for NLDBG.\n");
			goto errout;
		}

		nl_debug = dbg;
	}

	info.nl = nl_handle_alloc_nondefault(nl_cbset);
	assert(info.nl != NULL);

	cc = nl_connect(info.nl, NETLINK_ROUTE);
	if (cc < 0)
		goto errout_destroy;

	info.link_cache = rtnl_link_alloc_cache(info.nl);
	if (info.link_cache == NULL)
		goto errout_close;

	/* Setups iterator filters. */
	info.qdisc_filter = rtnl_qdisc_alloc();
	assert(info.qdisc_filter != NULL);
	rtnl_qdisc_set_kind(info.qdisc_filter, "psp");

	info.class_filter = rtnl_class_alloc();
	assert(info.class_filter != NULL);
	rtnl_class_set_kind(info.class_filter, "psp");

	nl_cache_foreach(info.link_cache, &pspd_setup_interface, NULL);

	return 0;

errout_close:
	nl_close(info.nl);
errout_destroy:
	nl_handle_destroy(info.nl);
errout:
	return -1;
}

static int
pspd_finalize(void)
{
	nl_cache_foreach(info.link_cache, pspd_clean_interface, NULL);
	nl_cache_free(info.link_cache);
	rtnl_class_put(info.class);
	rtnl_class_put(info.class_filter);
	rtnl_qdisc_put(info.qdisc);
	rtnl_qdisc_put(info.qdisc_filter);
	nl_close(info.nl);
	nl_handle_destroy(info.nl);
	return 0;
}

static int
pspd_exec_command(struct psp_msg *msg)
{
	struct pspd_cb_param param;
	int ifindex, classid;
	uint32_t backlog;
	int cc;

	ASSERT(msg != NULL);

	param.err = PSP_ERR_MATCH;
	param.cmd = msg->cmd;

	switch (msg->cmd) {
	case PSP_CMD_INIT:
		if (msg->u.init.ver != LIBPSP_VERSION) { /* version check */
			param.err = PSP_ERR_VERSION;
			break;
		}

		cc = rtnl_link_name2i(info.link_cache, msg->u.init.dev);
		if (cc == RTNL_LINK_NOT_FOUND) {
			param.err = PSP_ERR_PARAM;
			break;
		}
		msg->ifindex = cc;

		cc = rtnl_tc_str2handle(msg->u.init.cid, &msg->handle);
		if (cc != 0) {
			param.err = PSP_ERR_PARAM;
			break;
		}
		param.err = PSP_SUCCESS;
		break;

	case PSP_CMD_GET_QOPT:
		ifindex = msg->ifindex;
		rtnl_qdisc_set_ifindex(info.qdisc_filter, ifindex);
		nl_cache_foreach_filter(info.qdisc_cache[ifindex-1],
					(struct nl_object *)info.qdisc_filter,
					&pspd_get_qdisc_opt, &param);
		msg->u.qopt.rate = param.qopt.rate;
		break;

	case PSP_CMD_SET_QOPT:
		ifindex = msg->ifindex;
		rtnl_qdisc_set_ifindex(info.qdisc_filter, ifindex);
		param.qopt.rate = msg->u.qopt.rate;
		nl_cache_foreach_filter(info.qdisc_cache[ifindex-1],
					(struct nl_object *)info.qdisc_filter,
					&pspd_set_qdisc_opt, &param);
		break;

	case PSP_CMD_GET_COPT:
		ifindex = msg->ifindex;
		classid = msg->handle;

		rtnl_class_set_ifindex(info.class_filter, ifindex);
		rtnl_class_set_handle(info.class_filter, classid);
		nl_cache_foreach_filter(info.class_cache[ifindex-1],
					(struct nl_object *)info.class_filter,
					&pspd_get_class_opt, &param);
		msg->u.copt.mode = param.copt.mode;
		msg->u.copt.rate = param.copt.rate;
		break;

	case PSP_CMD_SET_COPT:
		ifindex = msg->ifindex;
		classid = msg->handle;

		ASSERT(info.handle[ifindex-1] != 0);
		info.qdisc = rtnl_qdisc_get(info.qdisc_cache[ifindex-1],
					    ifindex, info.handle[ifindex-1]);

		/*
		 * Wait a minute until sweeping backlog.
		 * It assumes GbE trasfer rate (i.e. 12 usec / packet).
		 */
		do {
			nl_cache_update(info.nl, info.qdisc_cache[ifindex-1]);
			backlog = rtnl_qdisc_get_stat(info.qdisc, 
						      RTNL_TC_QLEN);
			usleep(12 * msg->u.copt.nconns * backlog);

			if (backlog_sweeping_mode == 1)
				break;
		} while (backlog != 0);

		rtnl_class_set_ifindex(info.class_filter, ifindex);
		rtnl_class_set_handle(info.class_filter, classid);
		param.copt.mode = msg->u.copt.mode;
		param.copt.rate = msg->u.copt.rate;
		nl_cache_foreach_filter(info.class_cache[ifindex-1],
					(struct nl_object *)info.class_filter,
					&pspd_set_class_opt, &param);
		break;
	}

	return param.err;
}

/*
 * libnl callback functions
 */

static void
pspd_setup_interface(struct nl_object *obj, void *arg)
{
	struct rtnl_link *link = (struct rtnl_link *) obj;
	int ifindex;

	ifindex = rtnl_link_get_ifindex(link);
	ASSERT(ifindex != RTNL_LINK_NOT_FOUND);
	assert(ifindex < IFNUM);

	info.qdisc_cache[ifindex-1] = rtnl_qdisc_alloc_cache(info.nl);
	assert(info.qdisc_cache[ifindex-1] != NULL);

	info.class_cache[ifindex-1] = rtnl_class_alloc_cache(info.nl, ifindex);
	assert(info.class_cache[ifindex-1] != NULL);

	rtnl_qdisc_set_ifindex(info.qdisc_filter, ifindex);
	nl_cache_foreach_filter(info.qdisc_cache[ifindex-1],
				(struct nl_object *)info.qdisc_filter,
				&pspd_setup_qdisc, NULL);
}

static void
pspd_clean_interface(struct nl_object *obj, void *arg)
{
	struct rtnl_link *link = (struct rtnl_link *) obj;
	int ifindex;

	ifindex = rtnl_link_get_ifindex(link);
	ASSERT(ifindex != RTNL_LINK_NOT_FOUND);
	assert(ifindex < IFNUM);

	nl_cache_free(info.class_cache[ifindex-1]);
	nl_cache_free(info.qdisc_cache[ifindex-1]);
}

static void
pspd_setup_qdisc(struct nl_object *obj, void *arg)
{
	struct rtnl_qdisc *qdisc = (struct rtnl_qdisc *) obj;
	int ifindex;

	ASSERT(qdisc != NULL);
	ASSERT(strncmp(qdisc->q_kind, "psp", 3) == 0);

	ifindex = rtnl_qdisc_get_ifindex(qdisc);
	ASSERT(ifindex != RTNL_LINK_NOT_FOUND);
	assert(ifindex < IFNUM);

	if (info.handle[ifindex-1] != 0) {
		fprintf(stderr,
			"Cannot support multiple qdiscs per an interface.\n");
		assert(NEVERHERE);
	}
	info.handle[ifindex-1] = rtnl_qdisc_get_handle(qdisc);
}

static void
pspd_get_qdisc_opt(struct nl_object *obj, void *arg)
{
	struct rtnl_qdisc *qdisc = (struct rtnl_qdisc *) obj;
	struct pspd_cb_param *param = (struct pspd_cb_param *) arg;

	ASSERT(qdisc != NULL);
	ASSERT(strncmp(qdisc->q_kind, "psp", 3) == 0);
	ASSERT(param != NULL);

	param->qopt.defcls = rtnl_psp_get_defcls(qdisc);
	param->qopt.rate = rtnl_psp_get_totalrate(qdisc);
	param->err = PSP_SUCCESS;
}

static void
pspd_set_qdisc_opt(struct nl_object *obj, void *arg)
{
	struct rtnl_qdisc *qdisc = (struct rtnl_qdisc *) obj;
	struct pspd_cb_param *param = (struct pspd_cb_param *) arg;
	int cc;

	ASSERT(qdisc != NULL);
	ASSERT(strncmp(qdisc->q_kind, "psp", 3) == 0);
	ASSERT(param != NULL);

	cc = rtnl_psp_set_defcls(qdisc, param->qopt.defcls);
	if (cc < 0) {
		fprintf(stderr, "%s\n", nl_geterror());
		param->err = PSP_ERR_PARAM;
		return;
	}
	cc = rtnl_psp_set_totalrate(qdisc, param->qopt.rate);
	if (cc < 0) {
		fprintf(stderr, "%s\n", nl_geterror());
		param->err = PSP_ERR_PARAM;
		return;
	}
	param->err = PSP_SUCCESS;
}

static void
pspd_get_class_opt(struct nl_object *obj, void *arg)
{
	struct rtnl_class *class = (struct rtnl_class *) obj;
	struct pspd_cb_param *param = (struct pspd_cb_param *) arg;

	ASSERT(class != NULL);
	ASSERT(strncmp(class->c_kind, "psp", 3) == 0);
	ASSERT(param != NULL);

	param->copt.mode = rtnl_psp_get_mode(class);
	if (param->copt.mode != TC_PSP_MODE_NORMAL) {
		param->copt.rate = rtnl_psp_get_rate(class);
	} else {
		param->copt.rate = 0;
	}
	param->err = PSP_SUCCESS;
}

static void
pspd_set_class_opt(struct nl_object *obj, void *arg)
{
	struct rtnl_class *class = (struct rtnl_class *) obj;
	struct pspd_cb_param *param = (struct pspd_cb_param *) arg;
	int cc;

	ASSERT(class != NULL);
	ASSERT(strncmp(class->c_kind, "psp", 3) == 0);
	ASSERT(param != NULL);

	if (verbose) {
		fprintf(stderr,
			"pspd_set_class_opt handle=%x mode=%d rate=%d\n",
			class->c_handle, param->copt.mode, param->copt.rate);
	}

	cc = rtnl_psp_set_mode(class, param->copt.mode);
	if (cc < 0) {
		fprintf(stderr, "%s\n", nl_geterror());
		param->err = PSP_ERR_PARAM;
		return;
	}
	if (param->copt.mode != TC_PSP_MODE_NORMAL) {
		cc = rtnl_psp_set_rate(class, param->copt.rate);
		if (cc < 0) {
			fprintf(stderr, "%s\n", nl_geterror());
			param->err = PSP_ERR_PARAM;
			return;
		}
	}

	cc = rtnl_class_add(info.nl, class, NLM_F_REPLACE);
	if (cc < 0) {
		fprintf(stderr, "Unable to change class: %s\n", nl_geterror());
		param->err = PSP_ERR_PARAM;
		return;
	}

	param->err = PSP_SUCCESS;
}

/*
 * Utility functions
 */

int
daemon(int not_chdir, int not_close)
{
	switch (fork()) {
	case -1:
		return (-1);
	case 0:
		break;
	default:
		exit(0);
	}
	setsid();
	if (!not_chdir)
		chdir("/");
	if (!not_close) {
		int fd = open("/dev/null", O_RDWR, 0);
		if (fd != -1) {
			dup2(fd, 0);
			dup2(fd, 1);
			dup2(fd, 2);
			if (fd > 2)
				close(fd);
		}
	}
	return (0);
}

static int
pspd_prepare_passive_open(void)
{
	int sock;
	struct sockaddr_un sa;
	socklen_t sun_len;
	int cc;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "Failure socket: %s\n", strerror(errno));
		exit(1);
	}

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, PSPD_SOCK_NAME, strlen(PSPD_SOCK_NAME));
	sun_len = (offsetof(struct sockaddr_un, sun_path)
		   + strlen(PSPD_SOCK_NAME));
#ifdef HAVE_SUN_LEN
	sa.sun_len = sun_len;
#endif

	unlink(sa.sun_path);
	cc = bind(sock, (struct sockaddr *)&sa, sun_len);
	if (cc < 0){
		fprintf(stderr, "Failure bind: %s\n", strerror(errno));
		exit(1);
	}
	chmod(sa.sun_path, 0777); /* Allows other to access it. */

	cc = listen(sock, 10);
	if (cc < 0) {
		fprintf(stderr, "Failure listen: %s\n", strerror(errno));
		unlink(sa.sun_path);
		exit(1);
	}

	return sock;
}

static int
pspd_passive_open(int fd)
{
	int sock;
	socklen_t addrlen;
	struct sockaddr_un saddr_un;

	addrlen = sizeof(struct sockaddr_un);
	sock = accept(fd, (struct sockaddr *)&saddr_un, &addrlen);
	if (sock < 0) {
		fprintf(stderr, "Failure accept: %s\n", strerror(errno));
		exit(1);
	}
	return sock;
}

static int
pspd_recv_msg(int fd, struct psp_msg *msg)
{
	int cc, count = 0;

	while (count != sizeof(struct psp_msg)) {
		cc = read(fd, msg, sizeof(struct psp_msg));
		if (cc == -1) {
			fprintf(stderr, "Failure read: %s\n", strerror(errno));
			exit(1);
		} else if (cc == 0) { /* close connection */
			return 1;
		}
		count += cc;
	}
	return 0;
}

static int
pspd_send_msg(int fd, struct psp_msg *msg)
{
	int cc, count = 0;

	while (count != sizeof(struct psp_msg)) {
		cc = write(fd, msg, sizeof(struct psp_msg));
		if (cc == -1) {
			fprintf(stderr, "Failure write: %s\n", 
				strerror(errno));
			exit(1);
		}
		count += cc;
	}
	return 0;
}

static void 
catch_signal(int signum)
{
	switch (signum) {
	case SIGTERM:
	case SIGINT:
		pspd_finalize();
		unlink(PSPD_SOCK_NAME);
		break;
	}
	exit(1);
}

int
main(int argc, char **argv)
{
	struct sigaction sa;
	struct psp_msg msg;
	char ch;
	int fd1, fd2;
	int cc;
	int maxfd = 0;
	fd_set xrfds;
	char *s;
	int v;

	signal(SIGPIPE, SIG_IGN);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = catch_signal;
	sa.sa_flags = SA_NOCLDSTOP;
#ifdef SA_RESTART
	sa.sa_flags |= SA_RESTART;
#endif
	cc = sigaction(SIGINT, &sa, NULL);
	ASSERT(cc == 0);
	cc = sigaction(SIGTERM, &sa, NULL);
	ASSERT(cc == 0);


	while ((ch = getopt(argc, argv, "i:dchv")) != -1) {
		switch(ch) {
		case 'd': /* daemonize */
			daemon(0, 0);
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
			usage();
			exit(0);
		default:
			break;
		}
	}

	s = getenv("PSPD_SWEEP_BACKLOG");
	if (s != 0) {
		cc = sscanf(s, "%u%c", &v, (char *)&ch);
		if (cc != 1 || !(v ==0 || v == 1)) {
			fprintf(stderr, "PSPD_SWEEP_BACKLOG value is illegal"
				" (%d).  Use default.\n", v);
			backlog_sweeping_mode = 0;
		}
		backlog_sweeping_mode = v;
	}
	if (verbose) {
	    fprintf(stderr, "backlog sweeping mode=%d\n",
		    backlog_sweeping_mode);
	}

	cc = pspd_init();
	if (cc != 0)
		return 1;

	maxfd = fd1 = pspd_prepare_passive_open();
	FD_ZERO(&xrfds);
	FD_SET(fd1, &xrfds);

	/* main loop */
	while (1) {
		int fd, n, err;
		fd_set rfds;

		memcpy(&rfds, &xrfds, sizeof(fd_set));
		n = select(maxfd + 1, &rfds, NULL, NULL, NULL);
		if (n < 0) {
			fprintf(stderr, "Failure select: %s\n",
				strerror(errno));
			break;
		}

		if (FD_ISSET(fd1, &rfds)) {
			fd2 = pspd_passive_open(fd1);
			if (fd2 > maxfd)
				maxfd = fd2;
			FD_SET(fd2, &xrfds);
			continue;
		}

		/* recv-exec-send message */
		for (fd = maxfd; fd >= 3; fd--) {
			if (!FD_ISSET(fd, &rfds)) continue;

			if (pspd_recv_msg(fd, &msg) != 0) {
				/* close connection */
				FD_CLR(fd, &xrfds);
				break;
			}

			err = pspd_exec_command(&msg);
			msg.err = err;
			pspd_send_msg(fd, &msg);
		}
	}

	pspd_finalize();
	return 0;
}

