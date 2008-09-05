/*
 * pspd.h		PSPacer control deamon
 *
 * Copyright (C) 2004-2007 National Institute of Advanced Industrial
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
#ifndef __PSPD_H
#define __PSPD_H

#define PSPD_SOCK_NAME  "/tmp/pspd"
#define PSPD_CONF_FILE "/etc/pspd.conf"

/* Command code. */

enum {
	PSP_CMD_INIT = 0,
	PSP_CMD_GET_QOPT,
	PSP_CMD_SET_QOPT,
	PSP_CMD_GET_COPT,
	PSP_CMD_SET_COPT
};

/* Error code. */

enum {
	PSP_SUCCESS = 0,
	PSP_ERR_VERSION = -1,
	PSP_ERR_PARAM = -2,
	PSP_ERR_MATCH = -3
};


/* Message format:
 * The structure keeps consistency with a client side library (i.e. libpsp.h).
 */
#define LIBPSP_VERSION (0x00010000) /* version 1.0 */

struct psp_msg {
	uint8_t cmd;
	uint8_t err;
	uint16_t ifindex;
	uint32_t handle;	/* (classid) */

	union {
		struct {
			uint32_t ver;
			char dev[16];
			char cid[16];
		} init;
		struct {
			uint32_t rate;
		} qopt;
		struct {
			uint32_t mode;
			uint32_t rate;
			uint32_t nconns;/* number of nodes which shared a link.
					 * It is used for sweeping backlog. */
		} copt;
	} u;
};


/* 
 * pspd nformation block.
 * NOTE: The indexes of both .qdisc_cache and .class_cache is {ifindex-1}.
 */
#define IFNUM (32) /* The number of interfaces */

struct pspd_info {
	struct nl_handle *nl;
	struct nl_cache *link_cache;
	uint32_t handle[IFNUM];
	struct rtnl_qdisc *qdisc;
	struct rtnl_qdisc *qdisc_filter;
	struct nl_cache *qdisc_cache[IFNUM];
	struct rtnl_class *class;
	struct rtnl_class *class_filter;
	struct nl_cache *class_cache[IFNUM];
};

/* Parameter for callback functions. */

struct pspd_cb_param {
	int cmd;
	int err;
	struct tc_psp_qopt qopt;
	struct tc_psp_copt copt;
};

#endif /* __PSPD_H */
