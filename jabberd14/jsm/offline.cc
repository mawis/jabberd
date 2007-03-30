/*
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2007 Matthias Wimmer
 *
 * This file is part of jabberd14.
 *
 * This software is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

#include "jsm.h"

/**
 * @file offline.cc
 * @brief handle packets addressed to existing but offline users
 */

/**
 * function that handles packets that are sent to a valid user account, that has no online session
 *
 * First try if one of the e_OFFLINE modules handles the packet, if not it is bounced as recipient-unavailable
 *
 * @param arg the jpq_struct for this packet (contains the session manager instance data and the packet)
 */
void js_offline_main(void *arg) {
    jpq q = (jpq)arg;
    udata user;

    /* performace hack, don't lookup the udata again */
    user = (udata)q->p->aux1;

    /* debug message */
    log_debug2(ZONE, LOGT_DELIVER, "THREAD:OFFLINE received %s's packet: %s", jid_full(user->id), xmlnode_serialize_string(q->p->x, xmppd::ns_decl_list(), 0));

    /* let the filters check the packet */
    if (q->p->flag == PACKET_PASS_FILTERS_MAGIC || !js_mapi_call(q->si, e_FILTER_IN, q->p, user, NULL)) {
	/* let the modules handle the packet */
	if(!js_mapi_call(q->si, e_OFFLINE, q->p, user, NULL)) {
	    js_bounce_xmpp(q->si, NULL, q->p->x, XTERROR_RECIPIENTUNAVAIL);
	}
    }

    /* it can be cleaned up now */
    user->ref--;
}
