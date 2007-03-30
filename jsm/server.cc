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
 * @file server.cc
 * @brief handle packets intended for the server: administration, public IQ (agents, etc)
 */

/**
 * handle a packet addressed to the server itself (no node part in the JID)
 *
 * Pass the packet to the modules, that registered for the e_SERVER event. If none
 * of the modules handled the packet, it is bounced as "not-found".
 *
 * @param arg jpq structure containing the session manager instance data and the packet
 */
void js_server_main(void *arg) {
    int incremented=0;
    jpq q = (jpq)arg;
    udata u = NULL;

    log_debug2(ZONE, LOGT_DELIVER, "THREAD:SERVER received a packet: %s", xmlnode_serialize_string(q->p->x, xmppd::ns_decl_list(), 0));

    /* get the user struct for convience if the sender was local */
    if (js_islocal(q->si, q->p->from))
        u = js_user(q->si, q->p->from, NULL);

    /* don't free the udata while the mapi call is processed */
    if (u != NULL) {
	u->ref++;
	incremented++;
    }

    /* let the modules have a go at the packet; if nobody handles it... */
    if(!js_mapi_call(q->si, e_SERVER, q->p, u, NULL))
        js_bounce_xmpp(q->si, NULL, q->p->x, XTERROR_NOTFOUND);

    /* free our lock */
    if (incremented != 0) {
	u->ref--;
    }
}
