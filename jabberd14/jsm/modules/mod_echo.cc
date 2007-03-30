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
 * @file mod_echo.cc
 * @brief reflect messages sent to serverdomain/echo back to the sender (undocumented)
 *
 * This module implements some functionality useful for testing if a server can be reached. It can
 * either be used to check if the local server is still responding or to check if there
 * is connectivity to a remote server. It is something like a Jabber network ping, but it should
 * not be used automatically as it will generate more load on the servers than an ICMP ping.
 *
 * All messages to a resource starting with "echo" are processed. If you are using this service,
 * please use always the resource "echo" (in small letters) and do not rely on the fact
 * that every resource starting with "echo" (ignoring case) will generate a reflected message.
 * (Resources are case-sensitive in XMPP!)
 */

/**
 * handle messages sent to the session manager's address
 *
 * Everything but message stanzas are ignored. Only messages to a resource starting with "echo" are
 * processed.
 *
 * @param m the mapi structure containing the message
 * @param arg unused/ignored
 * @return M_IGNORE if the stanza is no message, M_PASS if the message has not been processed, M_HANDLED if the message has been handled
 */
static mreturn mod_echo_reply(mapi m, void *arg) {
    if (m->packet->type != JPACKET_MESSAGE)
	return M_IGNORE;

    /* first, is this a valid request? */
    if (m->packet->to->resource == NULL || strncasecmp(m->packet->to->resource, "echo", 4) != 0)
	return M_PASS;

    log_debug2(ZONE, LOGT_DELIVER, "handling echo request from %s", jid_full(m->packet->from));

    xmlnode_put_attrib_ns(m->packet->x, "from", NULL, NULL, jid_full(m->packet->to));
    xmlnode_put_attrib_ns(m->packet->x, "to", NULL, NULL, jid_full(m->packet->from));
    jpacket_reset(m->packet);
    js_deliver(m->si, m->packet, NULL);

    return M_HANDLED;
}

/**
 * init the mod_echo module in the session manager
 *
 * registers a callback to be called on messages sent to the session manager's address
 *
 * @param si the session manager instance
 */
extern "C" void mod_echo(jsmi si) {
    js_mapi_register(si, e_SERVER, mod_echo_reply, NULL);
}
