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

#include <namespaces.hh>

/**
 * @file mod_example.cc
 * @brief example how to implement your own Jabber session manager (jsm) module
 *
 * This module will reply to messages sent to the resource "example" of the
 * server address by sending a message back with the body "this is the
 * mod_example_server reply".
 */

/*
 * Welcome!
 *
 * So... you want to play with the innards of jsm, huh?  Cool, this should be
 * fun, and it isn't too hard either :)
 *
 * The API that you're going to be working with is starting to show it's age, it
 * was created back in the era of 0.9, in early 2000. It's still quite
 * functional and usable, but not as clean as a purist geek might like.  Don't
 * hesistate to code against it though, it's not going anywhere until the 2.0
 * release (probably 02), and even then we'll make sure it remains as compatible
 * as possible (if not fully).
 *
 * A very general overview:
 *  -> packets come into jsm
 *  -> jsm tracks "sessions", or logged in users
 *  -> jsm determins the right session, and the packet is delivered to that
 * session
 *  -> packets can either be of the type the user generated and is sending (OUT)
 * or receiving from others (IN)
 *  -> modules are called to process the packets
 *
 * Modules can also hook in when a session starts, ends, and when packets are
 * just send to="server" or when the user is offline. Most of the module api
 * symbols, defines, etc are defined in the jsm.h file, consult it frequently.
 *
 * To get your module build, you have to add it to libjabberdsmmods_la_SOURCES
 * in Makefile.am and regenerate the Makefile from this automake template. I
 * suggest you get a repository snapshot in this case, that will contain the
 * bootstrap script in the main directory that will regenerate all automatically
 * created files. Also you have to include the module in your server
 * configuration, just like the other modules.
 *
 * You can often follow the logic bottom-up, the first function that registers
 * the module is at the bottom, and subsequent callbacks are above it. So, head
 * to the bottom of this file to get started!
 */

/**
 * check for packets that are sent to="servername/example" and reply
 *
 * @param the mapi_struct containing the request
 * @param arg unused/ignored
 * @return M_IGNORE if the request was not message stanza, M_HANDLED if it has
 * been handel and M_PASS else.
 */
static mreturn mod_example_server(mapi m, void *arg) {
    xmlnode body;

    /* we only handle messages, ignore the rest */
    if (m->packet->type != JPACKET_MESSAGE)
        return M_IGNORE;

    /* second, is this message sent to the right resource? */
    if (!m->packet->to->has_resource() ||
        m->packet->to->get_resource() == "example")
        return M_PASS;

    log_debug2(ZONE, LOGT_DELIVER, "handling example request from %s",
               jid_full(m->packet->from));

    /* switch the to/from headers, using a utility */
    jutil_tofrom(m->packet->x);

    /* hide the old body */
    xmlnode_hide(xmlnode_get_list_item(
        xmlnode_get_tags(m->packet->x, "body", m->si->std_namespace_prefixes),
        0));

    /* insert our own and fill it up */
    body = xmlnode_insert_tag_ns(m->packet->x, "body", NULL, NS_SERVER);
    xmlnode_insert_cdata(body, "this is the mod_example_server reply", -1);

    /* reset the packet and deliver it again */
    jpacket_reset(m->packet);
    js_deliver(m->si, m->packet, m->s);

    /* we handled the packet */
    return M_HANDLED;
}

/**
 * the main startup/initialization function
 *
 * In here we register our callbacks with the "events" we are interested in.
 * Each callback can register an argument (we're passing NULL) that is passed to
 * them again when called. Before looking at specific callbacks above, take the
 * change now to look at the mod_example_generic one above that explains what
 * they all have in common.
 *
 * The argument registered with the callback (NULL here) is often used for
 * passing configuration data, that has been processed here once at the
 * initialisation of the module.
 *
 * @param si jsmi_struct containing instance internal data of the jabber session
 * manager
 */
extern "C" void mod_example(jsmi si) {
    /* this event is when packets are sent to the server address,
     * to="example.com", often used for administrative purposes or special
     * server/resources */
    js_mapi_register(si, e_SERVER, mod_example_server, NULL);
}
