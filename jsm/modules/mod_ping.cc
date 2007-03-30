/*
 * Copyrights
 * 
 * Copyright (c) 2006-2007 Matthias Wimmer
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
 * @file mod_ping.cc
 * @brief implements XEP-0199 - XMPP Ping
 *
 * This module allows the administrator to block some user-names from being registered
 * by users.
 */

/**
 * handle disco info query to the server address, add our feature
 */
static mreturn mod_ping_server_disco_info(mapi m) {
    xmlnode feature = NULL;

    /* only no node, only get */
    if (jpacket_subtype(m->packet) != JPACKET__GET)
	return M_PASS;
    if (xmlnode_get_attrib_ns(m->packet->iq, "node", NULL) != NULL)
	return M_PASS;

    /* build the result IQ */
    js_mapi_create_additional_iq_result(m, "query", NULL, NS_DISCO_INFO);
    if (m->additional_result == NULL || m->additional_result->iq == NULL)
	return M_PASS;

    /* add features */
    feature = xmlnode_insert_tag_ns(m->additional_result->iq, "feature", NULL, NS_DISCO_INFO);
    xmlnode_put_attrib_ns(feature, "var", NULL, NULL, NS_XMPP_PING);

    return M_PASS;
}

/**
 * handle pings
 */
static mreturn mod_ping_server_ping(mapi m) {
    /* only get */
    if (jpacket_subtype(m->packet) != JPACKET__GET)
	return M_PASS;

    /* build the result IQ */
    jutil_iqresult(m->packet->x);
    jpacket_reset(m->packet);
    js_deliver(m->si, m->packet, NULL);

    return M_HANDLED;
}

/**
 * handle iq queries addressed to the server
 *
 * all but iq stanzas are ignored, only relevant namespaces are handled
 *
 * redirects processing to the right handler for the namespace
 *
 * @param m the mapi structure
 * @param arg time_t timestampe when the server was started
 * @return M_IGNORE if the stanza is no iq, M_PASS or M_HANDLED else
 */
static mreturn mod_ping_server(mapi m, void *arg) {
    /* sanity check */
    if (m == NULL || m->packet == NULL)
	return M_PASS;

    /* only handle iqs */
    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;

    if (NSCHECK(m->packet->iq, NS_DISCO_INFO))
	return mod_ping_server_disco_info(m);

    if (NSCHECK(m->packet->iq, NS_XMPP_PING))
	return mod_ping_server_ping(m);

    return M_PASS;
}

/**
 * handle stream-level pings sent by a client
 *
 * @param m the mapi_struct containing the request
 * @param arg unused/ignored
 * @return M_IGNORE if no iq request, M_PASS if no ping, M_HANDLED if ping
 */
static mreturn mod_ping_out(mapi m, void *arg) {
    if (m == NULL || m->packet == NULL)
	return M_PASS;

    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;

    if (m->packet->to != NULL) {
	return M_PASS;
    }
    if (!NSCHECK(m->packet->iq, NS_XMPP_PING)) {
	return M_PASS;
    }
    if (jpacket_subtype(m->packet) != JPACKET__GET) {
	return M_PASS;
    }

    jutil_iqresult(m->packet->x);
    jpacket_reset(m->packet);
    js_deliver(m->si, m->packet, m->s);

    return M_HANDLED;
}

/**
 * new session started, register es_OUT handler
 *
 * @param m the mapi_struct containing the new session
 * @param arg unused/ignored
 * @return always M_PASS
 */
static mreturn mod_ping_session(mapi m, void *arg) {
    js_mapi_session(es_OUT, m->s, mod_ping_out, NULL);
    return M_PASS;
}

static mreturn mod_ping_deliver(mapi m, void *arg) {
    if (m == NULL || m->packet == NULL)
	return M_PASS;

    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;

    if (!NSCHECK(m->packet->iq, NS_XMPP_PING)) {
	return M_PASS;
    }
    if (jpacket_subtype(m->packet) != JPACKET__GET) {
	return M_PASS;
    }

    jutil_iqresult(m->packet->x);
    jpacket_reset(m->packet);
    js_deliver(m->si, m->packet, m->s);

    return M_HANDLED;
}

/**
 * init the module, register callbacks
 *
 * @param si the session manager instance
 */
extern "C" void mod_ping(jsmi si) {
    js_mapi_register(si, e_SERVER, mod_ping_server, NULL);
    js_mapi_register(si, e_SESSION, mod_ping_session, NULL);
    js_mapi_register(si, e_DESERIALIZE, mod_ping_session, NULL);
    js_mapi_register(si, e_DELIVER, mod_ping_deliver, NULL);
}
