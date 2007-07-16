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
 * @file mod_last.cc
 * @brief Implement handling of jabber:iq:last (XEP-0012) in the session manager
 *
 * By sending a jabber:iq:last query of type get the server will either reply
 * with its own startup time (query sent to the session manager's address) or
 * with the time a user last went offline or the time of the user's registration
 * if it never was online (query sent to a user's address).
 *
 * jabber:iq:last queries are only processed if the querying entity has a
 * subscription to the queried user's presence.
 */

/**
 * handle iq queries addresses to the server
 *
 * all but iq stanzas are ignored, stanzas not of type get or not in the jabber:iq:last namespace are not processed
 *
 * return the time when the server was started
 *
 * @param m the mapi structure
 * @param arg time_t timestamp when the server was started
 * @return M_IGNORE if the stanza was no iq, M_PASS if the stanza has not been processed, M_HANDLED if the stanza has been handled
 */
static mreturn _mod_last_server_last(mapi m, time_t start) {
    time_t passed = time(NULL) - start;
    char str[11];
    xmlnode last;

    /* pre-requisites */
    if (jpacket_subtype(m->packet) != JPACKET__GET || m->packet->to->resource != NULL)
	return M_PASS;

    jutil_iqresult(m->packet->x);
    jpacket_reset(m->packet);

    last = xmlnode_insert_tag_ns(m->packet->x, "query", NULL, NS_LAST);
    snprintf(str, sizeof(str), "%d", (int)passed);
    xmlnode_put_attrib_ns(last, "seconds", NULL, NULL, str);

    js_deliver(m->si,m->packet, NULL);

    return M_HANDLED;
}

/**
 * handle disco info query to the server address, add our feature
 */
static mreturn _mod_last_server_disco_info(mapi m) {
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
    xmlnode_put_attrib_ns(feature, "var", NULL, NULL, NS_LAST);

    return M_PASS;
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
static mreturn mod_last_server(mapi m, void *arg) {
    time_t start = 0;

    /* sanity check */
    if (m == NULL || m->packet == NULL || arg == NULL)
	return M_PASS;

    start = *(time_t*)arg;

    /* only handle iqs */
    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;

    if (NSCHECK(m->packet->iq, NS_LAST))
	return _mod_last_server_last(m, start);
    if (NSCHECK(m->packet->iq, NS_DISCO_INFO))
	return _mod_last_server_disco_info(m);

    return M_PASS;
}

/**
 * function that updates the stored last information in xdb
 *
 * @param m the mapi structure
 * @param to which user should be updated
 * @param reason why the stored last information is updated
 */
static void mod_last_set(mapi m, jid to, const char *reason) {
    xmlnode last;
    char str[11];

    log_debug2(ZONE, LOGT_SESSION, "storing last for user %s",jid_full(to));

    /* make a generic last chunk and store it */
    last = xmlnode_new_tag_ns("query", NULL, NS_LAST);
    snprintf(str, sizeof(str), "%d", (int)time(NULL));
    xmlnode_put_attrib_ns(last, "last", NULL, NULL, str);
    xmlnode_insert_cdata(last, messages_get(m->packet ? xmlnode_get_lang(m->packet->x) : NULL, reason), -1);
    xdb_set(m->si->xc, jid_user(to), NS_LAST, last);
    xmlnode_free(last);
}

/**
 * callback that gets called on newly created accounts
 *
 * will initialize the stored last information with the account creation time
 *
 * @param m the mapi structure
 * @param arg unused/ignored
 * @return always M_PASS
 */
static mreturn mod_last_init(mapi m, void *arg) {
    if (jpacket_subtype(m->packet) != JPACKET__SET)
	return M_PASS;

    mod_last_set(m, m->packet->to, N_("Registered"));

    return M_PASS;
}

/**
 * callback that gets called on ending sessions
 *
 * update the stored information that contains the time of the ending of the last session
 *
 * @param m the mapi structure
 * @param arg unused/ignored
 * @return always M_PASS
 */
static mreturn mod_last_sess_end(mapi m, void *arg) {
    if(m->s->presence != NULL) /* presence is only set if there was presence sent, and we only track logins that were available */
        mod_last_set(m, m->user->id, xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(m->s->presence, "status", m->si->std_namespace_prefixes), 0)));

    return M_PASS;
}

/**
 * callback that gets called on new sessions
 *
 * register a callback to get notified if the session ends
 *
 * @param m the mapi structure
 * @param arg unused/ignored
 * @return always M_PASS
 */
static mreturn mod_last_sess(mapi m, void *arg) {
    js_mapi_session(es_END, m->s, mod_last_sess_end, NULL);

    return M_PASS;
}

/**
 * handle jabber:iq:last queries sent to a user's address
 *
 * everything but iq stanzas are ignored, everything but jabber:iq:last ist not processed.
 *
 * queries of type 'set' are rejected, queries of type 'get' are replied if the querying entity is subscribed to the user's presence,
 * other types are not processed.
 *
 * @param m the mapi structure
 * @param arg unused/ignored
 * @return M_IGNORE if it is no iq stanza, M_PASS if the stanza nas not been processed, M_HANDLED if the stanza has been handled
 */
static mreturn mod_last_reply(mapi m, void *arg) {
    xmlnode last;
    int lastt;
    char str[11];

    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;
    if (!NSCHECK(m->packet->iq,NS_LAST))
	return M_PASS;

    /* first, is this a valid request? */
    switch(jpacket_subtype(m->packet)) {
	case JPACKET__RESULT:
	case JPACKET__ERROR:
	    return M_PASS;
	case JPACKET__SET:
	    js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_NOTALLOWED);
	    return M_HANDLED;
    }

    /* make sure they're in the roster */
    if (!js_trust(m->user,m->packet->from)) {
        js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_FORBIDDEN);
        return M_HANDLED;
    }

    log_debug2(ZONE, LOGT_SESSION, "handling query for user %s", m->user->id->user);

    last = xdb_get(m->si->xc, m->user->id, NS_LAST);

    jutil_iqresult(m->packet->x);
    jpacket_reset(m->packet);
    lastt = j_atoi(xmlnode_get_attrib_ns(last,"last", NULL),0);
    if(lastt > 0) {
        xmlnode_hide_attrib_ns(last, "last", NULL);
        lastt = time(NULL) - lastt;
        snprintf(str, sizeof(str), "%d", lastt);
        xmlnode_put_attrib_ns(last, "seconds", NULL, NULL, str);
        xmlnode_insert_tag_node(m->packet->x,last);
    }
    js_deliver(m->si,m->packet, m->s);

    xmlnode_free(last);
    return M_HANDLED;
}

/**
 * delete stored data if a user is deleted
 *
 * @param m the mapi_struct
 * @param arg unused/ignored
 * @return always M_PASS
 */
static mreturn mod_last_delete(mapi m, void *arg) {
    mod_last_set(m, m->user->id, N_("Unregistered"));
    return M_PASS;
}

/**
 * init the mod_last module
 *
 * register different callbacks:
 * - mod_last_init for new user registrations
 * - mod_last_sess for new sessions
 * - mod_last_reply for stanzas  sent to an offline user
 * - mod_last_server for stanzas sent to the session manager's address
 *
 * The server's startup time is stored as the argument to the mod_last_server callback.
 *
 * @param si the session manager instance
 */
extern "C" void mod_last(jsmi si) {
    time_t *ttmp;
    xmlnode register_config = js_config(si, "register:register", NULL);
    log_debug2(ZONE, LOGT_INIT, "initing");

    if (register_config != NULL)
	js_mapi_register(si, e_REGISTER, mod_last_init, NULL);
    js_mapi_register(si, e_SESSION, mod_last_sess, NULL);
    js_mapi_register(si, e_DESERIALIZE, mod_last_sess, NULL);
    js_mapi_register(si, e_OFFLINE, mod_last_reply, NULL);

    /* set up the server responce, giving the startup time :) */
    ttmp = static_cast<time_t*>(pmalloco(si->p, sizeof(time_t)));
    time(ttmp);
    js_mapi_register(si, e_SERVER, mod_last_server, (void *)ttmp);
    js_mapi_register(si, e_DELETE, mod_last_delete, NULL);
    xmlnode_free(register_config);
}
