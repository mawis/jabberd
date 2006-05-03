/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "JOSL").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the JOSL. You
 * may obtain a copy of the JOSL at http://www.jabber.org/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the JOSL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the JOSL
 * for the specific language governing rights and limitations under the
 * JOSL.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 or later (the "GPL"), in which case
 * the provisions of the GPL are applicable instead of those above.  If you
 * wish to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the JOSL,
 * indicate your decision by deleting the provisions above and replace them
 * with the notice and other provisions required by the GPL.  If you do not
 * delete the provisions above, a recipient may use your version of this file
 * under either the JOSL or the GPL. 
 * 
 * 
 * --------------------------------------------------------------------------*/
#include "jsm.h"

/**
 * @file mod_last.c
 * @brief Implement handling of jabber:iq:last (JEP-0012) in the session manager
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
mreturn mod_last_server(mapi m, void *arg) {
    time_t start = time(NULL) - *(time_t*)arg;
    char str[11];
    xmlnode last;

    /* pre-requisites */
    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(jpacket_subtype(m->packet) != JPACKET__GET || !NSCHECK(m->packet->iq,NS_LAST) || m->packet->to->resource != NULL) return M_PASS;

    jutil_iqresult(m->packet->x);
    jpacket_reset(m->packet);

    last = xmlnode_insert_tag_ns(m->packet->x, "query", NULL, NS_LAST);
    snprintf(str, sizeof(str), "%d", (int)start);
    xmlnode_put_attrib_ns(last, "seconds", NULL, NULL, str);

    js_deliver(m->si,m->packet);

    return M_HANDLED;
}

/**
 * function that updates the stored last information in xdb
 *
 * @param m the mapi structure
 * @param to which user should be updated
 * @param reason why the stored last information is updated
 */
void mod_last_set(mapi m, jid to, char *reason) {
    xmlnode last;
    char str[11];

    log_debug2(ZONE, LOGT_SESSION, "storing last for user %s",jid_full(to));

    /* make a generic last chunk and store it */
    last = xmlnode_new_tag_ns("query", NULL, NS_LAST);
    snprintf(str, sizeof(str), "%d", (int)time(NULL));
    xmlnode_put_attrib_ns(last, "last", NULL, NULL, str);
    xmlnode_insert_cdata(last, reason, -1);
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
mreturn mod_last_init(mapi m, void *arg) {
    if (jpacket_subtype(m->packet) != JPACKET__SET)
	return M_PASS;

    mod_last_set(m, m->packet->to, "Registered");

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
mreturn mod_last_sess_end(mapi m, void *arg) {
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
mreturn mod_last_sess(mapi m, void *arg) {
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
mreturn mod_last_reply(mapi m, void *arg) {
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
	    js_bounce_xmpp(m->si,m->packet->x,XTERROR_NOTALLOWED);
	    return M_HANDLED;
    }

    /* make sure they're in the roster */
    if (!js_trust(m->user,m->packet->from)) {
        js_bounce_xmpp(m->si,m->packet->x,XTERROR_FORBIDDEN);
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
    js_deliver(m->si,m->packet);

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
mreturn mod_last_delete(mapi m, void *arg) {
    xdb_set(m->si->xc, m->user->id, NS_LAST, NULL);
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
void mod_last(jsmi si) {
    time_t *ttmp;
    log_debug2(ZONE, LOGT_INIT, "initing");

    if (js_config(si,"register:register") != NULL)
	js_mapi_register(si, e_REGISTER, mod_last_init, NULL);
    js_mapi_register(si, e_SESSION, mod_last_sess, NULL);
    js_mapi_register(si, e_OFFLINE, mod_last_reply, NULL);

    /* set up the server responce, giving the startup time :) */
    ttmp = pmalloc(si->p, sizeof(time_t));
    time(ttmp);
    js_mapi_register(si, e_SERVER, mod_last_server, (void *)ttmp);
    js_mapi_register(si, e_DELETE, mod_last_delete, NULL);
}
