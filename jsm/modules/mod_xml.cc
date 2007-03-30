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
 * @file mod_xml.cc
 * @brief handling jabber:iq:private (XEP-0049) requests
 *
 * This module implements the storage of private data by a client on the server using the
 * jabber:iq:private namespace documented in XEP-0049.
 *
 * The module also used to implement the storage of data, that had been accessible by any entity on
 * the Jabber network and the handling of requests by other users to this data. But this has been
 * dropped with jabberd14 1.6.0.
 */

/**
 * callback that handles iq stanzas of the user itself (either set and get requests!)
 *
 * @param m the mapi structure
 * @param arg how results for non-existant private data should be handled (NULL = <item-not-found/>, other = empty list)
 * @return M_IGNORE if it is not an iq stanza, M_PASS if the stanza has not been processed, M_HANDLED if the stanza has been handled
 */
static mreturn mod_xml_set(mapi m, void *arg) {
    xmlnode storedx, inx = m->packet->iq;
    const char *ns = xmlnode_get_namespace(m->packet->iq);
    int got_result = 0;
    jpacket jp;
    xmlnode_list_item result_item = NULL;
    int is_delete = 0;

    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;

    /* to someone else? */
    if (m->packet->to != NULL)
	return M_PASS;

    /* we only handle requests in the jabber:iq:private namespace */
    if (!NSCHECK(m->packet->iq, NS_PRIVATE))
	return M_PASS;

    inx = xmlnode_get_firstchild(m->packet->iq);
    while (inx != NULL && (xmlnode_get_type(inx) != NTYPE_TAG || j_strcmp(xmlnode_get_namespace(inx), NS_PRIVATE) == 0 ))
	inx = xmlnode_get_nextsibling(inx);
    if (inx == NULL) {
	jutil_error_xmpp(m->packet->x, (xterror){406, N_("The query element in the jabber:iq:private namespace needs a child element in another namespace."), "modify", "not-acceptable"});
	js_session_to(m->s, m->packet);
	return M_HANDLED;
    }
    ns = xmlnode_get_namespace(inx);

    switch (jpacket_subtype(m->packet)) {
	case JPACKET__GET:
	    log_debug2(ZONE, LOGT_DELIVER|LOGT_STORAGE, "handling get request for %s", ns);

	    /* get the stored data */
	    storedx = xdb_get(m->si->xc, m->user->id, NS_PRIVATE);

	    /* get the relevant items */
	    for (result_item = xmlnode_get_tags(storedx, spools(m->packet->p, "private:query[@jabberd:ns='", ns, "']", m->packet->p), m->si->std_namespace_prefixes); result_item != NULL; result_item = result_item->next) {
		if (!got_result) {
		    got_result = 1;
		    /* prepare result */
		    jutil_iqresult(m->packet->x);
		}
		log_debug2(ZONE, LOGT_STORAGE, "found node: %s", xmlnode_serialize_string(result_item->node, xmppd::ns_decl_list(), 0));
		xmlnode_hide_attrib_ns(result_item->node, "ns", NS_JABBERD_WRAPPER);
		xmlnode_insert_tag_node(m->packet->x, result_item->node);
	    }

	    /* found something? */
	    if (!got_result) {
		if (!arg) {
		    /* no => return error */
		    js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_NOTFOUND);
		} else {
		    /* legacy client improved compatibility */
		    jutil_iqresult(m->packet->x);
		    m->packet->iq = xmlnode_insert_tag_ns(m->packet->x, "query", NULL, NS_PRIVATE);
		    xmlnode_insert_tag_node(m->packet->iq, inx);
		    jpacket_reset(m->packet);
		    js_session_to(m->s,m->packet);
		}
	    } else {
		/* yes => return result */
		jpacket_reset(m->packet);
		js_session_to(m->s,m->packet);
	    }

	    /* free the result */
	    xmlnode_free(storedx);

	    break;

	case JPACKET__SET:
	    log_debug2(ZONE, LOGT_DELIVER|LOGT_STORAGE, "handling set request for %s with data %s", ns, xmlnode_serialize_string(inx, xmppd::ns_decl_list(), 0));

	    is_delete = (xmlnode_get_firstchild(inx) == NULL);

	    log_debug2(ZONE, LOGT_STORAGE, "is_delete=%i, ns=%s", is_delete, ns);

	    /* save the changes */
	    xmlnode_put_attrib_ns(m->packet->iq, "ns", "jabberd", NS_JABBERD_WRAPPER, ns);
	    if (xdb_act_path(m->si->xc, m->user->id, NS_PRIVATE, "insert", spools(m->packet->p, "private:query[@jabberd:ns='", ns, "']", m->packet->p), m->si->std_namespace_prefixes, is_delete ? NULL : m->packet->iq))
		jutil_error_xmpp(m->packet->x, XTERROR_UNAVAIL);

	    /* build result and send back */
	    jutil_iqresult(m->packet->x);
	    jpacket_reset(m->packet);
	    js_session_to(m->s,m->packet);

	    break;

	default:
	    return M_PASS;
    }

    return M_HANDLED;
}

/**
 * callback that gets notified on new sessions of a user
 *
 * will register mod_xml_set as callback for stanzas sent by the user itself
 *
 * @param m the mapi structure
 * @param arg how results for non-existant private data should be handled (NULL = <item-not-found/>, other = empty list)
 * @return always M_PASS
 */
static mreturn mod_xml_session(mapi m, void *arg) {
    js_mapi_session(es_OUT, m->s, mod_xml_set, arg);
    return M_PASS;
}

/**
 * if a user is deleted, delete his stored data
 *
 * @param m the mapi structure
 * @param arg unused/ignored
 * @return always M_PASS
 */
static mreturn mod_xml_delete(mapi m, void *arg) {
    xdb_set(m->si->xc, m->user->id, NS_PRIVATE, NULL);
    return M_PASS;
}

/**
 * init the mod_xml module by registering callbacks
 *
 * mod_xml_session will register the mod_xml_set callback to process
 * requests from the user itself when the user starts a new session
 *
 * @param si the session manager instance
 */
extern "C" void mod_xml(jsmi si) {
    int empty_results = 0;
    xmlnode config = js_config(si, "jsm:mod_xml", NULL);
    if (xmlnode_get_tags(config, "jsm:empty_results", si->std_namespace_prefixes) != NULL) {
	empty_results = 1;
    }
    xmlnode_free(config);

    js_mapi_register(si, e_SESSION, mod_xml_session, (void*)empty_results);
    js_mapi_register(si, e_DESERIALIZE, mod_xml_session, (void*)empty_results);
    js_mapi_register(si, e_DELETE, mod_xml_delete, NULL);
}
