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
 * @file mod_vcard.cc
 * @brief Implement handling of namespace 'vcard-temp' (XEP-0054)
 *
 * This module allows publishing of vcard data, replies queries for the vcard data
 * of a user, responds to queries for the server vcard, and my forward published
 * vcards to a configured Jabber users directory.
 */

/**
 * publish vcard data to a Jabber users directory: handle the result to a get
 * request we sent to the users directory to get a key.
 *
 * @param m the mapi_struct containing the result
 * @return always M_HANDLED
 */
static mreturn mod_vcard_jud(mapi m) {
    xmlnode vcard, reg, regq;
    char *key;

    vcard = xdb_get(m->si->xc, m->user->id, NS_VCARD);

    if (vcard != NULL) {
        log_debug2(ZONE, LOGT_DELIVER, "sending registration for %s", jid_full(m->packet->to));
        reg = jutil_iqnew(JPACKET__SET, NS_REGISTER);
        xmlnode_put_attrib_ns(reg, "to", NULL, NULL, jid_full(m->packet->from));
        xmlnode_put_attrib_ns(reg, "from", NULL, NULL, jid_full(m->packet->to));
        regq = xmlnode_get_list_item(xmlnode_get_tags(reg,"register:query", m->si->std_namespace_prefixes), 0);

        xmlnode_insert_cdata(xmlnode_insert_tag_ns(regq, "name", NULL, NS_REGISTER), xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(vcard, "vcard:FN", m->si->std_namespace_prefixes), 0)),-1);
        xmlnode_insert_cdata(xmlnode_insert_tag_ns(regq, "first", NULL, NS_REGISTER), xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(vcard, "vcard:N/vcard:GIVEN", m->si->std_namespace_prefixes) ,0)),-1);
        xmlnode_insert_cdata(xmlnode_insert_tag_ns(regq, "last", NULL, NS_REGISTER), xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(vcard, "vcard:N/vcard:FAMILY", m->si->std_namespace_prefixes) ,0)),-1);
        xmlnode_insert_cdata(xmlnode_insert_tag_ns(regq, "nick", NULL, NS_REGISTER), xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(vcard, "vcard:NICKNAME", m->si->std_namespace_prefixes) ,0)),-1);
        xmlnode_insert_cdata(xmlnode_insert_tag_ns(regq, "email", NULL, NS_REGISTER), xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(vcard, "vcard:EMAIL", m->si->std_namespace_prefixes) ,0)),-1);
        js_deliver(m->si, jpacket_new(reg), NULL);
    }

    xmlnode_free(m->packet->x);
    xmlnode_free(vcard);
    return M_HANDLED;
}

/**
 * handle requests by the user to update his vcard
 *
 * @param m the mapi_struct containing the request
 * @param arg unused/ignored
 * @return M_IGNORE if not an iq stanza, M_HANDLED if the packet has been handled, M_PASS else
 */
static mreturn mod_vcard_set(mapi m, void *arg) {
    xmlnode vcard = NULL;
    xmlnode cur, judreg;
    xmlnode vcard2jud = NULL;
    xmlnode browse = NULL;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(m->packet->to != NULL || !NSCHECK(m->packet->iq,NS_VCARD)) return M_PASS;

    switch(jpacket_subtype(m->packet)) {
	case JPACKET__GET:
	    log_debug2(ZONE, LOGT_DELIVER, "handling get request");

	    /* request the vcard from storage */
	    vcard = xdb_get(m->si->xc, m->user->id, NS_VCARD);
	   
	    /* generate result */
	    xmlnode_put_attrib_ns(m->packet->x, "type", NULL, NULL, "result");

	    /* insert the vcard into the result */
	    xmlnode_insert_node(m->packet->iq, xmlnode_get_firstchild(vcard));
	    jpacket_reset(m->packet);

	    /* send to the user */
	    js_session_to(m->s,m->packet);

	    /* free the vcard again */
	    xmlnode_free(vcard);

	    break;
	case JPACKET__SET:
	    log_debug2(ZONE, LOGT_DELIVER, "handling set request %s",xmlnode_serialize_string(m->packet->iq, xmppd::ns_decl_list(), 0));

	    /* save and send response to the user */
	    if (xdb_set(m->si->xc, m->user->id, NS_VCARD, m->packet->iq)) {
		/* failed */
		jutil_error_xmpp(m->packet->x,XTERROR_UNAVAIL);
	    } else {
		jutil_iqresult(m->packet->x);
	    }

	    /* don't need to send the whole thing back */
	    xmlnode_hide(xmlnode_get_list_item(xmlnode_get_tags(m->packet->x, "vcard:vcard", m->si->std_namespace_prefixes), 0));
	    jpacket_reset(m->packet);
	    js_session_to(m->s,m->packet);

	    vcard2jud = js_config(m->si, "jsm:vcard2jud", NULL);
	    if (vcard2jud == NULL)
		break;
	    xmlnode_free(vcard2jud);
	    vcard2jud=NULL;

	    /* handle putting the vcard to the configured jud: send a get request to the jud services */
	    browse = js_config(m->si, "browse:browse", xmlnode_get_lang(m->packet->x));
	    for(cur = xmlnode_get_firstchild(browse); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
		if (j_strcmp(xmlnode_get_attrib_ns(cur, "type", NULL), "user") != 0)
		    continue;
		if (j_strcmp(xmlnode_get_attrib_ns(cur, "category", NULL), "directory") != 0)
		    continue;

		judreg = jutil_iqnew(JPACKET__GET,NS_REGISTER);
		xmlnode_put_attrib_ns(judreg, "to", NULL, NULL, xmlnode_get_attrib_ns(cur, "jid", NULL));
		xmlnode_put_attrib_ns(judreg, "id", NULL, NULL, "mod_vcard_jud");
		js_session_from(m->s,jpacket_new(judreg));

		/* added this in so it only does the first one */
		break;
	    }
	    xmlnode_free(browse);
	    browse = NULL;
	    break;
	default:
	    xmlnode_free(m->packet->x);
	    break;
    }
    return M_HANDLED;
}

/**
 * handle packets sent to an offline user
 *
 * Check if the packet is a query for the user's vcard, if yes reply to it.
 *
 * @param m the mapi_struct containing the query packet
 * @param arg unused/ignored
 * @return M_IGNORE if not an iq stanza, M_HANDLED if the packet is handled, M_PASS else
 */
static mreturn mod_vcard_reply(mapi m, void *arg) {
    xmlnode vcard;

    /* we only handle iq stanzas */
    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;

    /* register queries with an id of "mod_vcard_jud" */
    if (NSCHECK(m->packet->iq, NS_REGISTER) && j_strcmp(xmlnode_get_attrib_ns(m->packet->x, "id", NULL), "mod_vcard_jud") == 0)
	return mod_vcard_jud(m);

    /* we only care about iq stanzas in the vcard-temp namespace */
    if (!NSCHECK(m->packet->iq, NS_VCARD))
	return M_PASS;

    /* first, is this a valid request? */
    switch (jpacket_subtype(m->packet)) {
	case JPACKET__RESULT:
	case JPACKET__ERROR:
	    return M_PASS;
	case JPACKET__SET:
	    js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_NOTALLOWED);
	    return M_HANDLED;
    }

    log_debug2(ZONE, LOGT_DELIVER, "handling query for user %s", m->user->id->user);

    /* get this guys vcard info */
    vcard = xdb_get(m->si->xc, m->user->id, NS_VCARD);

    /* send back */
    jutil_iqresult(m->packet->x);
    jpacket_reset(m->packet);
    xmlnode_insert_tag_node(m->packet->x,vcard);
    js_deliver(m->si, m->packet, m->s);

    xmlnode_free(vcard);
    return M_HANDLED;
}

/**
 * Register callbacks for a session, called at session establishment
 *
 * Register the mod_vcard_set callback for packets the client sents,
 * register the mod_vcard_reply callback for packets the client receives.
 *
 * @param m the mapi_struct containing the pointer to the new session
 * @param arg unused/ignored
 * @return always M_PASS
 */
static mreturn mod_vcard_session(mapi m, void *arg) {
    js_mapi_session(es_OUT,m->s,mod_vcard_set,NULL);
    js_mapi_session(es_IN,m->s,mod_vcard_reply,NULL);
    return M_PASS;
}

/**
 * handle packets addressed to the server
 *
 * Reply IQ get packets in the vcard-temp namespace addressed to the server
 * by sending the servers vCard back to the sender.
 *
 * @param m the mapi_struct containing the packet
 * @param arg unused/ignored
 * @return M_IGNORE if not a iq stanza, M_HANDLED if the packet has been handled, M_PASS else
 */
static mreturn mod_vcard_server(mapi m, void *arg) {   
    xmlnode vcard, query;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(jpacket_subtype(m->packet) != JPACKET__GET || !NSCHECK(m->packet->iq,NS_VCARD) || m->packet->to->resource != NULL) return M_PASS;

    /* get data from the config file */
    if((vcard = js_config(m->si,"vcard:vCard", xmlnode_get_lang(m->packet->x))) == NULL)
        return M_PASS;

    log_debug2(ZONE, LOGT_DELIVER, "handling server vcard query");

    /* build the result IQ */
    jutil_iqresult(m->packet->x);
    query = xmlnode_insert_tag_node(m->packet->x,vcard);
    jpacket_reset(m->packet);
    js_deliver(m->si, m->packet, NULL);

    xmlnode_free(vcard);
    return M_HANDLED;
}

/**
 * delete a users vcard if the user is deleted
 *
 * @param m the mapi_struct
 * @param arg unused/ignored
 * @return always M_PASS
 */
static mreturn mod_vcard_delete(mapi m, void *arg) {
    xdb_set(m->si->xc, m->user->id, NS_VCARD, NULL);
    return M_PASS;
}

/**
 * Init the module, register callbacks in the session manager
 *
 * Register mod_vcard_session to be called for new established sessions,
 * register mod_vcard_session to be called for stanzas while user is offline,
 * register mod_vcard_server to be called for packets sent to the server address.
 *
 * @param si the session manager instance internal data
 */
extern "C" void mod_vcard(jsmi si) {
    js_mapi_register(si,e_SESSION,mod_vcard_session,NULL);
    js_mapi_register(si,e_DESERIALIZE, mod_vcard_session, NULL);
    js_mapi_register(si,e_OFFLINE,mod_vcard_reply,NULL);
    js_mapi_register(si,e_SERVER,mod_vcard_server,NULL);
    js_mapi_register(si, e_DELETE, mod_vcard_delete, NULL);
}
