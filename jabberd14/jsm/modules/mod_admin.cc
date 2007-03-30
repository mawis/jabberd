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
 * @file mod_admin.cc
 * @brief Admin functionallity for the session manager
 *
 * This implements the admin functionallity of the session manger:
 * - The admin can discover the list of online users using service discovery on
 *   server node 'online sessions'
 * - Messages addressed to the session manager (without a resource) are forwarded to the
 *   configured admin address(es)
 */

/**
 * xhash_walker function used by _mod_admin_disco_online_items to add all online sessions to the iq result
 *
 * @param h not used by this function
 * @param key not used by this function
 * @param data the user's data structure
 * @param arg the iq result XML node
 */
static void _mod_admin_disco_online_iter(xht h, const char *key, void *data, void *arg) {
    xmlnode item = NULL;
    xmlnode query = (xmlnode)arg;
    udata u = (udata)data;
    session session_iter = NULL;
    char buffer[32];
    time_t t = time(NULL);
    const char* lang = NULL;

    /* sanity check */
    if (query == NULL || u == NULL)
	return;

    lang = xmlnode_get_lang(query);

    /* for all sessions of this user */
    for (session_iter = u->sessions; session_iter != NULL; session_iter = session_iter->next) {
	xmlnode item = xmlnode_insert_tag_ns(query, "item", NULL, NS_DISCO_ITEMS);
	spool sp = spool_new(xmlnode_pool(query));

	/* generate text for this item */
	spooler(sp, jid_full(session_iter->id), " (", messages_get(lang, N_("dur")), ": ", sp);
	snprintf(buffer, sizeof(buffer), "%d", (int)(t - session_iter->started));
	spooler(sp, buffer, " ", messages_get(lang, N_("s")), ", ", messages_get(lang, N_("in")), ": ", sp);
	snprintf(buffer, sizeof(buffer), "%d", session_iter->c_out);
	spooler(sp, buffer, " ", messages_get(lang, N_("stnz")), ", ", messages_get(lang, N_("out")), ": ", sp);
	snprintf(buffer, sizeof(buffer), "%d", session_iter->c_in);
	spooler(sp, buffer, " ", messages_get(lang, N_("stnz")), ")", sp);

	/* add attributes for this item */
	xmlnode_put_attrib_ns(item, "jid", NULL, NULL, jid_full(session_iter->id));
	xmlnode_put_attrib_ns(item, "name", NULL, NULL, spool_print(sp));
    }
}

/**
 * handle iq disco items request for the server's node 'online sessions'
 *
 * Send a reply to the disco#items request
 *
 * @param si the session manager instance
 * @param p the packet, that contains the disco request
 */
static void _mod_admin_disco_online_items(jsmi si, jpacket p) {
    xmlnode query = NULL;

    log_notice(NULL, "trying to handle online sessions items request");

    /* prepare the stanza */
    jutil_iqresult(p->x);
    query =xmlnode_insert_tag_ns(p->x, "query", NULL, NS_DISCO_INFO);
    xmlnode_put_attrib_ns(query, "node", NULL, NULL, "online sessions");

    /* add the online sessions */
    xhash_walk(static_cast<xht>(xhash_get(si->hosts, p->to->server)), _mod_admin_disco_online_iter, (void *)query);

    /* send back */
    jpacket_reset(p);
    js_deliver(si, p, NULL);
}

/**
 * handle iq disco info request for the server's node 'online sessions'
 *
 * Send a reply to the disco#info request
 *
 * @param m the session manager instance
 * @param p the packet, that contains the disco request
 */
static void _mod_admin_disco_online_info(jsmi si, jpacket p) {
    xmlnode query = NULL;

    /* prepare the stanza */
    jutil_iqresult(p->x);
    query =xmlnode_insert_tag_ns(p->x, "query", NULL, NS_DISCO_INFO);
    xmlnode_put_attrib_ns(query, "node", NULL, NULL, "online sessions");

    /* send back */
    jpacket_reset(p);
    js_deliver(si, p, NULL);
}

/**
 * handle iq stanzas sent to the server address (all other stanza types will result in M_IGNORE).
 *
 * this function handles non-error-type iq stanas in the jabber:iq:admin namespace and in the
 * jabber:iq:browse namespace if the destination resource is 'admin'.
 *
 * this function will apply the access control configured in the <admin/> element in the session
 * manager configuration.
 *
 * @param m the mapi strcuture (containing the stanza)
 * @param arg not used/ignored
 * @return M_IGNORE if there should be no calls for stanzas of the same type again, M_PASS if we did not process the packet, M_HANDLED if it has been processed
 */
static mreturn mod_admin_dispatch(mapi m, void *arg) {
    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;
    if (jpacket_subtype(m->packet) == JPACKET__ERROR)
	return M_PASS;

    /* check disco node 'online sessions' feature */
    if (NSCHECK(m->packet->iq, NS_DISCO_INFO) && j_strcmp(xmlnode_get_attrib_ns(m->packet->iq, "node", NULL), "online sessions") == 0 && jpacket_subtype(m->packet) == JPACKET__GET) {
	if (acl_check_access(m->si->xc, ADMIN_LISTSESSIONS, m->packet->from))
	    _mod_admin_disco_online_info(m->si, m->packet);
	else
	    js_bounce_xmpp(m->si, NULL, m->packet->x, XTERROR_NOTALLOWED);
	return M_HANDLED;
    }
    if (NSCHECK(m->packet->iq, NS_DISCO_ITEMS) && j_strcmp(xmlnode_get_attrib_ns(m->packet->iq, "node", NULL), "online sessions") == 0 && jpacket_subtype(m->packet) == JPACKET__GET) {
	log_notice(NULL, "we got a disco items online sessions request");
	if (acl_check_access(m->si->xc, ADMIN_LISTSESSIONS, m->packet->from))
	    _mod_admin_disco_online_items(m->si, m->packet);
	else
	    js_bounce_xmpp(m->si, NULL, m->packet->x, XTERROR_NOTALLOWED);
	return M_HANDLED;
    }

    return M_PASS;
}

/**
 * handle messages sent to the server address (all other stanza types will result in M_IGNORE).
 * 
 * messages will only be processed if the destination resource is empty, it's not a message of
 * type 'error' and if there is a <admin/> element in the session manager configuration.
 *
 * messages with an <x xmlns='jabber:x:delay'/> element will be ignored to break circular loops
 * if a session manager is configured as the admin of itself or two session managers are configured
 * to be the admin of each other.
 *
 * @param m the mapi structure (contains the received stanza)
 * @param arg not used/ignored
 * @return M_IGNORE if not a message stanza (no further delivery of this stanza type), M_PASS if not handled, M_HANDLED else
 */
static mreturn mod_admin_message(mapi m, void *arg) {
    jpacket p;
    xmlnode cur;
    char *subject;
    const char *element_name;
    static char jidlist[1024] = "";
    jid admins = NULL;
    jid admin_iter = NULL;
    xmlnode reply = NULL;

    /* check if we are interested in handling this packet */
    if (m->packet->type != JPACKET_MESSAGE)
	return M_IGNORE; /* the session manager should not deliver this stanza type again */
    if (m->packet->to->resource != NULL || jpacket_subtype(m->packet) == JPACKET__ERROR)
	return M_PASS;

    /* drop ones w/ a delay! (circular safety) */
    if (xmlnode_get_list_item(xmlnode_get_tags(m->packet->x,"delay:x", m->si->std_namespace_prefixes), 0) != NULL) {
        xmlnode_free(m->packet->x);
        return M_HANDLED;
    }

    log_debug2(ZONE, LOGT_DELIVER, "delivering admin message from %s",jid_full(m->packet->from));

    /* update the message */
    subject=spools(m->packet->p, messages_get(xmlnode_get_lang(m->packet->x), N_("Admin: ")), xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(m->packet->x, "subject", m->si->std_namespace_prefixes) ,0)), " (", m->packet->to->server, ")", m->packet->p);
    xmlnode_hide(xmlnode_get_list_item(xmlnode_get_tags(m->packet->x, "subject", m->si->std_namespace_prefixes), 0));
    xmlnode_insert_cdata(xmlnode_insert_tag_ns(m->packet->x, "subject", NULL, NS_SERVER), subject, -1);
    jutil_delay(m->packet->x, "admin");

    /* forward the message to every configured admin */
    admins = acl_get_users(m->si->xc, ADMIN_ADMINMSG);
    for (admin_iter = admins; admin_iter != NULL; admin_iter = admin_iter->next) {
	p = jpacket_new(xmlnode_dup(m->packet->x));
	p->to = jid_new(p->p, jid_full(admin_iter));
	xmlnode_put_attrib_ns(p->x, "to", NULL, NULL, jid_full(p->to));
	js_deliver(m->si, p, NULL);
    }
    if (admins != NULL) {
	pool_free(admins->p);
	admins = NULL;
    }

    /* reply, but only if we haven't in the last few or so jids */
    reply = js_config(m->si, "jsm:admin/reply", xmlnode_get_lang(m->packet->x));
    if (reply != NULL && strstr(jidlist,jid_full(jid_user(m->packet->from))) == NULL) {
	const char *lang = NULL;

        /* tack the jid onto the front of the list, depreciating old ones off the end */
        char njidlist[1024];
        snprintf(njidlist, sizeof(njidlist), "%s %s", jid_full(jid_user(m->packet->from)), jidlist);
        memcpy(jidlist,njidlist,1024);

	/* hide original subject and body */
	xmlnode_hide(xmlnode_get_list_item(xmlnode_get_tags(m->packet->x, "subject", m->si->std_namespace_prefixes), 0));
	xmlnode_hide(xmlnode_get_list_item(xmlnode_get_tags(m->packet->x, "body", m->si->std_namespace_prefixes), 0));

	/* copy the xml:lang attribute to the message */
	lang = xmlnode_get_lang(reply);
	if (lang != NULL) {
	    xmlnode_put_attrib_ns(m->packet->x, "lang", "xml", NS_XML, lang);
	}

	/* copy subject and body to the message */
	xmlnode_insert_node(m->packet->x, xmlnode_get_firstchild(reply));

        jutil_tofrom(m->packet->x);
        jpacket_reset(m->packet);
        js_deliver(m->si, m->packet, NULL);
    } else {
        xmlnode_free(m->packet->x);
    }
    xmlnode_free(reply);
    return M_HANDLED; /* no other module needs to process this message */
}

/**
 * startup the mod_admin module
 * will register two callbacks:
 * - mod_admin_dispatch (will process iq stanzas to the server address)
 * - mod_admin_message (will process messages to the server address)
 *
 * @param si the session manager instance
 */
extern "C" void mod_admin(jsmi si) {
    js_mapi_register(si,e_SERVER,mod_admin_dispatch,NULL);
    js_mapi_register(si,e_SERVER,mod_admin_message,NULL);
}
