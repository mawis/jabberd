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
 * @file mod_admin.c
 * @brief Admin functionallity for the session manager
 *
 * This implements the admin functionallity of the session manger:
 * - The admin can discover the list of online users using service discovery on
 *   server node 'online users'
 * - Messages addressed to the session manager (without a resource) are forwarded to the
 *   configured admin address(es)
 */

/**
 * xhash_walker function used by _mod_admin_disco_online_items to add all online users to the iq result
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

    /* sanity check */
    if (query == NULL || u == NULL)
	return;

    log_notice(NULL, "walk for %s", key);

    /* for all sessions of this user */
    for (session_iter = u->sessions; session_iter != NULL; session_iter = session_iter->next) {
	xmlnode item = xmlnode_insert_tag_ns(query, "item", NULL, NS_DISCO_ITEMS);
	spool sp = spool_new(xmlnode_pool(query));

	/* generate text for this item */
	spooler(sp, jid_full(session_iter->id), " (dur: ", sp);
	snprintf(buffer, sizeof(buffer), "%d", (int)(t - session_iter->started));
	spooler(sp, buffer, " s, in: ", sp);
	snprintf(buffer, sizeof(buffer), "%d", session_iter->c_out);
	spooler(sp, buffer, " stnz, out: ", sp);
	snprintf(buffer, sizeof(buffer), "%d", session_iter->c_in);
	spooler(sp, buffer, " stnz)", sp);

	/* add attributes for this item */
	xmlnode_put_attrib_ns(item, "jid", NULL, NULL, jid_full(session_iter->id));
	xmlnode_put_attrib_ns(item, "name", NULL, NULL, spool_print(sp));
    }
}

/**
 * handle iq disco items request for the server's node 'online users'
 *
 * Send a reply to the disco#items request
 *
 * @param si the session manager instance
 * @param p the packet, that contains the disco request
 */
static void _mod_admin_disco_online_items(jsmi si, jpacket p) {
    xmlnode query = NULL;

    log_notice(NULL, "trying to handle online users items request");

    /* prepare the stanza */
    jutil_iqresult(p->x);
    query =xmlnode_insert_tag_ns(p->x, "query", NULL, NS_DISCO_INFO);
    xmlnode_put_attrib_ns(query, "node", NULL, NULL, "online users");

    /* add the online users */
    xhash_walk(xhash_get(si->hosts, p->to->server), _mod_admin_disco_online_iter, (void *)query);

    /* send back */
    jpacket_reset(p);
    js_deliver(si, p);
}

/**
 * handle iq disco info request for the server's node 'online users'
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
    xmlnode_put_attrib_ns(query, "node", NULL, NULL, "online users");

    /* send back */
    jpacket_reset(p);
    js_deliver(si, p);
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
mreturn mod_admin_dispatch(mapi m, void *arg) {
    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;
    if (jpacket_subtype(m->packet) == JPACKET__ERROR)
	return M_PASS;

    /* check disco node 'online users' feature */
    if (NSCHECK(m->packet->iq, NS_DISCO_INFO) && j_strcmp(xmlnode_get_attrib_ns(m->packet->iq, "node", NULL), "online users") == 0 && jpacket_subtype(m->packet) == JPACKET__GET) {
	if (acl_check_access(m->si->xc, ADMIN_LISTSESSIONS, m->packet->from))
	    _mod_admin_disco_online_info(m->si, m->packet);
	else
	    js_bounce_xmpp(m->si, m->packet->x, XTERROR_NOTALLOWED);
	return M_HANDLED;
    }
    if (NSCHECK(m->packet->iq, NS_DISCO_ITEMS) && j_strcmp(xmlnode_get_attrib_ns(m->packet->iq, "node", NULL), "online users") == 0 && jpacket_subtype(m->packet) == JPACKET__GET) {
	log_notice(NULL, "we got a disco items online users request");
	if (acl_check_access(m->si->xc, ADMIN_LISTSESSIONS, m->packet->from))
	    _mod_admin_disco_online_items(m->si, m->packet);
	else
	    js_bounce_xmpp(m->si, m->packet->x, XTERROR_NOTALLOWED);
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
mreturn mod_admin_message(mapi m, void *arg) {
    jpacket p;
    xmlnode cur;
    char *subject;
    const char *element_name;
    static char jidlist[1024] = "";
    jid admins = NULL;
    jid admin_iter = NULL;

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
    subject=spools(m->packet->p, "Admin: ", xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(m->packet->x, "subject", m->si->std_namespace_prefixes) ,0)), " (", m->packet->to->server, ")", m->packet->p);
    xmlnode_hide(xmlnode_get_list_item(xmlnode_get_tags(m->packet->x, "subject", m->si->std_namespace_prefixes), 0));
    xmlnode_insert_cdata(xmlnode_insert_tag_ns(m->packet->x, "subject", NULL, NS_SERVER), subject, -1);
    jutil_delay(m->packet->x, "admin");

    /* forward the message to every configured admin */
    admins = acl_get_users(m->si->xc, ADMIN_ADMINMSG);
    for (admin_iter = admins; admin_iter != NULL; admin_iter = admin_iter->next) {
	p = jpacket_new(xmlnode_dup(m->packet->x));
	p->to = jid_new(p->p, jid_full(admin_iter));
	xmlnode_put_attrib_ns(p->x, "to", NULL, NULL, jid_full(p->to));
	js_deliver(m->si, p);
    }

    /* reply, but only if we haven't in the last few or so jids */
    if ((cur = js_config(m->si,"jsm:admin/reply")) != NULL && strstr(jidlist,jid_full(jid_user(m->packet->from))) == NULL) {
	const char *lang = NULL;

        /* tack the jid onto the front of the list, depreciating old ones off the end */
        char njidlist[1024];
        snprintf(njidlist, sizeof(njidlist), "%s %s", jid_full(jid_user(m->packet->from)), jidlist);
        memcpy(jidlist,njidlist,1024);

	/* hide original subject and body */
	xmlnode_hide(xmlnode_get_list_item(xmlnode_get_tags(m->packet->x, "subject", m->si->std_namespace_prefixes), 0));
	xmlnode_hide(xmlnode_get_list_item(xmlnode_get_tags(m->packet->x, "body", m->si->std_namespace_prefixes), 0));

	/* copy the xml:lang attribute to the message */
	lang = xmlnode_get_lang(cur);
	if (lang != NULL) {
	    xmlnode_put_attrib_ns(m->packet->x, "lang", "xml", NS_XML, lang);
	}

	/* copy subject and body to the message */
	xmlnode_insert_node(m->packet->x, xmlnode_get_firstchild(cur));

        jutil_tofrom(m->packet->x);
        jpacket_reset(m->packet);
        js_deliver(m->si,m->packet);
    } else {
        xmlnode_free(m->packet->x);
    }
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
void mod_admin(jsmi si) {
    js_mapi_register(si,e_SERVER,mod_admin_dispatch,NULL);
    js_mapi_register(si,e_SERVER,mod_admin_message,NULL);
}
