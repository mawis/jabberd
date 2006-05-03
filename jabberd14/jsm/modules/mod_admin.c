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
 * @brief Admin functionallity for the session manager (undocumented) - DEPRECATED
 *
 * This implements the admin functionallity of the session manger:
 * - The admin can browse the list of online users (jabber:iq:browse to serverdomain/admin)
 * - The admin can request the list of online users using the DEPRICATED jabber:iq:admin
 *   namespace (which is not documented)
 * - The admin can update the session managers configuration file using the DEPRICATED
 *   and undocumented jabber:iq:admin namespace
 * - Messages addressed to the session manager (without a resource) are forwarded to the
 *   configured admin address(es)
 */

/**
 * xhash_walker function used by mod_admin_browse to add all online users to the iq result
 *
 * @param h not used by this function
 * @param key not used by this function
 * @param data the user's data structure
 * @param arg the iq result XML node
 */
void _mod_admin_browse(xht h, const char *key, void *data, void *arg) {
    xmlnode browse = (xmlnode)arg;
    udata u = (udata)data;
    xmlnode x;
    session s = js_session_primary(u);
    spool sp;
    int t = time(NULL);
    char buff[10];

    /* make a user generic entry */
    x = xmlnode_insert_tag_ns(browse, "user", NULL, NS_BROWSE);
    xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(u->id));
    if (s == NULL) {
        xmlnode_put_attrib_ns(x, "name", NULL, NULL, u->id->user);
        return;
    }
    sp = spool_new(xmlnode_pool(browse));
    spooler(sp,u->id->user," (",sp);

    /* insert extended data for the primary session */
    snprintf(buff, sizeof(buff), "%d", (int)(t - s->started));
    spooler(sp,buff,", ",sp);
    snprintf(buff, sizeof(buff), "%d", s->c_out);
    spooler(sp,buff,", ",sp);
    snprintf(buff, sizeof(buff), "%d", s->c_in);
    spooler(sp,buff,")",sp);

    xmlnode_put_attrib_ns(x, "name", NULL, NULL, spool_print(sp));
}

/**
 * handle an iq request in the jabber:iq:browse namespace sent to the resource "admin"
 * get requests will return the list of online users
 * set requests will return an empty list
 *
 * @param si the session manager instance
 * @param p the packet containing the request
 */
void mod_admin_browse(jsmi si, jpacket p) {
    xmlnode browse;

    /* all requests we have to process are of type 'get' */
    if (jpacket_subtype(p) != JPACKET__GET) {
	js_bounce_xmpp(si,p->x,XTERROR_BAD);
	return;
    }

    /* prepare the result */
    jutil_iqresult(p->x);
    browse = xmlnode_insert_tag_ns(p->x, "item", NULL, NS_BROWSE);
    xmlnode_put_attrib_ns(browse, "jid", NULL, NULL, spools(xmlnode_pool(browse),p->to->server,"/admin",xmlnode_pool(browse)));
    xmlnode_put_attrib_ns(browse, "name", NULL, NULL, "Online Users (seconds, sent, received)");

    log_debug2(ZONE, LOGT_DELIVER, "handling who GET");

    /* walk the users on this host */
    xhash_walk(xhash_get(si->hosts, p->to->server),_mod_admin_browse,(void *)browse);

    /* deliver the result */
    jpacket_reset(p);
    js_deliver(si,p);
}

/**
 * xhash_walker to add the presences of the online users to the result of a
 * jabber:iq:admin/who query
 *
 * used by mod_admin_who
 *
 * @param ht not used
 * @param key not used
 * @param data the user's data structure
 * @param arg the XML element where the presences will be added as child elements
 */
void _mod_admin_who(xht ht, const char *key, void *data, void *arg) {
    xmlnode who = (xmlnode)arg;
    udata u = (udata)data;
    session s;
    xmlnode x;
    time_t t;
    char buff[10];

    t = time(NULL);

    /* loop through all the sessions */
    for (s = u->sessions; s != NULL; s = s->next) {
        /* make a presence entry for each one with a custom extension */
        x = xmlnode_insert_tag_node(who,s->presence);
        x = xmlnode_insert_tag_ns(x, "x", NULL, NS_ADMIN_WHO);

        /* insert extended data */
        snprintf(buff, sizeof(buff), "%d", (int)(t - s->started));
        xmlnode_put_attrib_ns(x, "timer", NULL, NULL, buff);
        snprintf(buff, sizeof(buff), "%d", s->c_in);
        xmlnode_put_attrib_ns(x, "from", NULL, NULL, buff);
        snprintf(buff, sizeof(buff), "%d", s->c_out);
        xmlnode_put_attrib_ns(x, "to", NULL, NULL, buff);
    }
}

/**
 * handle iq stanzas sent to the server address with a query in the jabber:iq:admin namespace
 * containing a <who/> element.
 *
 * Reply to this query with an iq result containing a list of presences of all users currently
 * online on the session manager. The presences will contain an additional element in the
 * jabber:mod_admin:who namespace containing simple user statistics
 *
 * @param si the session manager instance structure
 * @param p the stanza packet containing the request
 * @return always M_HANDLED
 */
mreturn mod_admin_who(jsmi si, jpacket p) {
    xmlnode who;

    /* all valid requests will be of type 'get' */
    if (jpacket_subtype(p) != JPACKET__GET) {
	js_bounce_xmpp(si, p->x, XTERROR_BAD);
	return M_HANDLED;
    }

    log_debug2(ZONE, LOGT_DELIVER, "handling who GET");

    /* walk the users on this host */
    who = xmlnode_get_list_item(xmlnode_get_tags(p->iq, "admin:who", si->std_namespace_prefixes), 0);
    xhash_walk(xhash_get(si->hosts, p->to->server),_mod_admin_who,(void *)who);

    /* sent the result */
    jutil_tofrom(p->x);
    xmlnode_put_attrib_ns(p->x, "type", NULL, NULL, "result");
    jpacket_reset(p);
    js_deliver(si,p);
    return M_HANDLED;
}

/**
 * handle iq stanzas sent to the server address of type 'get' and 'set' in the jabber:iq:admin namespace
 * containing an <config/> element.
 *
 * This can be used to get the session manager configuration and to update it while the server is
 * running. Updating the configuration is only with limited use as the session manager will not
 * run the initialization stuff using the new configuration.
 *
 * @param si the session manager instance
 * @param p the packet containing the request
 * @return always M_HANDLED
 */
mreturn mod_admin_config(jsmi si, jpacket p) {
    xmlnode config = xmlnode_get_list_item(xmlnode_get_tags(p->iq, "admin:config", si->std_namespace_prefixes), 0);
    xmlnode cur;

    if(jpacket_subtype(p) == JPACKET__GET) {
        log_debug2(ZONE, LOGT_DELIVER|LOGT_CONFIG, "handling config GET");

        /* insert the loaded config file */
        xmlnode_insert_node(config,xmlnode_get_firstchild(si->config));
    }

    if(jpacket_subtype(p) == JPACKET__SET) {
        log_debug2(ZONE, LOGT_DELIVER|LOGT_CONFIG, "handling config SET");

        /* XXX FIX ME, like do init stuff for the new config, etc */
        si->config = xmlnode_dup(config);


        /* empty the iq result */
        for(cur = xmlnode_get_firstchild(p->x); cur != NULL; cur = xmlnode_get_nextsibling(cur))
            xmlnode_hide(cur);
    }

    jutil_tofrom(p->x);
    xmlnode_put_attrib_ns(p->x, "type", NULL, NULL, "result");
    jpacket_reset(p);
    js_deliver(si,p);
    return M_HANDLED;
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

    /* first check the /admin browse feature */
    if (NSCHECK(m->packet->iq,NS_BROWSE) && j_strcmp(m->packet->to->resource,"admin") == 0) {
        if(js_admin(m->user, ADMIN_READ))
            mod_admin_browse(m->si, m->packet);
        else
            js_bounce_xmpp(m->si, m->packet->x, XTERROR_NOTALLOWED);
        return M_HANDLED;
    }

    /* now normal iq:admin stuff */
    if (!NSCHECK(m->packet->iq,NS_ADMIN))
	return M_PASS;

    log_debug2(ZONE, LOGT_AUTH|LOGT_DELIVER, "checking admin request from %s",jid_full(m->packet->from));

    if (js_admin(m->user, ADMIN_READ)) {
	if (j_strcmp(xmlnode_get_localname(m->packet->iq), "who") == 0)
	    return mod_admin_who(m->si, m->packet);
    }

    if (js_admin(m->user, ADMIN_WRITE)) {
	if (j_strcmp(xmlnode_get_localname(m->packet->iq), "config") == 0)
	    return mod_admin_config(m->si, m->packet);
    }

    js_bounce_xmpp(m->si, m->packet->x, XTERROR_NOTALLOWED);
    return M_HANDLED;
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

    /* check if we are interested in handling this packet */
    if (m->packet->type != JPACKET_MESSAGE)
	return M_IGNORE; /* the session manager should not deliver this stanza type again */
    if (m->packet->to->resource != NULL || js_config(m->si, "jsm:admin") == NULL || jpacket_subtype(m->packet) == JPACKET__ERROR)
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

    /* forward the message to every configured admin (either read-only- or read-/write-admins) */
    for (cur = xmlnode_get_firstchild(js_config(m->si, "jsm:admin")); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
	element_name = xmlnode_get_localname(cur);
        if(element_name == NULL || (j_strcmp(element_name, "read")!=0 && j_strcmp(element_name, "write")!=0) || xmlnode_get_data(cur) == NULL || j_strcmp(xmlnode_get_namespace(cur), NS_JABBERD_CONFIG_JSM) != 0)
	continue;

        p = jpacket_new(xmlnode_dup(m->packet->x));
        p->to = jid_new(p->p,xmlnode_get_data(cur));
        xmlnode_put_attrib_ns(p->x, "to", NULL, NULL, jid_full(p->to));
        js_deliver(m->si,p);
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
