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
 * @file mod_browse.cc
 * @brief implement handling of the jabber:iq:browse namespace (XEP-0011) in the session manager - DEPRICATED
 *
 * This module implements the handling of jabber:iq:browse to query client information
 * in the session manager. jabber:iq:browse is documented in XEP-0011. Browsing
 * is DEPRICATED, clients should use service discovery instead.
 */

/**
 * Generate the browse result for a user by loading the information from xdb or creating it if there is nothing stored yet.
 *
 * @param m the mapi structure
 * @param id the JID of the user for which the browse info should be build
 * @return the xml fragment containing the browse result (must be freed by the caller)
 */
static xmlnode mod_browse_get(mapi m, jid id) {
    xmlnode browse, x;

    if (id == NULL) /* use the user id as a backup */
        id = m->user->id;

    /* get main account browse */
    if ((browse = xdb_get(m->si->xc, id, NS_BROWSE)) == NULL) {
	/* no browse is set up yet, we must create one for this user! */
        if (id->resource == NULL) {
	    /* a user is only the user@host */
            browse = xmlnode_new_tag_ns("user", NULL, NS_BROWSE);
            /* get the friendly name for this user from somewhere */
            if ((x = xdb_get(m->si->xc, m->user->id, NS_VCARD)) != NULL)
                xmlnode_put_attrib_ns(browse, "name", NULL, NULL, xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(x, "vcard:FN", m->si->std_namespace_prefixes), 0)));
            else if ((x = xdb_get(m->si->xc, m->user->id, NS_REGISTER)) != NULL)
                xmlnode_put_attrib_ns(browse, "name", NULL, NULL, xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(x, "register:name", m->si->std_namespace_prefixes), 0)));
            xmlnode_free(x);
        } else {
	    /* everything else is generic unless set by the user */
            browse = xmlnode_new_tag_ns("item", NULL, NS_BROWSE);
        }

        xmlnode_put_attrib_ns(browse, "jid", NULL, NULL, jid_full(id));

        xdb_set(m->si->xc, id, NS_BROWSE, browse);
    }

    return browse;
}

/**
 * Handle iq stanzas of type 'set' containing a jabber:iq:browse request.
 *
 * This callback is only inserted in the es_OUT handler list, therefore it is only called for stanzas the user
 * sents itself. It is NOT called for stanzas arriving at the user's address. It only handles stanzas with NO
 * to attribute.
 *
 * Handling iq stanzas of type 'set' is not documented in XEP-0011. I guess, it is an undocumented extension in jabberd14.
 *
 * @param m the mapi structure containing the request
 * @param arg unused/ignored
 * @return M_IGNORE if it is no iq stanza, M_PASS if the packet has not been processed, M_HANDLED if the packet has been processed
 */
static mreturn mod_browse_set(mapi m, void *arg) {
    xmlnode browse, cur;
    jid id, to;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(!NSCHECK(m->packet->iq,NS_BROWSE) || jpacket_subtype(m->packet) != JPACKET__SET) return M_PASS;
    if(m->packet->to != NULL) return M_PASS; /* if its to someone other than ourselves */

    log_debug2(ZONE, LOGT_DELIVER, "handling set request %s", xmlnode_serialize_string(m->packet->iq, xmppd::ns_decl_list(), 0));

    /* no to implies to ourselves */
    if (m->packet->to != NULL)
        to = m->packet->to;
    else
        to = m->user->id;

    /* if we set to a resource, we need to make sure that resource's browse is in the users browse */
    if (to->resource != NULL) {
        browse = mod_browse_get(m, to); /* get our browse info */
        xmlnode_hide_attrib_ns(browse, "xmlns", NS_XMLNS); /* don't need a ns as a child */
        for (cur = xmlnode_get_firstchild(browse); cur != NULL; cur = xmlnode_get_nextsibling(cur))
            xmlnode_hide(cur); /* erase all children */
        xdb_act_path(m->si->xc, m->user->id, NS_BROWSE, "insert", spools(m->packet->p,"*[@jid='", jid_full(to), "']", m->packet->p), m->si->std_namespace_prefixes, browse); /* insert and match replace */
        xmlnode_free(browse);
    }

    /* get the id of the new browse item */
    if ((cur = xmlnode_get_firstchild(m->packet->iq)) == NULL || (id = jid_new(m->packet->p, xmlnode_get_attrib_ns(cur, "jid", NULL))) == NULL) {
        js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_NOTACCEPTABLE);
        return M_HANDLED;
    }

    /* insert the new item into the resource it was sent to */
    xmlnode_hide_attrib_ns(cur, "xmlns", NS_XMLNS); /* just in case, to make sure it inserts */
    if (xdb_act_path(m->si->xc, to, NS_BROWSE, "insert", spools(m->packet->p, "*[@jid='", jid_full(id), "']", m->packet->p), m->si->std_namespace_prefixes, cur)) {
        js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_UNAVAIL);
        return M_HANDLED;
    }
        
    /* if the new data we're inserting is to one of our resources, update that resource's browse */
    if (jid_cmpx(m->user->id, id, JID_USER|JID_SERVER) == 0 && id->resource != NULL) {
        /* get the old */
        browse = mod_browse_get(m, id);
        /* transform the new one into the old one */
        xmlnode_insert_node(cur, xmlnode_get_firstchild(browse));
        xdb_set(m->si->xc, id, NS_BROWSE, cur); /* replace the resource's browse w/ this one */
        xmlnode_free(browse);
    }

    /* send response to the user */
    jutil_iqresult(m->packet->x);
    jpacket_reset(m->packet);
    js_session_to(m->s,m->packet);

    return M_HANDLED;
}

/**
 * register a callback for stanzas the user sends (to be able to handle queries without a to attribute)
 *
 * @param m the mapi structure
 * @param arg unused/ignored
 * @return always M_PASS
 */
static mreturn mod_browse_session(mapi m, void *arg) {
    js_mapi_session(es_OUT,m->s,mod_browse_set,NULL);
    return M_PASS;
}

/**
 * This callback handles iq stanzas sent to an offline user.
 * Everything but iq stanzas are ignored, iq queries not in the jabber:iq:browse namespace are not handled.
 * Only iq stanzas of type 'get' are really processed, stanzas of type 'set' are denied, other types are ignored.
 *
 * The result is build using the user's stored browse info. If the user that sent the query is subscribed
 * to the target's presence, a list of active sessions of the users is added to the result as well.
 *
 * @param m the mapi instance containing the query
 * @param arg not used/ignored
 * @return M_IGNORE if the packet is no iq stanza, M_PASS if the stanza has not been processed, M_HANDLED if the request has been handled
 */
static mreturn mod_browse_reply(mapi m, void *arg) {
    xmlnode browse, ns, cur;
    session s;

    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;
    if (!NSCHECK(m->packet->iq,NS_BROWSE))
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

    log_debug2(ZONE, LOGT_DELIVER, "handling query for user %s", m->user->id->user);

    /* get this dudes browse info */
    browse = mod_browse_get(m, m->packet->to);

    /* insert the namespaces */
    ns = xdb_get(m->si->xc, m->packet->to, NS_XDBNSLIST);
    for (cur = xmlnode_get_firstchild(ns); cur != NULL; cur = xmlnode_get_nextsibling(cur))
        if(xmlnode_get_attrib_ns(cur, "type", NULL) == NULL)
            xmlnode_insert_tag_node(browse, cur); /* only include the generic <ns>foo</ns> */
    xmlnode_free(ns);

    /* include any connected resources if there's a s10n from them */
    if (js_trust(m->user, m->packet->from)) {
        for (s = m->user->sessions; s != NULL; s = s->next) {
            /* if(s->priority < 0) continue; *** include all resources I guess */
            if (xmlnode_get_list_item(xmlnode_get_tags(browse, spools(m->packet->p,"*[@jid='",jid_full(s->id), "']'", m->packet->p), m->si->std_namespace_prefixes), 0) != NULL)
		continue; /* already in the browse result */
            cur = xmlnode_insert_tag_ns(browse, "user", NULL, NS_BROWSE);
            xmlnode_put_attrib_ns(cur, "type", NULL, NULL, "client");
            xmlnode_put_attrib_ns(cur, "jid", NULL, NULL, jid_full(s->id));
        }
    }

    jutil_iqresult(m->packet->x);
    jpacket_reset(m->packet);
    xmlnode_insert_tag_node(m->packet->x,browse);
    js_deliver(m->si, m->packet, m->s);

    xmlnode_free(browse);
    return M_HANDLED;
}

/**
 * Handle stanzas that are sent to the server's address.
 * Everything but iq stanzas are ignored. The iq stanzas have to be of type 'get', the content must be in the jabber:iq:browse namespace
 * and there must be no resource, else the stanza won't be handled either.
 *
 * The result will be build using the content of the <browse/> element in the session manager configuration. The the user that sent
 * the query as read admin privileges, and advertizement for serverdomain/admin will be sent as well. (Queries to this address
 * are handled by mod_admin.c.)
 *
 * @param m the mapi structure containing the request
 * @return M_IGNORE if the stanza is no iq, M_PASS if this module is not responsible, M_HANDLED if the stanza has been processed
 */
static mreturn _mod_browse_server(mapi m) {
    xmlnode browse, query, x;
    xmlnode vcard_fn = NULL;

    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;
    if (jpacket_subtype(m->packet) != JPACKET__GET || m->packet->to->resource != NULL)
	return M_PASS;

    /* get data from the config file */
    if ((browse = js_config(m->si, "browse:browse", xmlnode_get_lang(m->packet->x))) == NULL)
        return M_PASS;

    log_debug2(ZONE, LOGT_DELIVER, "handling browse query");

    /* build the result IQ */
    vcard_fn = js_config(m->si, "vcard:vCard/vcard:FN", xmlnode_get_lang(m->packet->x));
    query = xmlnode_insert_tag_ns(jutil_iqresult(m->packet->x), "service", NULL, NS_BROWSE);
    xmlnode_put_attrib_ns(query, "type", NULL, NULL, "jabber");
    xmlnode_put_attrib_ns(query, "jid", NULL, NULL, m->packet->to->server);
    xmlnode_put_attrib_ns(query, "name", NULL, NULL, xmlnode_get_data(vcard_fn)); /* pull name from the server vCard */

    /* copy in the configured services */
    for (x=xmlnode_get_firstchild(browse); x != NULL; x=xmlnode_get_nextsibling(x)) {
	const char* acl = NULL;

	/* only copy tags */
	if (x->type != NTYPE_TAG)
	    continue;

	/* check if this element should be skipped because of ACLs */
	acl = xmlnode_get_attrib_ns(x, "if", NS_JABBERD_ACL);
	if (acl != NULL && !acl_check_access(m->si->xc, acl, m->packet->from))
	    continue;
	acl = xmlnode_get_attrib_ns(x, "ifnot", NS_JABBERD_ACL);
	if (acl != NULL && acl_check_access(m->si->xc, acl, m->packet->from))
	    continue;

	/* copy the node */
	xmlnode_insert_tag_node(query, x);
    }

    jpacket_reset(m->packet);
    js_deliver(m->si,m->packet, m->s);

    xmlnode_free(browse);
    xmlnode_free(vcard_fn);

    return M_HANDLED;
}

/**
 * delete browse data for a user on user deletion
 *
 * @param m the mapi_struct
 * @param arg unused/ignored
 * @return always M_PASS
 */
static mreturn mod_browse_delete(mapi m, void *arg) {
    xdb_set(m->si->xc, m->user->id, NS_BROWSE, NULL);
    return M_PASS;
}

/**
 * handle disco info query to the server address, add our feature
 */
static mreturn _mod_browse_disco_info(mapi m) {
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
    xmlnode_put_attrib_ns(feature, "var", NULL, NULL, NS_BROWSE);

    return M_PASS;
}
/**
 * handle iq packets to the server address
 *
 * @param m the mapi_struct containing the request
 * @param arg unused/ignored
 * @return M_IGNORE if no iq request, M_HANDLED or M_PASS else
 */
static mreturn _mod_browse_iq_server(mapi m, void *arg) {
    /* sanity check */
    if (m == NULL || m->packet == NULL)
	return M_PASS;

    /* only handle iq packets */
    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;

    /* version request? */
    if (NSCHECK(m->packet->iq, NS_BROWSE))
	return _mod_browse_server(m);

    /* disco#info query? */
    if (NSCHECK(m->packet->iq, NS_DISCO_INFO))
	return _mod_browse_disco_info(m);

    return M_PASS;
}

/**
 * init the mod_browse module in the session manager
 * registers three callbacks: if a session is started, mod_browse_session should be called,
 * if an offline user gets a stanza, mod_browse_reply should be called,
 * if a stanza is sent to the server, mod_browse_server should be called.
 *
 * @param si the session manager instance
 */
extern "C" void mod_browse(jsmi si) {
    js_mapi_register(si, e_SESSION, mod_browse_session, NULL);
    js_mapi_register(si, e_DESERIALIZE, mod_browse_session, NULL);
    js_mapi_register(si, e_OFFLINE, mod_browse_reply, NULL);
    js_mapi_register(si, e_SERVER, _mod_browse_iq_server, NULL);
    js_mapi_register(si, e_DELETE, mod_browse_delete, NULL);
}
