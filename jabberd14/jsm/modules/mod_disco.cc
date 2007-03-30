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

/* * this was taken from wpjabber cvs - thanks guys :) */

#include "jsm.h"

/**
 * @file mod_disco.cc
 * @brief implement handling of service discovery (XEP-0030) in the session manager
 *
 * This module implements service discovery to get the list of available services
 * on the jabber server installation. Only handling of requests addressed to the
 * server is implemented. Handling requests to a user's address are not handled
 * by this module. Neither does this module handle service discovery requests sent
 * to a node.
 */

/**
 * This function handles iq stanzas of type 'get' in the http://jabber.org/protocol/disco#info namespace.
 *
 * The result is build using the content of the <disco/> element in the session manager's configuration.
 * 
 * The packet is not processed if it is addressed to a specific node.
 *
 * @param m the mapi structure containing the request
 * @param arg unused/ignored
 * @return M_PASS if the packet has not been processed, M_HANDLED if the packet has been handled
 */
static mreturn mod_disco_server_info(mapi m, void *arg) {
    xmlnode identity = NULL;
    xmlnode feature = NULL;

    if ((xmlnode_get_attrib_ns(m->packet->iq, "node", NULL)) != NULL)
	return M_PASS;
        
    log_debug2(ZONE, LOGT_DELIVER, "handling disco#info query");

    /* build the result IQ */
    js_mapi_create_additional_iq_result(m, "query", NULL, NS_DISCO_INFO);

    /* sanity check */
    if (m->additional_result == NULL)
	return M_PASS;

    /* special identity in configuration? else generate from vCard */
    identity = js_config(m->si, "disco-info:disco/disco-info:identity", xmlnode_get_lang(m->packet->x));

    /* general features, not added by other modules */
    feature = xmlnode_insert_tag_ns(m->additional_result->iq, "feature", NULL, NS_DISCO_INFO);
    xmlnode_put_attrib_ns(feature, "var", NULL, NULL, "stringprep");
    feature = xmlnode_insert_tag_ns(m->additional_result->iq, "feature", NULL, NS_DISCO_INFO);
    xmlnode_put_attrib_ns(feature, "var", NULL, NULL, "fullunicode");
    feature = xmlnode_insert_tag_ns(m->additional_result->iq, "feature", NULL, NS_DISCO_INFO);
    xmlnode_put_attrib_ns(feature, "var", NULL, NULL, "xmllang");
    feature = xmlnode_insert_tag_ns(m->additional_result->iq, "feature", NULL, NS_DISCO_INFO);
    xmlnode_put_attrib_ns(feature, "var", NULL, NULL, NS_DISCO_INFO);
    feature = xmlnode_insert_tag_ns(m->additional_result->iq, "feature", NULL, NS_DISCO_INFO);
    xmlnode_put_attrib_ns(feature, "var", NULL, NULL, NS_DISCO_ITEMS);

    if (identity != NULL) {
	xmlnode_insert_node(m->additional_result->iq, identity);
    } else {
	xmlnode generated_identity = xmlnode_insert_tag_ns(m->additional_result->iq, "identity", NULL, NS_DISCO_INFO);
	xmlnode vcard_fn = js_config(m->si, "vcard:vCard/vcard:FN", xmlnode_get_lang(m->packet->x));
	xmlnode_put_attrib_ns(generated_identity, "category", NULL, NULL, "server");
	xmlnode_put_attrib_ns(generated_identity, "type", NULL, NULL, "im");
	xmlnode_put_attrib_ns(generated_identity, "name", NULL, NULL, xmlnode_get_data(vcard_fn));
	xmlnode_free(vcard_fn);
    }

    /* other modules might add other information to the result */
    xmlnode_free(identity);
    return M_PASS;
}

/**
 * This function handles iq stanzas of type 'get' in the http://jabber.org/protocol/disco#items namespace.
 *
 * The result is build using the content of the <browse/> element in the session manager's configruration.
 *
 * The packet is not processed if it is addressed to a specific node.
 *
 * @param m the mapi structure containing the request
 * @param arg unused/ignored
 * @return M_PASS if the packet has not been processed, M_HANDLED if the packet has been handled
 */
static mreturn mod_disco_server_items(mapi m, void *arg) {
  xmlnode browse, query, cur;
  jid admins = NULL;
  jid admin_iter = NULL;
  
  if ((xmlnode_get_attrib_ns(m->packet->iq, "node", NULL)) != NULL)
      return M_PASS;

  /* config get */        
  if ((browse = js_config(m->si,"browse:browse", xmlnode_get_lang(m->packet->x))) == NULL)
	return M_PASS;
  
  log_debug2(ZONE, LOGT_DELIVER, "handling disco#items query");

  /* build the result IQ */
  query = xmlnode_insert_tag_ns(jutil_iqresult(m->packet->x), "query", NULL, NS_DISCO_ITEMS);

  /* copy in the configured services */
  for (cur = xmlnode_get_firstchild(browse); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
	xmlnode item;
	const char *jid,*name;
	const char* acl=NULL;

	if (cur->type != NTYPE_TAG)
	    continue;

	/* check if this element should be skipped because of ACLs */
	acl = xmlnode_get_attrib_ns(cur, "if", NS_JABBERD_ACL);
	if (acl != NULL && !acl_check_access(m->si->xc, acl, m->packet->from))
	    continue;
	acl = xmlnode_get_attrib_ns(cur, "ifnot", NS_JABBERD_ACL);
	if (acl != NULL && acl_check_access(m->si->xc, acl, m->packet->from))
	    continue;

	jid = xmlnode_get_attrib_ns(cur, "jid", NULL);
	if (!jid)
	    continue;

	item = xmlnode_insert_tag_ns(query, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(item, "jid", NULL, NULL, jid);
	name = xmlnode_get_attrib_ns(cur, "name", NULL);
	if (name)
	    xmlnode_put_attrib_ns(item, "name", NULL, NULL, name);
  }

  /* list the admin stuff */
  if (acl_check_access(m->si->xc, ADMIN_LISTSESSIONS, m->packet->from)) {
    xmlnode item = NULL;
    item = xmlnode_insert_tag_ns(query, "item", NULL, NS_DISCO_ITEMS);
    xmlnode_put_attrib_ns(item, "jid", NULL, NULL, jid_full(m->packet->to));
    xmlnode_put_attrib_ns(item, "name", NULL, NULL, "Online Users");
    xmlnode_put_attrib_ns(item, "node", NULL, NULL, "online sessions");
  }

  /* list administrators */
  admins = acl_get_users(m->si->xc, "showasadmin");
  for (admin_iter = admins; admin_iter != NULL; admin_iter = admin_iter->next) {
      xmlnode item = NULL;
      item = xmlnode_insert_tag_ns(query, "item", NULL, NS_DISCO_ITEMS);
      xmlnode_put_attrib_ns(item, "jid", NULL, NULL, jid_full(admin_iter));
      xmlnode_put_attrib_ns(item, "name", NULL, NULL, messages_get(xmlnode_get_lang(m->packet->x), N_("Administrator")));
  }
  if (admins != NULL) {
      pool_free(admins->p);
      admins = NULL;
  }


  jpacket_reset(m->packet);
  js_deliver(m->si, m->packet, NULL);

  xmlnode_free(browse);
  
  return M_HANDLED;
}

/**
 * This callback handles stanzas sent to the server's address.
 *
 * Everything but iq stanzas are ignored. Only iq stanzas of type 'get' are processed.
 * Processing of queries in the namespace http://jabber.org/protocol/disco#items are delegated to mod_disco_server_items.
 * Processing of queries in the namespace http://jabber.org/protocol/disco#info are delegated to mod_disco_server_info.
 * No other namespaces are processed.
 *
 * @param m the mapi structure containing the request
 * @param arg unused/ignored (but passed to mod_disco_server_items and mod_disco_server_info)
 * @return M_IGNORE if it is no iq stanza, M_PASS if the packet has not been processed, M_HANDLED if the packet has been processed
 */
static mreturn mod_disco_server(mapi m, void *arg) {
    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;
    if (jpacket_subtype(m->packet) != JPACKET__GET)
	return M_PASS;
    if (m->packet->to->resource != NULL)
	return M_PASS;
    if (NSCHECK(m->packet->iq, NS_DISCO_ITEMS))
	return mod_disco_server_items(m,arg);
    if (NSCHECK(m->packet->iq, NS_DISCO_INFO))
	return mod_disco_server_info(m,arg);
    return M_PASS;
}

/**
 * This function handles a disco items request to a user's JID
 *
 * @param m the mapi structure containing the request
 * @return M_PASS if the request has not been processed, M_HANDLED if the request has been handled
 */
static mreturn mod_disco_user_items(mapi m) {
    xmlnode x = NULL;
    session s = NULL;

    if (jpacket_subtype(m->packet) == JPACKET__SET) {
	js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_NOTALLOWED);
	return M_HANDLED;
    }
    if (jpacket_subtype(m->packet) != JPACKET__GET) {
	return M_PASS;
    }

    /* make result */
    jutil_iqresult(m->packet->x);
    m->packet->iq = xmlnode_insert_tag_ns(m->packet->x, "query", NULL, NS_DISCO_INFO);

    if (js_trust(m->user, m->packet->from)) {
        for (s = m->user->sessions; s != NULL; s = s->next) {
            /* if(s->priority < 0) continue; *** include all resources I guess */
            if (xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, spools(m->packet->p,"*[@jid='",jid_full(s->id), "']'", m->packet->p), m->si->std_namespace_prefixes), 0) != NULL)
		continue; /* already in the browse result */
            x = xmlnode_insert_tag_ns(m->packet->iq, "item", NULL, NS_BROWSE);
            xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(s->id));
        }
    }

    /* deliver and return */
    jpacket_reset(m->packet);
    js_deliver(m->si, m->packet, m->s);
    return M_HANDLED;
}

/**
 * This function handles a disco info request to a user's JID
 *
 * @param m the mapi structure containing the request
 * @return M_PASS if the request has not been processed, M_HANDLED if the request has been handled
 */
static mreturn mod_disco_user_info(mapi m) {
    xmlnode x = NULL;
    xmlnode vcard = NULL;
    xmlnode_list_item vcard_fn = NULL;
    int is_admin = 0;

    if (jpacket_subtype(m->packet) == JPACKET__SET) {
	js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_NOTALLOWED);
	return M_HANDLED;
    }
    if (jpacket_subtype(m->packet) != JPACKET__GET) {
	return M_PASS;
    }

    /* make result */
    jutil_iqresult(m->packet->x);
    m->packet->iq = xmlnode_insert_tag_ns(m->packet->x, "query", NULL, NS_DISCO_INFO);

    is_admin = acl_check_access(m->si->xc, "showasadmin", m->packet->to);
    x = xmlnode_insert_tag_ns(m->packet->iq, "identity", NULL, NS_DISCO_INFO);
    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "account");
    xmlnode_put_attrib_ns(x, "type", NULL, NULL, is_admin ? "admin" : "registered");

    vcard = xdb_get(m->si->xc, m->user->id, NS_VCARD);
    vcard_fn = xmlnode_get_tags(vcard, "vcard:FN", m->si->std_namespace_prefixes);
    if (vcard_fn != NULL) {
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, is_admin ? spools(m->packet->p, xmlnode_get_data(vcard_fn->node), messages_get(xmlnode_get_lang(m->packet->x), N_(" (administrator)")), m->packet->p) : xmlnode_get_data(vcard_fn->node));
    } else {
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(xmlnode_get_lang(m->packet->x), is_admin ? N_("Administrator") : N_("User")));
    }

    if (vcard != NULL) {
	x = xmlnode_insert_tag_ns(m->packet->iq, "feature", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "var", NULL, NULL, NS_VCARD);
    }

    x = xmlnode_insert_tag_ns(m->packet->iq, "feature", NULL, NS_DISCO_INFO);
    xmlnode_put_attrib_ns(x, "var", NULL, NULL, NS_XMPP_PING);

    x = xmlnode_insert_tag_ns(m->packet->iq, "feature", NULL, NS_DISCO_INFO);
    xmlnode_put_attrib_ns(x, "var", NULL, NULL, NS_BROWSE);

    if (js_trust(m->user, m->packet->from)) {
	x = xmlnode_insert_tag_ns(m->packet->iq, "feature", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "var", NULL, NULL, NS_LAST);
    }

    /* free memory */
    if (vcard != NULL) {
	xmlnode_free(vcard);
	vcard = NULL;
    }

    /* deliver and return */
    jpacket_reset(m->packet);
    js_deliver(m->si, m->packet, m->s);
    return M_HANDLED;
}

/**
 * This callback handles iq stanzas sent to a user's address.
 *
 * Everything but iq stanzas are ignored.
 * Processing of queries in the namespace http://jabber.org/protocol/disco#items are delegated to mod_disco_user_items.
 * Processing of queries in the namespace http://jabber.org/protocol/disco#info are delegated to mod_disco_user_info.
 * No other namespaces are processed.
 *
 * @param m the mapi structure containing the request
 * @param arg unused/ignored
 * @return M_IGNORE if it is no iq stanza, M_PASS if the packet has not been processed, M_HANDLED if the packet has been processed
 */
static mreturn mod_disco_user(mapi m, void *arg) {
    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;
    if (m->packet->to->resource != NULL)
	return M_PASS;
    if (NSCHECK(m->packet->iq, NS_DISCO_ITEMS))
	return mod_disco_user_items(m);
    if (NSCHECK(m->packet->iq, NS_DISCO_INFO))
	return mod_disco_user_info(m);
    return M_PASS;
}

/**
 * init the mod_disco module in the session manager
 *
 * register a callback for stanzas sent to the server's address
 *
 * @param si the session manager instance
 */
extern "C" void mod_disco(jsmi si) {
    js_mapi_register(si, e_SERVER, mod_disco_server, NULL);
    js_mapi_register(si, e_OFFLINE, mod_disco_user, NULL);
}
