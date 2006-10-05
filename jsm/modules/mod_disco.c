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

/* * this was taken from wpjabber cvs - thanks guys :) */

#include "jsm.h"

/**
 * @file mod_disco.c
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
mreturn mod_disco_server_info(mapi m, void *arg) {
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
    identity = js_config(m->si, "disco-info:disco/disco-info:identity");

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
	identity = xmlnode_insert_tag_ns(m->additional_result->iq, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(identity, "category", NULL, NULL, "server");
	xmlnode_put_attrib_ns(identity, "type", NULL, NULL, "im");
	xmlnode_put_attrib_ns(identity, "name", NULL, NULL, xmlnode_get_data(js_config(m->si, "vcard:vCard/vcard:FN")));
    }

    /* other modules might add other information to the result */
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
mreturn mod_disco_server_items(mapi m, void *arg) {
  xmlnode browse, query, cur;
  
  if ((xmlnode_get_attrib_ns(m->packet->iq, "node", NULL)) != NULL)
      return M_PASS;

  /* config get */        
  if ((browse = js_config(m->si,"browse:browse")) == NULL)
	return M_PASS;
  
  log_debug2(ZONE, LOGT_DELIVER, "handling disco#items query");

  /* build the result IQ */
  query = xmlnode_insert_tag_ns(jutil_iqresult(m->packet->x), "query", NULL, NS_DISCO_ITEMS);

  /* copy in the configured services */
  for (cur = xmlnode_get_firstchild(browse); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
	xmlnode item;
	const char *jid,*name;

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
    xmlnode_put_attrib_ns(item, "node", NULL, NULL, "online users");
  }

  jpacket_reset(m->packet);
  js_deliver(m->si,m->packet);
  
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
mreturn mod_disco_server(mapi m, void *arg) {
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
 * init the mod_disco module in the session manager
 *
 * register a callback for stanzas sent to the server's address
 *
 * @param si the session manager instance
 */
void mod_disco(jsmi si) {
    js_mapi_register(si, e_SERVER, mod_disco_server, NULL);
}
