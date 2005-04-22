/* --------------------------------------------------------------------------
 *
 *  jabberd 1.4.4 GPL - XMPP/Jabber server implementation
 *
 *  Copyrights
 *
 *  Portions created by or assigned to Jabber.com, Inc. are
 *  Copyright (C) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 *  information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 *  Portions Copyright (C) 1998-1999 Jeremie Miller.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  Special exception for linking jabberd 1.4.4 GPL with OpenSSL:
 *
 *  In addition, as a special exception, you are allowed to link the code
 *  of jabberd 1.4.4 GPL with the OpenSSL library (or with modified versions
 *  of OpenSSL that use the same license as OpenSSL), and distribute linked
 *  combinations including the two. You must obey the GNU General Public
 *  License in all respects for all of the code used other than OpenSSL.
 *  If you modify this file, you may extend this exception to your version
 *  of the file, but you are not obligated to do so. If you do not wish
 *  to do so, delete this exception statement from your version.
 *
 * --------------------------------------------------------------------------*/

/* * this was taken from wpjabber cvs - thanks guys :) */

#include "jsm.h"

/**
 * @file mod_disco.c
 * @brief implement handling of service discovery (JEP-0030) in the session manager
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
mreturn mod_disco_server_info(mapi m, void *arg)
{
    xmlnode query, identity, disco;

    if((xmlnode_get_attrib(m->packet->x,"node")) != NULL) return M_PASS;
        
    log_debug2(ZONE, LOGT_DELIVER, "handling disco#info query");

    /* config get */
    disco = js_config(m->si,"disco");

    /* build the result IQ */		
    query = xmlnode_insert_tag(jutil_iqresult(m->packet->x),"query");
    xmlnode_put_attrib(query,"xmlns",NS_DISCO_INFO);

    /* if config */
    identity = NULL;
    if (disco != NULL) 
	  identity = xmlnode_get_tag(disco,"identity");
    
    /* if bad config, put identity */
    if (disco == NULL || identity == NULL){
	  identity = xmlnode_insert_tag(query,"identity");
	  xmlnode_put_attrib(identity,"category","services");
	  xmlnode_put_attrib(identity,"type","jabber");
	  xmlnode_put_attrib(identity,"name", xmlnode_get_data(js_config(m->si,"vCard/FN"))); 
    }
    
    /* put disco info if exist */
    if (disco != NULL) 
	  xmlnode_insert_node(query, xmlnode_get_firstchild(disco));

    jpacket_reset(m->packet);
    js_deliver(m->si,m->packet);

    return M_HANDLED;
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
mreturn mod_disco_server_items(mapi m, void *arg)
{
  xmlnode browse, query, cur;
  
  if((xmlnode_get_attrib(m->packet->x,"node")) != NULL) return M_PASS;

  /* config get */        
  if((browse = js_config(m->si,"browse")) == NULL)
	return M_PASS;
  
  log_debug2(ZONE, LOGT_DELIVER, "handling disco#items query");

  /* build the result IQ */
  query = xmlnode_insert_tag(jutil_iqresult(m->packet->x),"query");
  xmlnode_put_attrib(query,"xmlns",NS_DISCO_ITEMS);

  /* copy in the configured services */
  for(cur = xmlnode_get_firstchild(browse);
	  cur != NULL;
	  cur = xmlnode_get_nextsibling(cur)){
	xmlnode item;
	const char *jid,*name;

	jid = xmlnode_get_attrib(cur,"jid");
	if (!jid) continue;

	item = xmlnode_insert_tag(query,"item");
	xmlnode_put_attrib(item,"jid",jid);
	name = xmlnode_get_attrib(cur,"name");
	if (name) xmlnode_put_attrib(item,"name",name);
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
mreturn mod_disco_server(mapi m, void *arg)
{
    if (m->packet->type != JPACKET_IQ) return M_IGNORE;
    if (jpacket_subtype(m->packet) != JPACKET__GET) return M_PASS;
	if (m->packet->to->resource != NULL) return M_PASS;
    if (NSCHECK(m->packet->iq,NS_DISCO_ITEMS)) return mod_disco_server_items(m,arg);
    if (NSCHECK(m->packet->iq,NS_DISCO_INFO)) return mod_disco_server_info(m,arg);
    return M_PASS;
}

/**
 * init the mod_disco module in the session manager
 *
 * register a callback for stanzas sent to the server's address
 *
 * @param si the session manager instance
 */
void mod_disco(jsmi si)
{
    js_mapi_register(si,e_SERVER,mod_disco_server,NULL);
}

