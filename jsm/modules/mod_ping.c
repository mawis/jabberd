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
 * @file mod_ping.c
 * @brief implements XEP-0199 - XMPP Ping
 *
 * This module allows the administrator to block some user-names from being registered
 * by users.
 */

/**
 * handle disco info query to the server address, add our feature
 */
static mreturn mod_ping_server_disco_info(mapi m) {
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
    xmlnode_put_attrib_ns(feature, "var", NULL, NULL, NS_XMPP_PING);

    return M_PASS;
}

/**
 * handle pings
 */
static mreturn mod_ping_server_ping(mapi m) {
    /* only get */
    if (jpacket_subtype(m->packet) != JPACKET__SET)
	return M_PASS;

    /* build the result IQ */
    jutil_iqresult(m->packet->x);
    jpacket_reset(m->packet);
    js_deliver(m->si, m->packet);

    return M_HANDLED;
}

/**
 * handle iq queries addressed to the server
 *
 * all but iq stanzas are ignored, only relevant namespaces are handled
 *
 * redirects processing to the right handler for the namespace
 *
 * @param m the mapi structure
 * @param arg time_t timestampe when the server was started
 * @return M_IGNORE if the stanza is no iq, M_PASS or M_HANDLED else
 */
static mreturn mod_ping_server(mapi m, void *arg) {
    /* sanity check */
    if (m == NULL || m->packet == NULL)
	return M_PASS;

    /* only handle iqs */
    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;

    if (NSCHECK(m->packet->iq, NS_DISCO_INFO))
	return mod_ping_server_disco_info(m);

    if (NSCHECK(m->packet->iq, NS_XMPP_PING))
	return mod_ping_server_ping(m);

    return M_PASS;
}

/**
 * init the module, register callbacks
 *
 * registers mod_register_new() as the callback for new user's registration requests,
 * registers mod_register_server() as the callback for existing user's registration requests (unregister and change password)
 *
 * @param si the session manager instance
 */
void mod_ping(jsmi si) {
    log_debug2(ZONE, LOGT_INIT, "mod_ping starting up");
    js_mapi_register(si, e_SERVER, mod_ping_server, NULL);
}
