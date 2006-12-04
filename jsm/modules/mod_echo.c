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
 * @file mod_echo.c
 * @brief reflect messages sent to serverdomain/echo back to the sender (undocumented)
 *
 * This module implements some functionality useful for testing if a server can be reached. It can
 * either be used to check if the local server is still responding or to check if there
 * is connectivity to a remote server. It is something like a Jabber network ping, but it should
 * not be used automatically as it will generate more load on the servers than an ICMP ping.
 *
 * All messages to a resource starting with "echo" are processed. If you are using this service,
 * please use always the resource "echo" (in small letters) and do not rely on the fact
 * that every resource starting with "echo" (ignoring case) will generate a reflected message.
 * (Resources are case-sensitive in XMPP!)
 */

/**
 * handle messages sent to the session manager's address
 *
 * Everything but message stanzas are ignored. Only messages to a resource starting with "echo" are
 * processed.
 *
 * @param m the mapi structure containing the message
 * @param arg unused/ignored
 * @return M_IGNORE if the stanza is no message, M_PASS if the message has not been processed, M_HANDLED if the message has been handled
 */
mreturn mod_echo_reply(mapi m, void *arg) {
    if (m->packet->type != JPACKET_MESSAGE)
	return M_IGNORE;

    /* first, is this a valid request? */
    if (m->packet->to->resource == NULL || strncasecmp(m->packet->to->resource, "echo", 4) != 0)
	return M_PASS;

    log_debug2(ZONE, LOGT_DELIVER, "handling echo request from %s", jid_full(m->packet->from));

    xmlnode_put_attrib_ns(m->packet->x, "from", NULL, NULL, jid_full(m->packet->to));
    xmlnode_put_attrib_ns(m->packet->x, "to", NULL, NULL, jid_full(m->packet->from));
    jpacket_reset(m->packet);
    js_deliver(m->si, m->packet, NULL);

    return M_HANDLED;
}

/**
 * init the mod_echo module in the session manager
 *
 * registers a callback to be called on messages sent to the session manager's address
 *
 * @param si the session manager instance
 */
void mod_echo(jsmi si) {
    js_mapi_register(si, e_SERVER, mod_echo_reply, NULL);
}
