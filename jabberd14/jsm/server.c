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
 * --------------------------------------------------------------------------*/

#include "jsm.h"

/**
 * @file server.c
 * @brief handle packets intended for the server: administration, public IQ (agents, etc)
 */

/**
 * handle a packet addressed to the server itself (no node part in the JID)
 *
 * Pass the packet to the modules, that registered for the e_SERVER event. If none
 * of the modules handled the packet, it is bounced as "not-found".
 *
 * @param arg jpq structure containing the session manager instance data and the packet
 */
void js_server_main(void *arg)
{
    int incremented=0;
    jpq q = (jpq)arg;
    udata u = NULL;

    log_debug2(ZONE, LOGT_DELIVER, "THREAD:SERVER received a packet: %s",xmlnode2str(q->p->x));

    /* get the user struct for convience if the sender was local */
    if(js_islocal(q->si, q->p->from))
        u = js_user(q->si, q->p->from, NULL);

    /* don't free the udata while the mapi call is processed */
    if (u != NULL) {
	u->ref++;
	incremented++;
    }

    /* let the modules have a go at the packet; if nobody handles it... */
    if(!js_mapi_call(q->si, e_SERVER, q->p, u, NULL))
        js_bounce_xmpp(q->si,q->p->x,XTERROR_NOTFOUND);

    /* free our lock */
    if (incremented != 0) {
	u->ref--;
    }
}
