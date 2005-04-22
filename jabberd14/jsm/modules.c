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

#include "jsm.h"

/**
 * @file modules.c
 * @brief jsm module API
 */

/**
 * let a module register a new callback for a specified phase
 *
 * Takes a function pointer and argument and stores them in the
 * callback list for the event e
 *
 * @param si the session manager instance data
 * @param e the event type for which to register the callback
 * @param c pointer to the function, that gets registered
 * @param arg an argument to pass to c when it is called
 */
void js_mapi_register(jsmi si, event e, mcall c, void *arg)
{
    mlist newl, curl;

    if(c == NULL || si == NULL || e >= e_LAST) return;

    /* create a new mlist record for the call back */
    newl = pmalloc(si->p, sizeof(_mlist));
    newl->c = c;
    newl->arg = arg;
    newl->mask = 0x00;
    newl->next = NULL;

    /* append */
    if (si->events[e] == NULL) {
        si->events[e] = newl;
    } else {
	/* spin to end of list */
        for (curl = si->events[e]; curl->next != NULL; curl = curl->next)
	    /* do nothing special */;
        curl->next = newl;
    }
    log_debug2(ZONE, LOGT_INIT, "mapi_register %d %X",e,newl);
}

/**
 * let a module register a new callback for a specified phase on a session
 *
 * This is like js_mapi_register except that the call only applies to the specified session.
 *
 * @param e the event type for which to register the callback
 * @param s the session for which the callback should be registered
 * @param c pointer to the function, that gets registered
 * @param arg an argument to pass to c when it is called
 */
void js_mapi_session(event e, session s, mcall c, void *arg)
{
    mlist newl, curl;

    if(c == NULL || s == NULL || e >= es_LAST) return;

    /* create item for the call list */
    newl = pmalloco(s->p, sizeof(_mlist));
    newl->c = c;
    newl->arg = arg;
    newl->mask = 0x00;
    newl->next = NULL;

    /* append */
    if(s->events[e] == NULL)
    {
        s->events[e] = newl;
    }else{
        for(curl = s->events[e]; curl->next != NULL; curl = curl->next); /* spin to end of list */
        curl->next = newl;
    }

    log_debug2(ZONE, LOGT_INIT, "mapi_register_session %d %X",e,newl);
}

/**
 * call all the module callbacks for a phase
 *
 * Addes callbacks to the ignore mask for a given packet type if they return M_IGNORE.
 *
 * @param si the session manager instance data
 * @param e call the modules for which event type
 * @param packet the packet being processed, may be NULL
 * @param user the user data for the current session (or the sender for e_SERVER if it is local), may be NULL
 * @param s the session for which to call the event, may be NULL
 * @return 1 if the call was handled by a module, 0 if it wasn't handled
 */
int js_mapi_call(jsmi si, event e, jpacket packet, udata user, session s) {
    mlist l;
    _mapi m;		/* mapi structure to be passed to the call back */

    log_debug2(ZONE, LOGT_EXECFLOW, "mapi_call %d",e);

    /* this is a session event */
    if(si == NULL && s != NULL) {
        si = s->si;
        l = s->events[e];
    } else {
        l = si->events[e];
    }

    /* fill in the mapi structure */
    m.si = si;
    m.e = e;
    m.packet = packet;
    m.user = user;
    m.s = s;

    /* traverse the list of call backs */
    for (;l != NULL; l = l->next) {
        /* skip call-back if the packet type mask matches */
        if(packet != NULL && (packet->type & l->mask) == packet->type)
	    continue;
	log_debug2(ZONE, LOGT_EXECFLOW, "MAPI %X",l);
	
        /* call the function and handle the result */
        switch((*(l->c))(&m, l->arg)) {
	    /* this module is ignoring this packet->type */
	    case M_IGNORE:
		/* add the packet type to the mask */
		l->mask |= packet->type;
		break;
	    /* this module handled the packet */
	    case M_HANDLED:
		return 1;
	    default:
		;
        }
    }

    log_debug2(ZONE, LOGT_EXECFLOW, "mapi_call returning unhandled");

    /* if we got here, no module handled the packet */
    return 0;
}
