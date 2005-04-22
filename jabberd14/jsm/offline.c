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
 * @file offline.c
 * @brief handle packets addressed to existing but offline users
 */

/**
 * function that handles packets that are sent to a valid user account, that has no online session
 *
 * First try if one of the e_OFFLINE modules handles the packet, if not it is bounced as recipient-unavailable
 *
 * @param arg the jpq_struct for this packet (contains the session manager instance data and the packet)
 */
void js_offline_main(void *arg)
{
    jpq q = (jpq)arg;
    udata user;

    /* performace hack, don't lookup the udata again */
    user = (udata)q->p->aux1;

    /* debug message */
    log_debug2(ZONE, LOGT_DELIVER, "THREAD:OFFLINE received %s's packet: %s",jid_full(user->id),xmlnode2str(q->p->x));

    /* let the modules handle the packet */
    if(!js_mapi_call(q->si, e_OFFLINE, q->p, user, NULL))
        js_bounce_xmpp(q->si,q->p->x,XTERROR_RECIPIENTUNAVAIL);

    /* it can be cleaned up now */
    user->ref--;
}
