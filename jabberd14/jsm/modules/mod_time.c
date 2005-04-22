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
 * @file mod_time.c
 * @brief implement the Entity Time protocol (JEP-0090)
 *
 * The protocol implemented by this module can be used the query the current time on the server.
 */

/**
 * callback that handles iq stanzas containing a query in the jabber:x:time namespace
 *
 * ignores stanzas of other types, does not process iq stanzas containing other namespaces or addressed to a reseouce of the server
 *
 * sends back replies to jabber:x:time queries.
 *
 * @param m the mapi structure
 * @param arg unused/ignored
 * @return M_IGNORED if not a iq stanza, M_PASS if other namespace or sent to a resource of the server, M_HANDLED else
 */
mreturn mod_time_reply(mapi m, void *arg)
{
    time_t t;
    char *tstr;
    struct tm *tmd;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(!NSCHECK(m->packet->iq,NS_TIME) || m->packet->to->resource != NULL) return M_PASS;

    /* first, is this a valid request? */
    if(jpacket_subtype(m->packet) != JPACKET__GET)
    {
        js_bounce_xmpp(m->si,m->packet->x,XTERROR_NOTALLOWED);
        return M_HANDLED;
    }

    log_debug2(ZONE, LOGT_DELIVER, "handling time query from %s",jid_full(m->packet->from));

    jutil_iqresult(m->packet->x);
    xmlnode_put_attrib(xmlnode_insert_tag(m->packet->x,"query"),"xmlns",NS_TIME);
    jpacket_reset(m->packet);
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"utc"),jutil_timestamp(),-1);

    /* create nice display time */
    t = time(NULL);
    tstr = ctime(&t);
    tstr[strlen(tstr) - 1] = '\0'; /* cut off newline */
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"display"),tstr,-1);
    tzset();
    tmd = localtime(&t);

#ifdef TMZONE
    /* some platforms don't have tzname I guess */
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"tz"),tmd->tm_zone,-1);
#else
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"tz"),tzname[0],-1);
#endif

    js_deliver(m->si,m->packet);

    return M_HANDLED;
}

/**
 * init this module
 *
 * register mod_time_reply() as a callback for stanzas sent to the server's address
 *
 * @param si the session manager instance
 */
void mod_time(jsmi si)
{
    js_mapi_register(si,e_SERVER,mod_time_reply,NULL);
}


