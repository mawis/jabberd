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
 * @file mod_log.c
 * @brief write a log entry if a session ends, optionally forward all messages to a configured entity
 *
 * This module only logs ending sessions. (It expects that the beginning of a session is logged
 * by the client connection manager which is able to log the IP address if required as well.)
 *
 * The module can be configured to forward all message stanzas to a configured entity on the router.
 * The message forwarding is configured using the <archive/> element containing a <service/> element
 * for each destination having the destination's address as the CDATA node in it. The messages are
 * then forwarded using a <route/> element, therefore you cannot forward messages to entities
 * not connected to your router (you cannot use s2s).
 *
 * The message forwarding functionallity is disabled if there is no <archive/> element in the
 * configuration of the session manager.
 *
 * mod_log should be the last in the list of modules in the session manager.
 */

/**
 * logs the characteristics of a closed session (when it started, stanzas received, stanzas sent, resource)
 *
 * @param m the mapi structure
 * @param arg unused/ignored
 * @return always M_PASS
 */
mreturn mod_log_session_end(mapi m, void *arg)
{
    time_t t = time(NULL);

    log_debug2(ZONE, LOGT_SESSION, "creating session log entry");

    log_record(jid_full(m->user->id), "session", "end", "%d %d %d %s", (int)(t - m->s->started), m->s->c_in, m->s->c_out, m->s->res);

    return M_PASS;
}

/**
 * Forward message stanzas to the list of configured archiving services
 *
 * Everything but message stanzas are ignored.
 *
 * @param m the mapi structure containing the message to forward
 * @param arg list of destination JIDs
 * @return always M_PASS
 */
mreturn mod_log_archiver(mapi m, void* arg)
{
    jid svcs = (jid)arg;
    xmlnode x;
    
    if(m->packet->type != JPACKET_MESSAGE) return M_IGNORE;

    log_debug2(ZONE, LOGT_DELIVER, "archiving message");

    /* get a copy wrapped w/ a route and stamp it w/ a type='archive' (why not?) */
    x = xmlnode_wrap(xmlnode_dup(m->packet->x), "route");
    xmlnode_put_attrib(x,"type","archive");

    /* if there's more than one service, copy to the others */
    for(;svcs->next != NULL; svcs = svcs->next)
    {
        xmlnode_put_attrib(x, "to", jid_full(svcs));
        deliver(dpacket_new(xmlnode_dup(x)), NULL);
    }

    /* send off to the last (or only) one */
    xmlnode_put_attrib(x, "to", jid_full(svcs));
    deliver(dpacket_new(x), NULL);

    return M_PASS;
}

/**
 * callback that gets notified if a new session is establisched
 *
 * If message forwarding is enabled this callback will register the mod_log_archiver callback for incoming and outgoing messages.
 *
 * In any case it will register the mod_log_session_end callback for ending sessions
 *
 * @param m the mapi structure
 * @param arg NULL if message forwarding is disabled, pointer to a list of destination JIDs otherwise
 * @return always M_PASS
 */
mreturn mod_log_session(mapi m, void *arg)
{
    jid svcs = (jid)arg;

    if(svcs != NULL)
    {
        js_mapi_session(es_IN, m->s, mod_log_archiver, svcs);
        js_mapi_session(es_OUT, m->s, mod_log_archiver, svcs);
    }

    /* we always generate log records, if you don't like it, don't use mod_log :) */
    js_mapi_session(es_END, m->s, mod_log_session_end, NULL);

    return M_PASS;
}

/**
 * init the mod_log in the session manager
 *
 * build the list of forwarding destinations for the message logging functionallity
 * (using the <service/> elements inside the <archive/> element in the configuration
 * of the session manager)
 *
 * register mod_log_session as callback for new sessions
 *
 * @param si the session manager instance
 */
void mod_log(jsmi si)
{
    xmlnode cfg = js_config(si,"archive");
    jid svcs = NULL;

    log_debug2(ZONE, LOGT_INIT, "mod_log init");

    /* look for archiving service too */
    for(cfg = xmlnode_get_firstchild(cfg); cfg != NULL; cfg = xmlnode_get_nextsibling(cfg))
    {
        if(xmlnode_get_type(cfg) != NTYPE_TAG || j_strcmp(xmlnode_get_name(cfg),"service") != 0) continue;
        if(svcs == NULL)
            svcs = jid_new(si->p,xmlnode_get_data(cfg));
        else
            jid_append(svcs,jid_new(si->p,xmlnode_get_data(cfg)));
    }

    js_mapi_register(si,e_SESSION, mod_log_session, (void*)svcs);
}
