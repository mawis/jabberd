/*
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
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *  Jabber
 *  Copyright (C) 1998-1999 The Jabber Team http://jabber.org/
 */

#include "jsm.h"

mreturn mod_archive_redirect(mapi m, void* arg)
{
    char* redirecthost = (char*)arg;
    
    /* Ensure that we only archive messages */
    if (m->packet->type != JPACKET_MESSAGE) 
        return M_IGNORE;

    /* Transmit the message as xdb message to redirect host */
    log_debug(ZONE, "redirecting to %s: %s", redirecthost, xmlnode2str(m->packet->x));

    xdb_set(m->si->xc, m->user->id->server, jid_new(m->packet->p, redirecthost), "jabber:x:archive", xmlnode_dup(m->packet->x));
 
	log_debug(ZONE, "done");
    return M_PASS;
}

mreturn mod_archive_session(mapi m, void *arg)
{
    /* Setup a callback for outgoing _and_ incoming packets */
    js_mapi_session(es_OUT,m->s,mod_archive_redirect,arg);
    js_mapi_session(es_IN, m->s,mod_archive_redirect,arg);
    return M_PASS;
}

void mod_archive(jsmi si)
{
    /* Load configuration info */
    xmlnode cfg = js_config(si, "archiveid");
    if ((cfg != NULL) && (xmlnode_get_data(cfg) != NULL))
    {
        js_mapi_register(si, e_SESSION, mod_archive_session, xmlnode_get_data(cfg));
    }
}


