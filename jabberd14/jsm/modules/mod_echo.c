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

mreturn mod_echo_reply(mapi m, void *arg)
{
    if(m->packet->type != JPACKET_MESSAGE) return M_IGNORE;

    /* first, is this a valid request? */
    if(m->packet->to->resource == NULL || strncasecmp(m->packet->to->resource,"echo",4) != 0) return M_PASS;

    log_debug("mod_echo","handling echo request from %s",jid_full(m->packet->from));

    xmlnode_put_attrib(m->packet->x,"from",jid_full(m->packet->to));
    xmlnode_put_attrib(m->packet->x,"to",jid_full(m->packet->from));
    jpacket_reset(m->packet);
    js_deliver(m->si,m->packet);

    return M_HANDLED;
}

void mod_echo(jsmi si)
{
    js_mapi_register(si,e_SERVER,mod_echo_reply,NULL);
}


