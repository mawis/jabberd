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

mreturn mod_time_reply(mapi m, void *arg)
{
    time_t t;
    char *tstr;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(!NSCHECK(m->packet->iq,NS_TIME)) return M_PASS;

    /* first, is this a valid request? */
    if(jpacket_subtype(m->packet) != JPACKET__GET)
    {
        js_bounce(m->si,m->packet->x,TERROR_NOTALLOWED);
        return M_HANDLED;
    }

    log_debug("mod_time","handling time query from %s",jid_full(m->packet->from));

    jutil_iqresult(m->packet->x);
    xmlnode_put_attrib(xmlnode_insert_tag(m->packet->x,"query"),"xmlns",NS_TIME);
    jpacket_reset(m->packet);
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"utc"),jutil_timestamp(),-1);
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"tz"),tzname[0],-1);

    /* create nice display time */
    t = time(NULL);
    tstr = ctime(&t);
    tstr[strlen(tstr) - 1] = '\0'; /* cut off newline */
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"display"),tstr,-1);

    js_deliver(m->si,m->packet);

    return M_HANDLED;
}

void mod_time(jsmi si)
{
    js_mapi_register(si,e_SERVER,mod_time_reply,NULL);
}


