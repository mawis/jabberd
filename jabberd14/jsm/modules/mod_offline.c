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

/* THIS MODULE will soon be depreciated by mod_filter */

/* mod_offline must go before mod_presence */

/* get the user's offline options */
xmlnode mod_offline_get(udata u)
{
    xmlnode ret;

    log_debug("mod_offline","getting %s's offline options",u->user);

    /* get the existing options */
    ret = xdb_get(u->si->xc, u->id->server, u->id, NS_OFFLINE);
    if(ret == NULL)
    {
        log_debug("mod_offline","creating options container");
        ret = xmlnode_new_tag("offline");
        xmlnode_put_attrib(ret,"xmlns",NS_OFFLINE);
    }

    return ret;
}

/* handle an offline message */
mreturn mod_offline_message(mapi m)
{
    xmlnode opts, cur;
    int max = 0;
    session top;
    int ret = M_PASS;

    /* if there's an existing session, just give it to them */
    if((top = js_session_primary(m->user)) != NULL)
    {
        js_session_to(top,m->packet);
        return M_HANDLED;
    }

    switch(jpacket_subtype(m->packet))
    {
    case JPACKET__NONE:
    case JPACKET__ERROR:
    case JPACKET__CHAT:
        break;
    default:
        return M_PASS;
    }

    log_debug("mod_offline","handling message for %s",m->user->user);

    /* get user offline options */
    opts = mod_offline_get(m->user);

    /* ugly, max offline messages stored is 100, finish mod_filter right away */
    for(cur = xmlnode_get_firstchild(opts); cur != NULL; cur = xmlnode_get_nextsibling(cur)) max++;
    if(max < 100)
    {
        jutil_delay(m->packet->x,"Offline Storage");
        xmlnode_insert_tag_node(opts,m->packet->x);
        if(!xdb_set(m->si->xc, m->user->id->server, m->user->id, NS_OFFLINE, opts))
        {
            xmlnode_free(m->packet->x);
            ret = M_HANDLED;
        }
    }

    xmlnode_free(opts);
    return ret;
}

/* just breaks out to our message/presence offline handlers */
mreturn mod_offline_handler(mapi m, void *arg)
{
    if(m->packet->type == JPACKET_MESSAGE) return mod_offline_message(m);

    return M_IGNORE;
}

/* watches for when the user is available and sends out offline messages */
void mod_offline_out_available(mapi m)
{
    xmlnode opts, cur;

    log_debug("mod_offline","avability established, check for messages");

    opts = mod_offline_get(m->user);

    /* check for msgs */
    for(cur = xmlnode_get_firstchild(opts); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        if(j_strcmp(xmlnode_get_name(cur),"message") != 0) continue;

        js_session_to(m->s,jpacket_new(xmlnode_dup(cur)));
        xmlnode_hide(cur);
    }

    /* messages are gone, save the new sun-dried opts container */
    xdb_set(m->si->xc, m->user->id->server, m->user->id, NS_OFFLINE, opts); /* can't do anything if this fails anyway :) */
    xmlnode_free(opts);
}

mreturn mod_offline_out(mapi m, void *arg)
{
    if(m->packet->type != JPACKET_PRESENCE) return M_IGNORE;

    if(jpacket_subtype(m->packet) == JPACKET__AVAILABLE && m->s->priority < 0 && m->packet->to == NULL)
        mod_offline_out_available(m);

    return M_PASS;
}

/* sets up the per-session listeners */
mreturn mod_offline_session(mapi m, void *arg)
{
    log_debug(ZONE,"session init");

    js_mapi_session(es_OUT, m->s, mod_offline_out, NULL);

    return M_PASS;
}

void mod_offline(jsmi si)
{
    log_debug("mod_offline","init");
    js_mapi_register(si,e_OFFLINE, mod_offline_handler, NULL);
    js_mapi_register(si,e_SESSION, mod_offline_session, NULL);
}

