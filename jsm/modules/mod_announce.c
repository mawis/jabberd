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

int _mod_announce_avail(void *arg, const void *key, void *data)
{
    xmlnode msg = (xmlnode)arg;
    udata u = (udata)data;
    session s = js_session_primary(u);

    if(s == NULL) return 1;

    msg = xmlnode_dup(msg);
    xmlnode_put_attrib(msg,"to",jid_full(s->id));
    js_session_to(s,jpacket_new(msg));

    return 1;
}

/* callback for walking the host hash tree */
int _mod_announce_avail_hosts(void *arg, const void *key, void *data)
{
    HASHTABLE ht = (HASHTABLE)data;

    ghash_walk(ht,_mod_announce_avail,arg);

    return 1;
}

mreturn mod_announce_avail(jsmi si, jpacket p)
{
    xmlnode_put_attrib(p->x,"from",p->to->server);
    ghash_walk(si->hosts,_mod_announce_avail_hosts,(void *)(p->x));
    return M_HANDLED;
}

mreturn mod_announce_all(jsmi si, jpacket p)
{
    /* store the message in XDB, and feed to all online.
     * mark off users that got it, feed to new ones that come online
     * have a timeout/lifetime on the announcement
     */
    return M_PASS;
}

mreturn mod_announce_dispatch(mapi m, void *arg)
{
    int admin = 0;
    xmlnode cur;

    if(m->packet->type != JPACKET_MESSAGE) return M_IGNORE;
    if(j_strncmp(m->packet->to->resource,"announce/",9) != 0) return M_PASS;

    /* ensure that the user is local */
    if(js_config(m->si,"admin") == NULL || m->packet->from == NULL || m->packet->from->user == NULL || ghash_get(m->si->hosts, m->packet->from->server) == NULL)
    {
        js_bounce(m->si,m->packet->x,TERROR_NOTALLOWED);
        return M_HANDLED;
    }

    log_debug("mod_announce","handling announce message from %s",jid_full(m->packet->from));

    for(cur = xmlnode_get_firstchild(js_config(m->si,"admin")); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        if(j_strcmp(xmlnode_get_name(cur),"write") == 0 && xmlnode_get_data(cur) != NULL && strcasecmp(m->packet->from->user,xmlnode_get_data(cur)) == 0)
            admin = 1;
    }

    if(admin)
    {
        if(j_strncmp(m->packet->to->resource,"announce/online",15) == 0) return mod_announce_avail(m->si, m->packet);
        if(j_strncmp(m->packet->to->resource,"announce/all",12) == 0) return mod_announce_all(m->si, m->packet);
    }

    js_bounce(m->si,m->packet->x,TERROR_NOTALLOWED);
    return M_HANDLED;
}

void mod_announce(jsmi si)
{
    js_mapi_register(si,e_SERVER,mod_announce_dispatch,NULL);
}


