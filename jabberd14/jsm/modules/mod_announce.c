/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "License").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the License.  You
 * may obtain a copy of the License at http://www.jabber.com/license/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2000 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * --------------------------------------------------------------------------*/
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

    log_debug("mod_announce","handling announce message from %s",jid_full(m->packet->from));

    for(cur = xmlnode_get_firstchild(js_config(m->si,"admin")); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        if(j_strcmp(xmlnode_get_name(cur),"write") == 0 && jid_cmpx(jid_new(xmlnode_pool(m->packet->x),xmlnode_get_data(cur)),m->packet->from,JID_USER|JID_SERVER) == 0)
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


