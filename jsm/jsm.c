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
 *
 *  main.c -- entry point for the jsm executable
 *
 */

#include "jsm.h"

/*

packet handler
    check for new session auth/reg request, handle seperately
    check master jid hash table for session
    pass to offline thread
    track server names for master "i am" table

*/

typedef void (*modcall)(jsmi si);

result jsm_stat(void *arg)
{
    pool_stat(0);
    return r_DONE;
}

void jsm(instance i, xmlnode x)
{
    jsmi si;
    xmlnode cur;
    modcall module;
    int n;

    log_debug(ZONE,"jsm initializing for section '%s'",i->id);

    /* create and init the jsm instance handle */
    si = pmalloco(i->p, sizeof(_jsmi));
    si->i = i;
    si->p = i->p;
    si->xc = xdb_cache(i); /* getting xdb_* handle and fetching config */
    si->config = xdb_get(si->xc, NULL, jid_new(xmlnode_pool(x),"config@-internal"),"jabberd:jsm:config");
    si->hosts = ghash_create(HOSTS_PRIME,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp); /* XXX hostname hash, make PRIME configurable */
    for(n=0;n<SESSION_WAITERS;n++)
        si->waiting[n] = NULL;
    for(n=0;n<e_LAST;n++)
        si->events[n] = NULL;

    /* start threads */
    pth_spawn(PTH_ATTR_DEFAULT, js_offline_main, (void *)si); /* the thread handling all offline packets */
    pth_spawn(PTH_ATTR_DEFAULT, js_server_main, (void *)si);  /* all traffic to server resources */
    pth_spawn(PTH_ATTR_DEFAULT, js_users_main, (void *)si);   /* free cached user data */

    /* fire up the modules by scanning the attribs on the xml we received */
    for(cur = xmlnode_get_firstattrib(x); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        /* avoid multiple personality complex */
        if(j_strcmp(xmlnode_get_name(cur),"jsm") == 0)
            continue;

        /* vattrib is stored as firstchild on an attrib node */
        if((module = (modcall)xmlnode_get_firstchild(cur)) == NULL)
            continue;

        /* call this module for this session instance */
        log_debug(ZONE,"jsm: loading module %s",xmlnode_get_name(cur));
        (module)(si);
    }

    register_phandler(i, o_DELIVER, js_packet, (void *)si);
    register_beat(5,jsm_stat,NULL);
}
