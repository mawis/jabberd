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

void jsm(instance i, xmlnode x)
{
    jsmi si;
    xmlnode cur;
    char *name;
    void (*module)(jsmi si);
    int n;

    log_debug(NULL,"jsm initializing for section '%s'",i->id);

    /* create and init the jsm instance handle */
    si = palloco(i->p, sizeof(_jsmi));
    si->i = i;
    si->xc = xdb_cache(i); /* getting xdb_* handle and fetching config */
    si->config = xmlnode_get_firstchild(xdb_get(si->xc, NULL, jid_new(xmlnode_pool(x),"config@-internal"),"test"));
    for(n=0;i<SESSION_WAITERS;n++)
        si->waiting[n] = NULL;

    /* start threads */
    pth_spawn(attr, js_offline_main, (void *)si); /* the thread handling all offline packets */
    pth_spawn(attr, js_server_main, (void *)si);  /* all traffic to server resources */
    pth_spawn(attr, js_users_main, (void *)si);   /* free cached user data */

    /* fire up the modules */
    for(cur = xmlnode_get_firstchild(cur); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        if((name = xmlnode_get_name(cur)) == NULL)
            continue;

        module = (void (*module)(jsmi si))xmlnode_get_vattrib(cur,name);
        if(module == NULL)
            continue;

        /* call this module for this session instance */
        (module)(si);
    }
}
