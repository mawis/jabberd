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
 * main.c - entry point for jsm.so
 * --------------------------------------------------------------------------*/
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
    si->config = xdb_get(si->xc, NULL, jid_new(xmlnode_pool(x),"config@-internal"),"jabber:config:jsm");
    si->hosts = ghash_create(j_atoi(xmlnode_get_tag_data(si->config,"maxhosts"),HOSTS_PRIME),(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);
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
