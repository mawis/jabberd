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

/* jsm initialization for a static build */

void    mod_echo();
void    mod_roster();
void    mod_time();
void    mod_vcard();
void    mod_version();
void    mod_announce();
void    mod_agents();
void    mod_admin();
void    mod_private();
void    mod_filter();
void    mod_presence();
void    mod_auth_plain();
void    mod_auth_digest();
void    mod_auth_0k();
void    mod_register();
void    mod_log();

result jsm_static_config(instance i, xmlnode x, void *arg)
{
    jsmi si;
    int n;

    if(i == NULL) return r_DONE;

    log_debug(ZONE,"jsm initializing for section '%s'",i->id);

    /* create and init the jsm instance handle */
    si = pmalloco(i->p, sizeof(_jsmi));
    si->i = i;
    si->p = i->p;
    si->xc = xdb_cache(i); /* getting xdb_* handle and fetching config */
    si->config = xmlnode_dup(x);
    si->hosts = ghash_create(j_atoi(xmlnode_get_tag_data(si->config,"maxhosts"),HOSTS_PRIME),(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);
    for(n=0;n<e_LAST;n++)
        si->events[n] = NULL;

    /* start threads */
    pth_spawn(PTH_ATTR_DEFAULT, js_offline_main, (void *)si); /* the thread handling all offline packets */
    pth_spawn(PTH_ATTR_DEFAULT, js_server_main, (void *)si);  /* all traffic to server resources */
    pth_spawn(PTH_ATTR_DEFAULT, js_users_main, (void *)si);   /* free cached user data */

    /* fire up the modules statically */
    mod_echo(si);
    mod_roster(si);
    mod_time(si);
    mod_vcard(si);
    mod_version(si);
    mod_announce(si);
    mod_agents(si);
    mod_admin(si);
    mod_private(si);
    mod_filter(si);
    mod_presence(si);
    mod_auth_plain(si);
    mod_auth_digest(si);
    mod_auth_0k(si);
    mod_register(si);
    mod_log(si);

    pool_cleanup(i->p, jsm_shutdown, (void*)si);
    register_phandler(i, o_DELIVER, js_packet, (void *)si);

    return r_DONE;
}

void jsm_static(void)
{
    log_debug(ZONE,"jsm loading statically");
    register_config("jsm",jsm_static_config,NULL);
}
