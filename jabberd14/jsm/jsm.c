/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "JOSL").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the JOSL. You
 * may obtain a copy of the JOSL at http://www.jabber.org/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the JOSL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the JOSL
 * for the specific language governing rights and limitations under the
 * JOSL.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 or later (the "GPL"), in which case
 * the provisions of the GPL are applicable instead of those above.  If you
 * wish to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the JOSL,
 * indicate your decision by deleting the provisions above and replace them
 * with the notice and other provisions required by the GPL.  If you do not
 * delete the provisions above, a recipient may use your version of this file
 * under either the JOSL or the GPL. 
 * 
 * 
 * main.c - entry point for jsm.so
 * --------------------------------------------------------------------------*/
#include "jsm.h"

/**
 * @file jsm.c
 * @brief main part of the jsm (Jabberd session manager) module
 *
 * This file contains the function that is called by jabberd to load this
 * module jsm() and we load the modules, that are plugged in the session
 * manager
 */

/**
 * template for the load function of jsm modules
 *
 * @param si the mapi, that should be used by the modules to interact with jsm
 */
typedef void (*modcall)(jsmi si);

/*
result jsm_stat(void *arg)
{
    pool_stat(0);
    return r_DONE;
}
*/

/**
 * xhash walker function to signal all sessions the server shutdown
 *
 * @param h the hashtable containing all users of a host
 * @param key the user
 * @param data the user's data
 * @param arg unused/ignored
 */
void __jsm_shutdown(xht h, const char *key, void *data, void *arg)
{
    udata u = (udata)data;	/* cast the pointer into udata */
    session cur;

    for(cur = u->sessions; cur != NULL; cur = cur->next)
    {
        js_session_end(cur, "JSM shutdown");
    }
}


/**
 * xhash walker function over all hosts of the session manager,
 * used to signal all sessions the server shutdown
 *
 * @param h the hashtable containing all hosts
 * @param key the host
 * @param data the table of users on this host
 * @param arg unused/ignored
 */
void _jsm_shutdown(xht h, const char *key, void *data, void *arg)
{
    xht ht = (xht)data;

    log_debug2(ZONE, LOGT_CLEANUP, "JSM SHUTDOWN: deleting users for host %s",(char*)key);

    xhash_walk(ht,__jsm_shutdown,NULL);

    xhash_free(ht);
}

/**
 * callback function where jabberd signals the shutdown of the server
 *
 * @param our instance internal jsm data
 */
void jsm_shutdown(void *arg)
{
    jsmi si = (jsmi)arg;

    log_debug2(ZONE, LOGT_CLEANUP, "JSM SHUTDOWN: Begining shutdown sequence");
    js_mapi_call(si, e_SHUTDOWN, NULL, NULL, NULL);

    xhash_walk(si->hosts,_jsm_shutdown,arg);
    xhash_free(si->hosts);
    xmlnode_free(si->config);
}

/**
 * startup the jsm module, register the jsm modules in jsm
 *
 * @param i the instance we are in jabberd
 * @param x the <load/> module that instructed the moduleloader to load us
 */
void jsm(instance i, xmlnode x)
{
    jsmi si;
    xmlnode cur;
    modcall module;
    int n;

    log_debug2(ZONE, LOGT_INIT, "jsm initializing for section '%s'",i->id);

    /* create and init the jsm instance handle */
    si = pmalloco(i->p, sizeof(_jsmi));
    si->i = i;
    si->p = i->p;
    si->xc = xdb_cache(i); /* getting xdb_* handle and fetching config */
    si->config = xdb_get(si->xc, jid_new(xmlnode_pool(x),"config@-internal"),"jabber:config:jsm");
    si->hosts = xhash_new(j_atoi(xmlnode_get_tag_data(si->config,"maxhosts"),HOSTS_PRIME));
    for(n=0;n<e_LAST;n++)
        si->events[n] = NULL;

    /* initialize globally trusted ids */
    for(cur = xmlnode_get_firstchild(xmlnode_get_tag(si->config,"admin")); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
	char *tagname = NULL;
	jid newjid = NULL;

        if(xmlnode_get_type(cur) != NTYPE_TAG) continue;

	tagname = xmlnode_get_name(cur);

	if (j_strcmp(tagname, "read") != 0 && j_strcmp(tagname, "write") != 0)
	    continue;

	newjid = jid_new(si->p, xmlnode_get_data(cur));

	if (newjid == NULL)
	    continue;

        if(si->gtrust == NULL)
            si->gtrust = jid_new(si->p,xmlnode_get_data(cur));
        else
            jid_append(si->gtrust,jid_new(si->p,xmlnode_get_data(cur)));

	log_debug2(ZONE, LOGT_INIT, "XXX appended %s to list of global trust", jid_full(jid_new(si->p,xmlnode_get_data(cur))));
    }

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
        log_debug2(ZONE, LOGT_INIT, "jsm: loading module %s",xmlnode_get_name(cur));
        (module)(si);
    }

    /* register us for being notified of the server shutdown */
    pool_cleanup(i->p, jsm_shutdown, (void*)si);

    /* register js_packet() as the handler for packets to this instance */
    register_phandler(i, o_DELIVER, js_packet, (void *)si);

    /* XXX do we still need this? we have the pool_stat() call in jabberd/jabberd.c now */
    /* register_beat(5,jsm_stat,NULL); */
   
    /* register js_users_gc() to be called frequently, once per minute by default */
    register_beat(j_atoi(xmlnode_get_tag_data(si->config,"usergc"),60),js_users_gc,(void *)si);
}
