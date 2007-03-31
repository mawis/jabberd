/*
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2007 Matthias Wimmer
 *
 * This file is part of jabberd14.
 *
 * This software is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

#include "jsm.h"

/**
 * @file jsm.cc
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
void __jsm_shutdown(xht h, const char *key, void *data, void *arg) {
    udata u = (udata)data;	/* cast the pointer into udata */
    session cur;

    for (cur = u->sessions; cur != NULL; cur = cur->next) {
        js_session_end(cur, N_("sessionmanager shutdown"));
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
void _jsm_shutdown(xht h, const char *key, void *data, void *arg) {
    xht ht = (xht)data;

    log_debug2(ZONE, LOGT_CLEANUP, "JSM SHUTDOWN: deleting users for host %s", (char*)key);

    xhash_walk(ht,__jsm_shutdown,NULL);

    xhash_free(ht);
}

/**
 * callback function where jabberd signals the shutdown of the server
 *
 * @param arg instance internal jsm data
 */
void jsm_shutdown(void *arg) {
    jsmi si = (jsmi)arg;

    log_debug2(ZONE, LOGT_CLEANUP, "JSM SHUTDOWN: Begining shutdown sequence");
    js_mapi_call(si, e_SHUTDOWN, NULL, NULL, NULL);

    xhash_walk(si->hosts,_jsm_shutdown,arg);
    xhash_free(si->hosts);
}

/**
 * wrapper around jsm_serialize() to call this function as a beat function
 *
 * @param arg session manager instance as ::jsmi
 * @return r_UNREG if arg==NULL, r_DONE else
 */
static result _jsm_serialize_beatwrapper(void *arg) {
    jsmi si = (jsmi)arg;

    if (arg == NULL)
	return r_UNREG;

    jsm_serialize(si);

    return r_DONE;
}

/**
 * callback, that gets called by the XML router, when a new host is routed to this instance, or a host is not routed anymore to this instance
 *
 * @param i our instance
 * @param destination the host that has been registered/unregistered from routing to this instance
 * @param is_register 0 = unregistered routing, 1 = registered routing
 * @param arg our jsmi
 */
static void _jsm_routing_update(instance i, const char *destination, int is_register, void *arg) {
    jsmi si = (jsmi)arg;
    xht ht = NULL;

    /* sanity check */
    if (i == NULL || si == NULL || destination == NULL)
	return;

    /* log it ... */
    if (is_register) {
	log_notice(i->id, "session manager instance '%s' is now responsible for domain '%s'", i->id, destination);
    } else {
	log_notice(i->id, "session manager instance '%s' is not responsible for domain '%s' anymore", i->id, destination);
    }

    /* load stored state */
    if (is_register && si->statefile != NULL) {

	/* make sure this hostname is in the master table */
	if ((ht = (xht)xhash_get(si->hosts, destination)) == NULL) {
	    xmlnode maxusers = js_config(si, "jsm:maxusers", NULL);
	    ht = xhash_new(j_atoi(xmlnode_get_data(maxusers), USERS_PRIME));
	    xmlnode_free(maxusers);
	    maxusers = NULL;
	    log_debug2(ZONE, LOGT_DELIVER, "creating user hash %X for %s", ht, destination);
	    xhash_put(si->hosts, pstrdup(si->p, destination), (void *)ht);
	}

	jsm_deserialize(si, destination);
    }
}

/**
 * startup the jsm module, register the jsm modules in jsm
 *
 * @param i the instance we are in jabberd
 * @param x the &lt;load/&gt; module that instructed the moduleloader to load us
 */
extern "C" void jsm(instance i, xmlnode x) {
    jsmi si;
    xmlnode cur;
    modcall module;
    int n;
    xmlnode config=NULL;

    log_debug2(ZONE, LOGT_INIT, "jsm initializing for section '%s'",i->id);

    /* create and init the jsm instance handle */
    si = static_cast<jsmi>(pmalloco(i->p, sizeof(_jsmi)));
    si->i = i;
    si->p = i->p;
    si->std_namespace_prefixes = xhash_new(17);
    xhash_put(si->std_namespace_prefixes, "", const_cast<char*>(NS_SERVER));
    xhash_put(si->std_namespace_prefixes, "jsm", const_cast<char*>(NS_JABBERD_CONFIG_JSM));
    xhash_put(si->std_namespace_prefixes, "auth", const_cast<char*>(NS_AUTH));
    xhash_put(si->std_namespace_prefixes, "browse", const_cast<char*>(NS_BROWSE));
    xhash_put(si->std_namespace_prefixes, "delay", const_cast<char*>(NS_DELAY));
    xhash_put(si->std_namespace_prefixes, "disco-info", const_cast<char*>(NS_DISCO_INFO));
    xhash_put(si->std_namespace_prefixes, "event", const_cast<char*>(NS_EVENT));
    xhash_put(si->std_namespace_prefixes, "expire", const_cast<char*>(NS_EXPIRE));
    xhash_put(si->std_namespace_prefixes, "register", const_cast<char*>(NS_REGISTER));
    xhash_put(si->std_namespace_prefixes, "roster", const_cast<char*>(NS_ROSTER));
    xhash_put(si->std_namespace_prefixes, "vcard", const_cast<char*>(NS_VCARD));
    xhash_put(si->std_namespace_prefixes, "state", const_cast<char*>(NS_JABBERD_STOREDSTATE));
    xhash_put(si->std_namespace_prefixes, "xoob", const_cast<char*>(NS_XOOB));
    xhash_put(si->std_namespace_prefixes, "private", const_cast<char*>(NS_PRIVATE));
    xhash_put(si->std_namespace_prefixes, "privacy", const_cast<char*>(NS_PRIVACY));
    xhash_put(si->std_namespace_prefixes, "jabberd", const_cast<char*>(NS_JABBERD_WRAPPER));
    si->xc = xdb_cache(i); /* getting xdb_* handle and fetching config */
    config = js_config(si, NULL, NULL);
    si->hosts = xhash_new(j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(config, "jsm:maxhosts", si->std_namespace_prefixes), 0)), HOSTS_PRIME));
    si->sc_sessions = xhash_new(j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(config, "jsm:maxusers", si->std_namespace_prefixes), 0)), USERS_PRIME));
    for (n=0; n<e_LAST; n++)
        si->events[n] = NULL;

    /* using an external authentication component? */
    si->auth = pstrdup(si->p, xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(config, "jsm:auth", si->std_namespace_prefixes), 0)));

    /* enable serialization? */
    cur = xmlnode_get_list_item(xmlnode_get_tags(config, "jsm:serialization", si->std_namespace_prefixes), 0);
    if (cur != NULL) {
	int interval = 0;

	si->statefile = pstrdup(si->p, xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(cur, "jsm:file", si->std_namespace_prefixes), 0)));
	interval = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(cur, "jsm:interval", si->std_namespace_prefixes), 0)), 0);

	if (interval > 0) {
	    register_beat(interval, _jsm_serialize_beatwrapper, (void*)si);
	}
    }

    /* enable history storage? */
    cur = xmlnode_get_list_item(xmlnode_get_tags(config, "jsm:history", si->std_namespace_prefixes), 0);
    if (cur != NULL) {
	xmlnode nodeptr = NULL;
	nodeptr = xmlnode_get_list_item(xmlnode_get_tags(cur, "jsm:sent", si->std_namespace_prefixes), 0);
	if (nodeptr != NULL) {
	    si->history_sent.general = 1;
	    si->history_sent.special = j_strcmp(xmlnode_get_attrib_ns(nodeptr, "special", NULL), "store") == 0 ? 1 : 0;
	}
	nodeptr = xmlnode_get_tag(cur, "recv");
	if (nodeptr != NULL) {
	    si->history_recv.general = 1;
	    si->history_recv.special = j_strcmp(xmlnode_get_attrib_ns(nodeptr, "special", NULL), "store") == 0 ? 1 : 0;
	    si->history_recv.offline = j_strcmp(xmlnode_get_attrib_ns(nodeptr, "offline", NULL), "store") == 0 ? 1 : 0;
	}
    }

    /* fire up the modules by scanning the attribs on the xml we received */
    for (cur = xmlnode_get_firstattrib(x); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
        /* avoid multiple personality complex */
        if (j_strcmp(xmlnode_get_localname(cur), "jsm") == 0)
            continue;

        /* vattrib is stored as firstchild on an attrib node */
        if ((module = (modcall)xmlnode_get_firstchild(cur)) == NULL)
            continue;

        /* call this module for this session instance */
        log_debug2(ZONE, LOGT_INIT, "jsm: loading module %s", xmlnode_get_localname(cur));
        (module)(si);
    }

    /* register us for being notified of the server shutdown */
    /*
     * XXX disabled for jabberd 1.4.4 - it's crashing if we have it
     * care for it later
    pool_cleanup(i->p, jsm_shutdown, (void*)si);
     */

    /* register js_routing_update() as a handler for routing updates */
    register_routing_update_callback(i, _jsm_routing_update, (void *)si);

    /* register js_packet() as the handler for packets to this instance */
    register_phandler(i, o_DELIVER, js_packet, (void *)si);

    /* XXX do we still need this? we have the pool_stat() call in jabberd/jabberd.c now */
    /* register_beat(5,jsm_stat,NULL); */
   
    /* register js_users_gc() to be called frequently, once per minute by default */
    register_beat(j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(config, "usergc", si->std_namespace_prefixes), 0)), 60), js_users_gc, (void *)si);

    /* free the configuration xmlnode */
    xmlnode_free(config);
}
