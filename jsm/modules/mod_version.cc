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
#include <sys/utsname.h>

/**
 * @file mod_version.cc
 * @brief implements handling of 'jabber:iq:version' (XEP-0092) in the session manager
 *
 * This session manager module implements the 'Software Version' protocol in the
 * session manager. It can be used to request which version of the Jabber server
 * (the version of the session manager) is running on which operating system version.
 * The information presented by this module is gathered automatically but the
 * administrator has the possibility to overwrite or hide this information.
 */


/**
 * @brief structure that holds precomputed strings for jabber:iq:version reply
 *
 * This structure keeps the strings used to build a reply for a version query.
 * Normally it is filled with collected information on the module startup, but
 * the administrator of the server is able to overwrite all fields in the session
 * manager configuration file.
 */
typedef struct {
    pool p;		/**< memory pool used to build the strings in this structure */
    char *name;		/**< the natural-language name of the software */
    char *version;	/**< the specific version of the software */
    char *os;		/**< the operating system */
} _mod_version_i, *mod_version_i;

/**
 * callback function that handles jabber:iq:version queries
 *
 * All non iq stanzas are ignored by this function. Only queries in the jabber:iq:version
 * namespace are handled. Queries of type set are rejected, queries of type get are replied.
 *
 * @param m the mapi structure
 * @param mi pointer to the _mod_version_t structure of this module instance
 * @return M_IGNORED if not a iq stanza, M_PASS if stanza not handled, M_HANDLED if stanza has been handled
 */
static mreturn _mod_version_reply(mapi m, mod_version_i mi) {
    if (m->packet->to->resource != NULL)
	return M_PASS;

    /* first, is this a valid request? */
    if (jpacket_subtype(m->packet) != JPACKET__GET) {
        js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_NOTALLOWED);
        return M_HANDLED;
    }

    log_debug2(ZONE, LOGT_DELIVER, "handling query from", jid_full(m->packet->from));

    jutil_iqresult(m->packet->x);
    xmlnode_insert_tag_ns(m->packet->x, "query", NULL, NS_VERSION);
    jpacket_reset(m->packet);
    xmlnode_insert_cdata(xmlnode_insert_tag_ns(m->packet->iq, "name", NULL, NS_VERSION), mi->name, j_strlen(mi->name));
    xmlnode_insert_cdata(xmlnode_insert_tag_ns(m->packet->iq, "version", NULL, NS_VERSION), mi->version, j_strlen(mi->version));
    xmlnode_insert_cdata(xmlnode_insert_tag_ns(m->packet->iq, "os", NULL, NS_VERSION), mi->os, j_strlen(mi->os));
    
    js_deliver(m->si, m->packet, NULL);

    return M_HANDLED;
}

/**
 * handle disco info query to the server address, add our feature
 */
static mreturn _mod_version_disco_info(mapi m) {
    xmlnode feature = NULL;

    /* only no node, only get */
    if (jpacket_subtype(m->packet) != JPACKET__GET)
	return M_PASS;
    if (xmlnode_get_attrib_ns(m->packet->iq, "node", NULL) != NULL)
	return M_PASS;

    /* build the result IQ */
    js_mapi_create_additional_iq_result(m, "query", NULL, NS_DISCO_INFO);
    if (m->additional_result == NULL || m->additional_result->iq == NULL)
	return M_PASS;

    /* add features */
    feature = xmlnode_insert_tag_ns(m->additional_result->iq, "feature", NULL, NS_DISCO_INFO);
    xmlnode_put_attrib_ns(feature, "var", NULL, NULL, NS_VERSION);

    return M_PASS;
}

/**
 * handle iq packets to the server address
 *
 * @param m the mapi_struct containing the request
 * @param arg containing the module configuration
 * @return M_IGNORE if no iq request, M_HANDLED or M_PASS else
 */
static mreturn mod_version_iq_server(mapi m, void *arg) {
    mod_version_i mi = (mod_version_i)arg;

    /* sanity check */
    if (m == NULL || mi == NULL)
	return M_PASS;

    /* only handle iq packets */
    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;

    /* version request? */
    if (NSCHECK(m->packet->iq, NS_VERSION))
	return _mod_version_reply(m, mi);

    /* disco#info query? */
    if (NSCHECK(m->packet->iq, NS_DISCO_INFO))
	return _mod_version_disco_info(m);

    return M_PASS;
}

/**
 * free memory allocated by this module instance
 *
 * @param m the mapi structure
 * @param arg pointer to the _mod_version_t structure holding the data of this module instance
 * @return always M_PASS
 */
static mreturn mod_version_shutdown(mapi m, void *arg) {
    mod_version_i mi = (mod_version_i)arg;
    pool_free(mi->p);
    
    return M_PASS;
}

/**
 * register this module's callbacks in the session manager, allocate memory and precompute the replies
 *
 * @param si the session manager instance
 */
extern "C" void mod_version(jsmi si) {
    char *from;
    xmlnode x, config, name, version, os;
    pool p;
    mod_version_i mi;
    struct utsname un;

    p = pool_new();
    mi = static_cast<mod_version_i>(pmalloco(p, sizeof(_mod_version_i)));
    mi->p = p;

    /* get the values that should be reported by mod_version */
    uname(&un);
    config = js_config(si, "jsm:mod_version", NULL);
    name = xmlnode_get_list_item(xmlnode_get_tags(config, "jsm:name", si->std_namespace_prefixes), 0);
    version = xmlnode_get_list_item(xmlnode_get_tags(config, "jsm:version", si->std_namespace_prefixes), 0);
    os = xmlnode_get_list_item(xmlnode_get_tags(config, "jsm:os", si->std_namespace_prefixes), 0);

    mi->name = pstrdup(p, name ? xmlnode_get_data(name) : PACKAGE);
    if (version)
	mi->version = pstrdup(p, xmlnode_get_data(version));
    else
    	mi->version = pstrdup(p, VERSION);
    if (os)
	mi->os = pstrdup(p, xmlnode_get_data(os));
    else if (xmlnode_get_list_item(xmlnode_get_tags(config, "jsm:no_os_version", si->std_namespace_prefixes), 0))
	mi->os = pstrdup(p, un.sysname);
    else
	mi->os = spools(p, un.sysname, " ", un.release, p);


    js_mapi_register(si,e_SERVER,mod_version_iq_server,(void *)mi);
    js_mapi_register(si,e_SHUTDOWN,mod_version_shutdown,(void *)mi);
    xmlnode_free(config);
}
