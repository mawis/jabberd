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

/**
 * @file acl.cc
 * @brief Functions that check access of users to restricted functionality of the server
 *
 * For the moment this is only a provisional implementation of ACLs for jabberd14
 * to get the interfaces working. A more dynamic implementation of ACLs should
 * soon follow, that will allow authorized accounts to alter ACLs at runtime of
 * the server using Jabber requests.
 */

#include "jabberd.h"

/* I really don't like having this as a global variable */
extern xmlnode greymatter__;

static int acl_check_access_domain(xdbcache xdb, const char* function, const jid user) {
    static xht		namespaces = NULL;
    xmlnode_list_item	acl = NULL;
    xmlnode_list_item	feature = NULL;
    pool		p = NULL;
    jid			result = NULL;

    /* sanity check */
    if (xdb == NULL || function == NULL || user == NULL || user->server == NULL)
	return 0;

    /* define namespace prefixes */
    if (namespaces == NULL) {
	namespaces = xhash_new(3);
	xhash_put(namespaces, "", const_cast<char*>(NS_JABBERD_CONFIGFILE));
	xhash_put(namespaces, "acl", const_cast<char*>(NS_JABBERD_ACL));
    }

    pool temp_pool = pool_new();

    /* get the acl */
    acl = xmlnode_get_tags(greymatter__, "global/acl:acl/acl:grant", namespaces, temp_pool);

    /* iterate the features */
    for (feature = acl; feature != NULL; feature = feature->next) {
	const char *f = xmlnode_get_attrib_ns(feature->node, "feature", NULL);

	/* are we interested in this feature element? */
	if (f == NULL || j_strcmp(f, function) == 0) {
	    xmlnode_list_item domain = NULL;

	    /* check for domain tags */
	    for (domain = xmlnode_get_tags(feature->node, "acl:domain", namespaces, temp_pool); domain != NULL; domain = domain->next) {
		if (j_strcmp(user->server, xmlnode_get_data(domain->node)) == 0) {
		    pool_free(temp_pool);
		    return 1;
		}
	    }
	}
    }

    pool_free(temp_pool);
    return 0;
}

/**
 * check if a user has access to a given functionality
 *
 * @param xdb instance of an xdbcache used to check the access
 * @param function functionality for which access should be checked
 * @param user user for which access should be checked
 * @return 1 if access is granted, 0 if access is denied
 */
int acl_check_access(xdbcache xdb, const char *function, const jid user) {
    jid allowed_users = NULL;
    jid iter = NULL;

    /* first try if allowed by domain */
    if (acl_check_access_domain(xdb, function, user))
	return 1;

    /* get list of all allowed users */
    pool temp_pool = pool_new();
    allowed_users = acl_get_users(xdb, function);
    pool_free(temp_pool);
    temp_pool = NULL;

    /* is this user allowed? */
    for (iter = allowed_users; iter != NULL; iter = iter->next) {
	log_debug2(ZONE, LOGT_AUTH, "allowed for this feature is: %s", jid_full(iter));
	if (jid_cmpx(iter, user, JID_USER|JID_SERVER) == 0) {
	    /* match */
	    pool_free(allowed_users -> p);
	    log_debug2(ZONE, LOGT_AUTH, "user %s has access to %s", jid_full(user), function);
	    return 1;
	}
    }

    /* cleanup */
    if (allowed_users != NULL)
	pool_free(allowed_users->p);

    /* no match found */
    log_debug2(ZONE, LOGT_AUTH, "denied user %s access to %s", jid_full(user), function);
    return 0;
}

/**
 * get the list of users, that have access to a given functionality
 *
 * @param xdb instance of an xdbcache used to check the access
 * @param function functionality for which access should be checked
 * @return list of jid_struct instances, that hold the users having access to the functionality; must be freed by the caller; NULL if no user has access
 */
jid acl_get_users(xdbcache xdb, const char *function) {
    static xht		namespaces = NULL;
    xmlnode_list_item	acl = NULL;
    xmlnode_list_item	feature = NULL;
    pool		p = NULL;
    jid			result = NULL;

    /* sanity check */
    if (xdb == NULL || function == NULL)
	return NULL;

    /* define namespace prefixes */
    if (namespaces == NULL) {
	namespaces = xhash_new(3);
	xhash_put(namespaces, "", const_cast<char*>(NS_JABBERD_CONFIGFILE));
	xhash_put(namespaces, "acl", const_cast<char*>(NS_JABBERD_ACL));
    }

    /* get the acl */
    pool temp_pool = pool_new();
    acl = xmlnode_get_tags(greymatter__, "global/acl:acl/acl:grant", namespaces, temp_pool);

    /* iterate the features */
    for (feature = acl; feature != NULL; feature = feature->next) {
	const char *f = xmlnode_get_attrib_ns(feature->node, "feature", NULL);

	/* are we interested in this feature element? */
	if (f == NULL || j_strcmp(f, function) == 0) {
	    xmlnode_list_item jid_iter = NULL;
	    xmlnode_list_item jids = xmlnode_get_tags(feature->node, "acl:jid", namespaces, temp_pool);

	    /* get all jids inside */
	    for (jid_iter = jids; jid_iter != NULL; jid_iter = jid_iter->next) {
		const char *jid_str = xmlnode_get_data(jid_iter->node);

		if (jid_str != NULL) {
		    if (p == NULL)
			p = pool_new();
		    result = result == NULL ? jid_new(p, jid_str) : jid_append(result, jid_new(p, jid_str));
		}
	    }
	}
    }

    pool_free(temp_pool);
    return result;
}
