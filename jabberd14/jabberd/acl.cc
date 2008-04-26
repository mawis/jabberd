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
    xmlnode_vector	acl;
    pool		p = NULL;
    jid			result = NULL;

    /* sanity check */
    if (xdb == NULL || function == NULL || user == NULL)
	return 0;

    /* define namespace prefixes */
    if (namespaces == NULL) {
	namespaces = xhash_new(3);
	xhash_put(namespaces, "", const_cast<char*>(NS_JABBERD_CONFIGFILE));
	xhash_put(namespaces, "acl", const_cast<char*>(NS_JABBERD_ACL));
    }

    /* get the acl */
    acl = xmlnode_get_tags(greymatter__, "global/acl:acl/acl:grant", namespaces);

    /* iterate the features */
    xmlnode_vector::iterator iter;
    for (iter = acl.begin(); iter != acl.end(); ++iter) {
	const char *f = xmlnode_get_attrib_ns(*iter, "feature", NULL);

	/* are we interested in this feature element? */
	if (f == NULL || j_strcmp(f, function) == 0) {
	    /* check for domain tags */
	    xmlnode_vector domain = xmlnode_get_tags(*iter, "acl:domain", namespaces);
	    xmlnode_vector::iterator p;
	    for (p = domain.begin(); p != domain.end(); ++p) {
		if (j_strcmp(user->get_domain().c_str(), xmlnode_get_data(*p)) == 0) {
		    return 1;
		}
	    }
	}
    }

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
    allowed_users = acl_get_users(xdb, function);

    /* is this user allowed? */
    for (iter = allowed_users; iter != NULL; iter = iter->next) {
	log_debug2(ZONE, LOGT_AUTH, "allowed for this feature is: %s", jid_full(iter));
	if (jid_cmpx(iter, user, JID_USER|JID_SERVER) == 0) {
	    /* match */
	    pool_free(allowed_users->get_pool());
	    log_debug2(ZONE, LOGT_AUTH, "user %s has access to %s", jid_full(user), function);
	    return 1;
	}
    }

    /* cleanup */
    if (allowed_users != NULL)
	pool_free(allowed_users->get_pool());

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
    xmlnode_vector	acl;
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
    acl = xmlnode_get_tags(greymatter__, "global/acl:acl/acl:grant", namespaces);

    /* iterate the features */
    xmlnode_vector::iterator feature;
    for (feature = acl.begin(); feature != acl.end(); ++feature) {
	const char *f = xmlnode_get_attrib_ns(*feature, "feature", NULL);

	/* are we interested in this feature element? */
	if (f == NULL || j_strcmp(f, function) == 0) {
	    xmlnode_vector::iterator jid_iter;
	    xmlnode_vector jids = xmlnode_get_tags(*feature, "acl:jid", namespaces);

	    /* get all jids inside */
	    for (jid_iter = jids.begin(); jid_iter != jids.end(); ++jid_iter) {
		const char *jid_str = xmlnode_get_data(*jid_iter);

		if (jid_str != NULL) {
		    if (p == NULL)
			p = pool_new();
		    result = result == NULL ? jid_new(p, jid_str) : jid_append(result, jid_new(p, jid_str));
		}
	    }
	}
    }

    return result;
}
