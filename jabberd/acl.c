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
 * If you choose to use this code under the GPL, as an exception to the GPL
 * your are allowed to link the code that results from this file with OpenSSL
 * as well as with OpenSLP.
 * 
 * --------------------------------------------------------------------------*/

/**
 * @file acl.c
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
	xhash_put(namespaces, "", NS_JABBERD_CONFIGFILE);
	xhash_put(namespaces, "acl", NS_JABBERD_ACL);
    }

    /* get the acl */
    acl = xmlnode_get_tags(greymatter__, "global/acl:acl/acl:grant", namespaces);

    /* iterate the features */
    for (feature = acl; feature != NULL; feature = feature->next) {
	const char *f = xmlnode_get_attrib_ns(feature->node, "feature", NULL);

	/* are we interested in this feature element? */
	if (f == NULL || j_strcmp(f, function) == 0) {
	    xmlnode_list_item domain = NULL;

	    /* check for domain tags */
	    for (domain = xmlnode_get_tags(feature->node, "acl:domain", namespaces); domain != NULL; domain = domain->next) {
		if (j_strcmp(user->server, xmlnode_get_data(domain->node)) == 0)
		    return 1;
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
	xhash_put(namespaces, "", NS_JABBERD_CONFIGFILE);
	xhash_put(namespaces, "acl", NS_JABBERD_ACL);
    }

    /* get the acl */
    acl = xmlnode_get_tags(greymatter__, "global/acl:acl/acl:grant", namespaces);

    /* iterate the features */
    for (feature = acl; feature != NULL; feature = feature->next) {
	const char *f = xmlnode_get_attrib_ns(feature->node, "feature", NULL);

	/* are we interested in this feature element? */
	if (f == NULL || j_strcmp(f, function) == 0) {
	    xmlnode_list_item jid_iter = NULL;
	    xmlnode_list_item jids = xmlnode_get_tags(feature->node, "acl:jid", namespaces);

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

    return result;
}
