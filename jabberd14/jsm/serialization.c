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
 * serialization.c -- functions for serialization an deserialization of JSM state
 * 
 --------------------------------------------------------------------------*/

#include "jsm.h"

/**
 * @file serialization.c
 * @brief functions for serialization an deserialization of JSM state
 *
 * Contains code to serialize all necessary state information of JSM to a XML file
 * which can be used to restart the session manager resuming the handling of
 * existing user sessions.
 */

static void _jsm_serialize_user(xht usershash, const char *user, void *value, void *arg) {
    xmlnode resulttree = (xmlnode)arg;
    xmlnode thisuser = NULL;
    udata userdata = (udata)value;
    session session_iter = NULL;
    char starttime[32] = "";

    /* sanity check */
    if (usershash == NULL || user == NULL || userdata == NULL || resulttree == NULL  || userdata->si == NULL)
	return;

    /* iterate on user's sessions */
    for (session_iter = userdata->sessions; session_iter != NULL; session_iter = session_iter->next) {
	xmlnode thissession = NULL;
	xmlnode c2s_routing = NULL;

	/* generate the wrapper element when first session is processed */
	if (thisuser == NULL) {
	    thisuser = xmlnode_insert_tag_ns(resulttree, "user", NULL, NS_JABBERD_STOREDSTATE);
	    xmlnode_put_attrib_ns(thisuser, "jid", NULL, NULL, userdata->user);
	}

	/* generate the wrapper element for the session */
	thissession = xmlnode_insert_tag_ns(thisuser, "session", NULL, NS_JABBERD_STOREDSTATE);
	xmlnode_put_attrib_ns(thissession, "resource", NULL, NULL, session_iter->res);

	/* serialize all necessary data managed by JSM */
	xmlnode_insert_tag_node(thissession, session_iter->presence);
	snprintf(starttime, sizeof(starttime), "%i", session_iter->started);
	xmlnode_insert_cdata(xmlnode_insert_tag_ns(thissession, "started", NULL, NS_JABBERD_STOREDSTATE), starttime, -1);
	c2s_routing = xmlnode_insert_tag_ns(thissession, "c2s-routing", NULL, NS_JABBERD_STOREDSTATE);
	xmlnode_put_attrib_ns(c2s_routing, "sm", NULL, NULL, jid_full(session_iter->route));
	xmlnode_put_attrib_ns(c2s_routing, "c2s", NULL, NULL, jid_full(session_iter->sid));
	xmlnode_put_attrib_ns(c2s_routing, "c2s", "sc", NS_SESSION, session_iter->sc_c2s);
	xmlnode_put_attrib_ns(c2s_routing, "sm", "sc", NS_SESSION, session_iter->sc_sm);

	/* let the modules serialize their data */
	/*
	js_mapi_call2(userdata->si, es_SERIALIZE, NULL, userdata, session_iter, thissession);
	*/
    }

    /* debugging */
    if (thisuser == NULL) {
	log_debug2(ZONE, LOGT_EXECFLOW, "user %s had no sessions", userdata->user);
    }
}

/**
 * serialize the state of a domain of the session manager to an XML tree
 *
 * @param si the session manager instance, that hosts the domain
 * @param users xhash containing all users, that should be serialized
 * @param domain the domain, that should be serialized
 * @param container the xmlnode where the data should be added
 */
static xmlnode _jsm_serialize_host(xht users, const char *domain, xmlnode container) {
    xmlnode resulttree = NULL;

    /* sanity check */
    if (users == NULL || domain == NULL)
	return NULL;

    /* generate the wrapper element */
    resulttree = xmlnode_insert_tag_ns(container, "jsm", NULL, NS_JABBERD_STOREDSTATE);
    xmlnode_put_attrib_ns(resulttree, "host", NULL, NULL, domain);

    /* walk the users hash */
    xhash_walk(users, _jsm_serialize_user, (void*)resulttree);
}

/**
 * xhash walker that starts serialization for each host contained in the hosts hash
 *
 * @param hosts the xhash containing all hosts
 * @param key the domain of the current host
 * @param value the xhash containing all users for this host
 * @param arg the session manager instance (::jsmi)
 */
static void _jsm_serialize_walker(xht hosts, const char *key, void *value, void *arg) {
    xmlnode storedstate = (xmlnode)arg;

    /* sanity check */
    if (storedstate == NULL)
	return;

    _jsm_serialize_host((xht)value, key, storedstate);
}

/**
 * serialize session manager data
 */
void jsm_serialize(jsmi si) {
    xmlnode storedstate = NULL;

    storedstate = xmlnode_new_tag_ns("storedstate", NULL, NS_JABBERD_STOREDSTATE);
    xhash_walk(si->hosts, _jsm_serialize_walker, (void*)storedstate);
    xmlnode2file(si->statefile, storedstate);
    xmlnode_free(storedstate);
}
