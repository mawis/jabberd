/*
 * Copyrights
 * 
 * Copyright (c) 2006-2007 Matthias Wimmer
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
 * @file serialization.cc
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

	if (session_iter->exit_flag)
	    continue;

	/* generate the wrapper element when first session is processed */
	if (thisuser == NULL) {
	    thisuser = xmlnode_insert_tag_ns(resulttree, "user", NULL, NS_JABBERD_STOREDSTATE);
	    xmlnode_put_attrib_ns(thisuser, "name", NULL, NULL, userdata->id->user);
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
	if (!session_iter->roster)
	    xmlnode_insert_tag_ns(thissession, "no-rosterfetch", NULL, NS_JABBERD_STOREDSTATE);

	/* let the modules serialize their data */
	js_mapi_call2(NULL, es_SERIALIZE, NULL, userdata, session_iter, thissession);
    }

    /* debugging */
    if (thisuser == NULL) {
	log_debug2(ZONE, LOGT_EXECFLOW, "user %s had no sessions", userdata->id->user);
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

/**
 * deserialize a session
 *
 * @param si the session manager, that receives the deserialized data
 * @param user_jid jid of the user, that gets deserialized
 * @param resource the resource, that gets deserialized
 * @param x the xmlnode containing the data for this session
 */
static void _jsm_deserialize_session(jsmi si, const jid user_jid, const char *resource, xmlnode x) {
    xmlnode presence = NULL;
    time_t started = 0;
    xmlnode c2s_routing = NULL;
    char *route = NULL;
    char *sid = NULL;
    char *sc_c2s = NULL;
    char *sc_sm = NULL;
    int roster = 0;
    session s = NULL;		/**< the session being deserialized */
    session cur = NULL;		/**< for iteration */
    udata u = NULL;		/**< the user that owns the session */
    pool p = NULL;		/**< memory pool for the new session */

    /* sanity check */
    if (si == NULL || user_jid == NULL || resource == NULL || x == NULL)
	return;

    log_debug2(ZONE, LOGT_EXECFLOW, "deserializing state for %s/%s", jid_full(user_jid), resource);

    /* get all data */
    presence = xmlnode_get_list_item(xmlnode_get_tags(x, "presence", si->std_namespace_prefixes), 0);
    started = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(x, "state:started", si->std_namespace_prefixes), 0)), 0);
    c2s_routing = xmlnode_get_list_item(xmlnode_get_tags(x, "state:c2s-routing", si->std_namespace_prefixes), 0);
    if (c2s_routing != NULL) {
	route = xmlnode_get_attrib_ns(c2s_routing, "sm", NULL);
	sid = xmlnode_get_attrib_ns(c2s_routing, "c2s", NULL);
	sc_sm = xmlnode_get_attrib_ns(c2s_routing, "sm", NS_SESSION);
	sc_c2s = xmlnode_get_attrib_ns(c2s_routing, "c2s", NS_SESSION);
    }
    if (xmlnode_get_list_item(xmlnode_get_tags(x, "state:no-rosterfetch", si->std_namespace_prefixes), 0) == 0) {
	roster = 1;
    }

    /* check if we got all we need */
    if (presence == NULL || c2s_routing == NULL || route == NULL || sid == NULL) {
	log_warn(si->i->id, "incomplete data while deserializing session '%s/%s' (%x, %i, %x, %x, %x)", jid_full(user_jid), resource, presence, started, c2s_routing, route, sid);
	return;
    }

    /* get user */
    u = js_user(si, user_jid, NULL);
    if (u == NULL) {
	log_warn(si->i->id, "cannot deserialize session for user '%s'. User does not exist (anymore?)", jid_full(user_jid));
	return;
    }

    /* create session */
    p = pool_heap(2*1024);
    s = static_cast<session>(pmalloco(p, sizeof(struct session_struct)));
    s->p = p;
    s->si = si;

    /* create aux_data hash */
    s->aux_data = xhash_new(17);
    pool_cleanup(s->p, js_session_free_aux_data, s);

    s->id = jid_new(p, jid_full(user_jid));
    jid_set(s->id, resource, JID_RESOURCE);
    s->res = s->id->resource;
    s->u = u;
    s->exit_flag = 0;
    s->roster = roster;
    s->started = started;
    s->priority = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(presence, "priority", si->std_namespace_prefixes), 0)), 0);
    s->presence = xmlnode_dup(presence);
    s->q = mtq_new(p);
    if (sc_sm != NULL) {
	s->sc_sm = pstrdup(p, sc_sm);
    }
    if (sc_c2s != NULL) {
	s->sc_c2s = pstrdup(p, sc_c2s);
    }
    s->route = jid_new(p, route);
    s->sid = jid_new(p, sid);

    /* remove any other session w/ this resource */
    for (cur = u->sessions; cur != NULL; cur = cur->next)
        if (j_strcmp(resource, cur->res) == 0)
            js_session_end(cur, N_("Replaced by new connection"));

    /* getting linked with the user */
    s->next = s->u->sessions;
    s->u->sessions = s;

    /* for sc protocol: get inserted in the hash */
    xhash_put(s->si->sc_sessions, s->sc_sm, u);

    /* notify modules */
    js_mapi_call2(si, e_DESERIALIZE, NULL, u, s, x);

    log_debug2(ZONE, LOGT_EXECFLOW, "user '%s/%s' deserialized ...", jid_full(user_jid), resource);
}

/**
 * deserialize session manager data from an XML fragment
 *
 * @param si the session manager, that receives the deserialized data
 * @param host the host to deserialize
 * @param x the XML fragment, that should be deserialized
 */
static void _jsm_deserialize_xml(jsmi si, const char *host, xmlnode x) {
    xmlnode_list_item user_fragment = NULL;
    xmlnode_list_item session_fragment = NULL;
    jid user = NULL;

    /* sanity check */
    if (si == NULL || host == NULL || x == NULL)
	return;

    /* initialize the JID */
    user = jid_new(xmlnode_pool(x), host);

    /* iterate on the users */
    for (user_fragment = xmlnode_get_tags(x, "state:user", si->std_namespace_prefixes); user_fragment != NULL; user_fragment = user_fragment->next) {
	jid_set(user, xmlnode_get_attrib_ns(user_fragment->node, "name", NULL), JID_USER);

	for (session_fragment = xmlnode_get_tags(user_fragment->node, "state:session", si->std_namespace_prefixes); session_fragment != NULL; session_fragment = session_fragment->next) {
	    _jsm_deserialize_session(si, user, xmlnode_get_attrib_ns(session_fragment->node, "resource", NULL), session_fragment->node);
	}
    }
}

/**
 * deserialize session manager data
 *
 * @param si the session manager, that receives the deserialized data
 * @param host the host to deserialize
 */
void jsm_deserialize(jsmi si, const char *host) {
    xmlnode file = NULL;
    xmlnode_list_item jsm_host = NULL;
    pool p = NULL;

    /* sanity check */
    if (si == NULL || si->statefile == NULL || host == NULL)
	return;

    /* load state file */
    file = xmlnode_file(si->statefile);
    if (file == NULL) {
	log_notice(si->i->id, "there has been no state file, not deserializing previous jsm state for '%s'", host);
	return;
    }

    /* get the right XML tree fragment */
    p = xmlnode_pool(file);
    jsm_host = xmlnode_get_tags(file, spools(p, "state:jsm[@host='", host, "']", p), si->std_namespace_prefixes);

    if (jsm_host == NULL) {
	log_notice(si->i->id, "There is no state for '%s' in %s: not deserializing previous jsm state", host, si->statefile);
	xmlnode_free(file);
	return;
    }

    /* deserialize the data for this host */
    while (jsm_host != NULL) {
	_jsm_deserialize_xml(si, host, jsm_host->node);
	jsm_host = jsm_host->next;
    }

    xmlnode_free(file);
}
