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
 * @file mod_privacy.cc
 * @brief implements XEP-0016 - Privacy Lists
 *
 * This module allows the user to configure and use privacy lists to
 * block unwanted stanzas from being received or sent.
 */

/**
 * entry in a compiled privacy list
 */
struct mod_privacy_compiled_list_item {
    pool					p;		/**< memory pool used to create _all_ items in the list */
    jid						match_jid;	/**< the JabberID that matches this item */
    int						match_parts;	/**< which parts of the JabberID have to be matched */
    int						match_subscription; /**< 0: no match by subscription / 1: match 'none' / 3: match 'to' / 5: match 'from' / 7: match 'both' */
    int						do_deny;	/**< 0 if the action is 'allow', 1 if the action is 'deny' */
    long int					order;		/**< order of this item, used when compiling the list; the list gets ordered */
    struct mod_privacy_compiled_list_item*	next;		/**< pointer to the next list item (with a higher or the same order) */
};

/**
 * check that we can accept a name as the name for a privacy list
 *
 * @todo it would be nice if we could accept any name. But currently our xpath implementation does not allow us to use some characters.
 *
 * @param name the name to check
 * @return 1 if the name can be used, 0 else
 */
static int mod_privacy_safe_name(const char* name) {
    /* no name is used in some cases and is okay */
    if (name == NULL)
	return 1;

    /* do not allow some characters in the name */
    if (strchr(name, '\''))
	return 0;
    if (strchr(name, '/'))
	return 0;
    if (strchr(name, ']'))
	return 0;

    return 1;
}

/**
 * check if a JabberID has to be denied using the given list
 *
 * @param list the compiled privacy list
 * @param user the user for which the list is checked
 * @param id the JabberID, that should get checked
 * @return 1 if the JabberID is denied, 0 else
 */
static int mod_privacy_denied(const struct mod_privacy_compiled_list_item* privacy_list, const udata user, const jid id) {
    /* sanity check */
    if (privacy_list == NULL || user == NULL || id == NULL)
	return 0;

    log_debug2(ZONE, LOGT_EXECFLOW, "mod_privacy_denied() check for %s", jid_full(id));

    /* iterate the list items until we have a match */
    for (; privacy_list != NULL; privacy_list = privacy_list->next) {
	log_debug2(ZONE, LOGT_EXECFLOW, "list item: jid=%s, parts=%i, subscription=%i, action=%s", jid_full(privacy_list->match_jid), privacy_list->match_parts, privacy_list->match_subscription, privacy_list->do_deny ? "deny" : "allow");

	/* check if the JID matches */
	if (privacy_list->match_jid && jid_cmpx(privacy_list->match_jid, id, privacy_list->match_parts) != 0) {
	    /* no match */
	    log_debug2(ZONE, LOGT_EXECFLOW, "no match because of JID");
	    continue;
	}

	/* subscription check */
	if (privacy_list->match_subscription) {
	    int id_from   = js_trust(user, id);
	    int id_to     = js_seen(user, id);
	    int list_from = privacy_list->match_subscription & 2;
	    int list_to   = privacy_list->match_subscription & 4;

	    log_debug2(ZONE, LOGT_EXECFLOW, "subscription tests, match when: %i = %i / %i = %i", id_from, list_from, id_to, list_to);

	    if (id_from && !list_from)
		/* no match */
		continue;
	    if (!id_from && list_from)
		/* no match */
		continue;
	    if (id_to && !list_to)
		/* no match */
		continue;
	    if (!id_to && list_to)
		/* no match */
		continue;

	    log_debug2(ZONE, LOGT_EXECFLOW, "subscription matches");
	}

	log_debug2(ZONE, LOGT_EXECFLOW, "Explicit result: %s", privacy_list->do_deny ? "deny" : "accept");

	/* we have a match */
	return privacy_list->do_deny;
    }

    log_debug2(ZONE, LOGT_EXECFLOW, "No match in the list: accepting");

    /* default is to allow */
    return 0;
}

/**
 * send notify about updated privacy list to all connected resources of a user
 *
 * @param user the user to send the notifies to
 * @param edited_list the name of the edited list
 */
static void mod_privacy_send_notify_new_list(udata user, const char* edited_list) {
    session cur = NULL;

    /* sanity check */
    if (user == NULL || edited_list == NULL)
	return;

    /* iterate on sessions */
    for(cur = user->sessions; cur != NULL; cur = cur->next) {
	char id_str[33] = "push at ";
	xmlnode push_iq = jutil_iqnew(JPACKET__SET, NS_PRIVACY);
	jpacket push_packet = jpacket_new(push_iq);

	jutil_timestamp_ms(id_str+8);
	xmlnode_put_attrib_ns(xmlnode_insert_tag_ns(push_packet->iq, "list", NULL, NS_PRIVACY), "name", NULL, NULL, edited_list);
	xmlnode_put_attrib_ns(push_packet->x, "to", NULL, NULL, jid_full(cur->id));
	xmlnode_put_attrib_ns(push_packet->x, "id", NULL, NULL, id_str);
	jpacket_reset(push_packet);
	js_session_to(cur, push_packet);
    }
}

/**
 * check if a privacy list is in use by any other session of the user
 *
 * @param s the session of the user
 * @param list the name of the privacy list to check
 * @return 0 if it is not in use by any other session, else number of sessions using this list
 */
static int mod_privacy_list_in_use_by_other(session s, const char* list) {
    session cur = NULL;
    int found = 0;

    /* santiy check */
    if (s == NULL || list == NULL)
	return 0;

    /* iterate on all sessions of the user */
    for(cur = s->u->sessions; cur != NULL; cur = cur->next) {
	/* don't count the session itself */
	if (cur == s)
	    continue;

	if (j_strcmp(static_cast<char*>(xhash_get(cur->aux_data, "mod_privacy_active")), list) == 0)
	    found++;
    }

    return found;
}

/**
 * free the compiled filter lists of a session
 *
 * @param s the session to free the lists for
 */
static void mod_privacy_free_current_list_definitions(session s) {
    struct mod_privacy_compiled_list_item* list = NULL;

    /* free the lists */
    list = static_cast<struct mod_privacy_compiled_list_item*>(xhash_get(s->aux_data, "mod_privacy_list_message"));
    if (list != NULL) {
	pool_free(list->p);
    }
    list = static_cast<struct mod_privacy_compiled_list_item*>(xhash_get(s->aux_data, "mod_privacy_list_presence-in"));
    if (list != NULL) {
	pool_free(list->p);
    }
    list = static_cast<struct mod_privacy_compiled_list_item*>(xhash_get(s->aux_data, "mod_privacy_list_presence-out"));
    if (list != NULL) {
	pool_free(list->p);
    }
    list = static_cast<struct mod_privacy_compiled_list_item*>(xhash_get(s->aux_data, "mod_privacy_list_iq"));
    if (list != NULL) {
	pool_free(list->p);
    }

    /* the lists cannot be used anymore */
    xhash_put(s->aux_data, "mod_privacy_list_message", NULL);
    xhash_put(s->aux_data, "mod_privacy_list_presence-in", NULL);
    xhash_put(s->aux_data, "mod_privacy_list_presence-out", NULL);
    xhash_put(s->aux_data, "mod_privacy_list_iq", NULL);
}

/**
 * free the compiled filter lists for offline delivery
 *
 * @param user the user to free the lists for
 */
static void mod_privacy_free_current_offline_list_definitions(udata user) {
    struct mod_privacy_compiled_list_item* list = NULL;

    /* free the lists */
    list = static_cast<struct mod_privacy_compiled_list_item*>(xhash_get(user->aux_data, "mod_privacy_list_message"));
    if (list != NULL) {
	pool_free(list->p);
    }
    list = static_cast<struct mod_privacy_compiled_list_item*>(xhash_get(user->aux_data, "mod_privacy_list_presence-in"));
    if (list != NULL) {
	pool_free(list->p);
    }
    list = static_cast<struct mod_privacy_compiled_list_item*>(xhash_get(user->aux_data, "mod_privacy_list_presence-out"));
    if (list != NULL) {
	pool_free(list->p);
    }
    list = static_cast<struct mod_privacy_compiled_list_item*>(xhash_get(user->aux_data, "mod_privacy_list_iq"));
    if (list != NULL) {
	pool_free(list->p);
    }

    /* the lists cannot be used anymore */
    xhash_put(user->aux_data, "mod_privacy_list_message", NULL);
    xhash_put(user->aux_data, "mod_privacy_list_presence-in", NULL);
    xhash_put(user->aux_data, "mod_privacy_list_presence-out", NULL);
    xhash_put(user->aux_data, "mod_privacy_list_iq", NULL);
}

/**
 * filter a list of JIDs against a privacy list, return only denied JIDs
 *
 *
 * @param p memory pool to use
 * @param jid_list list of JIDs that should get filtered
 * @param user the user the privacy list is for
 * @param privacy_list the filter
 * @return list of JIDs that where denied on the privacy_list, NULL if empty set
 */
static jid mod_privacy_filter_jidlist(pool p, const jid jid_list, udata user, struct mod_privacy_compiled_list_item* privacy_list) {
    jid cur = NULL;
    jid result = NULL;

    /* sanity check */
    if (jid_list == NULL || privacy_list == NULL) {
	return NULL;
    }

    /* iterate the list */
    for (cur = jid_list; cur != NULL; cur = cur->next) {
	/* is this trustee blocked? */
	if (mod_privacy_denied(privacy_list, user, cur)) {
	    /* first blocked trustee? */
	    if (result == NULL) {
		result = jid_new(p, jid_full(cur));
	    } else {
		jid_append(result, cur);
	    }
	}
    }

    return result;
}

/**
 * gets a list of trusted but currently presence-out blocked JIDs
 *
 * @param p pool to use for memory allocations
 * @param s for which session the list should get calculated
 * @return list of JIDs, that are subscribed to us, but have presence-out currently blocked, NULL if none
 */
static jid mod_privacy_blocked_trustees(pool p, session s) {
    struct mod_privacy_compiled_list_item* list = NULL;

    /* get the current privacy list for presence-out */
    list = static_cast<struct mod_privacy_compiled_list_item*>(xhash_get(s->aux_data, "mod_privacy_list_presence-out"));

    /* return filtered result */
    return mod_privacy_filter_jidlist(p, js_trustees(s->u), s->u, list);
}

/**
 * gets a list of seen but currently presence-in blocked JIDs
 *
 * @param p pool to use for memory allocations
 * @param s for which session the list should get calculated
 * @return list of JIDs, we are subscribed to, but have presence-in currently blocked, NULL if none
 */
static jid mod_privacy_blocked_seen_jids(pool p, session s) {
    struct mod_privacy_compiled_list_item* list = NULL;

    /* get the current privacy list for presence-in */
    list = static_cast<struct mod_privacy_compiled_list_item*>(xhash_get(s->aux_data, "mod_privacy_list_presence-in"));

    /* return filtered result */
    return mod_privacy_filter_jidlist(p, js_seen_jids(s->u), s->u, list);
}

/**
 * sets no privacy list to be active
 *
 * @param s the session for which no privacy list should be active
 */
static void mod_privacy_no_active_list(jsmi si, session s) {
    jid cur = NULL;

    /* get memory pool used inside this function */
    pool p = pool_new();

    /* remember blocked trustees */
    jid blocked_trustees = mod_privacy_blocked_trustees(p, s);

    /* remember blocked seen_jids */
    jid blocked_seen_jids = mod_privacy_blocked_seen_jids(p, s);

    /* delete current privacy lists */
    xhash_put(s->aux_data, "mod_privacy_active", NULL);
    mod_privacy_free_current_list_definitions(s);

    /* there are no blocked users now, send presence to trustees, that where blocked before */
    for (cur = blocked_trustees; cur != NULL; cur=cur->next) {
	xmlnode presence = xmlnode_dup(s->presence);
	xmlnode_put_attrib_ns(presence, "to", NULL, NULL, jid_full(cur));
	js_deliver(si, jpacket_new(presence), s);
    }

    /* there are no blocked users now, probe presence for seen jids, that where blocked before */
    for (cur = blocked_seen_jids; cur != NULL; cur=cur->next) {
	xmlnode probe = jutil_presnew(JPACKET__PROBE, jid_full(cur), NULL);
	xmlnode_put_attrib_ns(probe, "from", NULL, NULL, jid_full(s->u->id));
	js_deliver(si, jpacket_new(probe), s);
    }

    /* free memory pool again */
    pool_free(p);
}

/**
 * insert an item to a compiled privacy list at the position selected by the order
 *
 * @param list the list to update (pointer to the pointer to the first element)
 * @param order at which list position the item should get inserted
 * @param jid_str the JabberID to insert (NULL for a wildcard match of any JabberID)
 * @param subscription if != NULL, match this subscription type
 * @param do_deny 1 if the action should be denial, 0 if teh action should be acceptance
 */
static void mod_privacy_insert_list_item(struct mod_privacy_compiled_list_item** list, long order, const char *jid_str, const char *subscription, int do_deny) {
    int match_subscription = 0;
    int match_parts = 0;
    jid match_jid = NULL;
    pool p = NULL;
    struct mod_privacy_compiled_list_item* new_item = NULL;
    struct mod_privacy_compiled_list_item* cur = NULL;
    struct mod_privacy_compiled_list_item* last = NULL;

    /* get a memory pool */
    if (*list == NULL) {
	p = pool_new();
    } else {
	p = (*list)->p;
    }

    /* if a jid is given, check which parts have to be matched */
    if (jid_str != NULL) {
	match_jid = jid_new(p, jid_str);

	if (match_jid == NULL) {
	    /* invalid JID */
	    log_debug2(ZONE, LOGT_EXECFLOW, "Ignoring invalid JID: %s", match_jid);

	    /* we created a new pool, free it again */
	    if (*list == NULL) {
		pool_free(p);
	    }

	    return;
	}

	/* at least the server has to match */
	match_parts = JID_SERVER;

	/* check if node or resource has to match */
	if (match_jid->user != NULL)
	    match_parts |= JID_USER;
	if (match_jid->resource != NULL)
	    match_parts |= JID_RESOURCE;
    }

    /* if a subscription is given, check which one */
    if (subscription != NULL) {
	if (j_strcmp(subscription, "none") == 0) {
	    match_subscription = 1;
	} else if (j_strcmp(subscription, "to") == 0) {
	    match_subscription = 3;
	} else if (j_strcmp(subscription, "from") == 0) {
	    match_subscription = 5;
	} else if (j_strcmp(subscription, "both") == 0) {
	    match_subscription = 7;
	}
    }

    /* create the new item */
    new_item = static_cast<struct mod_privacy_compiled_list_item*>(pmalloco(p, sizeof(struct mod_privacy_compiled_list_item)));
    new_item->p = p;
    new_item->match_jid = match_jid;
    new_item->match_parts = match_parts;
    new_item->match_subscription = match_subscription;
    new_item->order = order;
    new_item->do_deny = do_deny;

    /* search insertion position */
    for (cur = *list; cur != NULL && cur->order <= order; cur = cur->next) {
	last = cur;
    }

    /* update the list */
    new_item->next = cur;
    if (last == NULL)
	*list = new_item;
    else
	last->next = new_item;
}

/**
 * insert the JIDs in a roster group into a compiled privacy list
 *
 * @param list the list to insert the JIDs to
 * @param order the order value, where to insert the roster group
 * @param group the group to add
 * @param do_deny if the action of the roster group should be allow (0) or deny (1)
 * @param roster the user's current roster
 * @param std_namespace_prefixes hash containing namespace prefixes for xpath expressions
 */
static void mod_privacy_insert_rostergroup(struct mod_privacy_compiled_list_item** list, long order, const char *group, int do_deny, xmlnode roster, xht std_namespace_prefixes) {
    xmlnode_list_item item_iter = NULL;

    /* iterate over all items */
    for (item_iter = xmlnode_get_tags(roster, "roster:item", std_namespace_prefixes); item_iter != NULL; item_iter = item_iter->next) {
	xmlnode_list_item group_iter = NULL;

	/* check if the contact is in the required group */
	for (group_iter = xmlnode_get_tags(item_iter->node, "roster:group", std_namespace_prefixes); group_iter != NULL; group_iter = group_iter->next) {
	    if (j_strcmp(xmlnode_get_data(group_iter->node), group) == 0) {
		/* if yes: add to the list */
		mod_privacy_insert_list_item(list, order, xmlnode_get_attrib_ns(item_iter->node, "jid", NULL), NULL, do_deny);
	    }
	}
    }
}

/**
 * 'compile' a privacy list: the list gets prepared for faster processing when it is needed.
 *
 * @param si the session manager instance this function runs in
 * @param list the privacy list
 * @param roster the roster of the user
 * @param list_type for which type of stanzas the privacy list should get compiled ('iq', 'message', 'presence-in', or 'presence-out')
 * @return pointer to the first entry in the compiled list (NULL if no list)
 */
static struct mod_privacy_compiled_list_item* mod_privacy_compile_list(jsmi si, xmlnode list, xmlnode roster, const char* list_type) {
    struct mod_privacy_compiled_list_item* new_list = NULL;
    xmlnode_list_item list_iter = NULL;

    /* iterate over all items in the XML list */
    for (list_iter = xmlnode_get_tags(list, "privacy:item", si->std_namespace_prefixes); list_iter != NULL; list_iter = list_iter->next) {
	xmlnode_list_item child_element = NULL;
	const char* type = NULL;
	const char* value = NULL;
	const char* action = NULL;
	const char* order = NULL;
	long order_long = 0;
	int do_deny = 1;

	log_debug2(ZONE, LOGT_EXECFLOW, "Compiling privacy list item: %s", xmlnode_serialize_string(list_iter->node, xmppd::ns_decl_list(), 0));

	/* check if this item is relevant for the list */
	child_element = xmlnode_get_tags(list_iter->node, "privacy:*", si->std_namespace_prefixes);
	if (child_element != NULL) {
	    int match = 0;
	    for (; child_element != NULL; child_element = child_element->next) {
		if (j_strcmp(list_type, xmlnode_get_localname(child_element->node)) == 0) {
		    match = 1;
		    break;
		}
	    }

	    /* if we had no match, this item is not relevant */
	    if (!match) {
		log_debug2(ZONE, LOGT_EXECFLOW, "This item is not relevant for %s", list_type);
		continue;
	    }
	}

	type = xmlnode_get_attrib_ns(list_iter->node, "type", NULL);
	value = xmlnode_get_attrib_ns(list_iter->node, "value", NULL);
	action = xmlnode_get_attrib_ns(list_iter->node, "action", NULL);
	order = xmlnode_get_attrib_ns(list_iter->node, "order", NULL);

	if (action == NULL || order == NULL) {
	    log_debug2(ZONE, LOGT_EXECFLOW, "Ignoring invalid list item");
	    continue;
	}

	order_long = atol(order);

	if (j_strcmp(action, "allow") == 0) {
	    do_deny = 0;
	}

	if (type == NULL) {
	    mod_privacy_insert_list_item(&new_list, order_long, NULL, NULL, do_deny);
	} else if (j_strcmp(type, "jid") == 0) {
	    mod_privacy_insert_list_item(&new_list, order_long, value, NULL, do_deny);
	} else if (j_strcmp(type, "subscription") == 0) {
	    mod_privacy_insert_list_item(&new_list, order_long, NULL, value, do_deny);
	} else if (j_strcmp(type, "group") == 0) {
	    mod_privacy_insert_rostergroup(&new_list, order_long, value, do_deny, roster, si->std_namespace_prefixes);
	} else {
	    log_debug2(ZONE, LOGT_EXECFLOW, "Skipping list item with unknown type.");
	}
    }

    return new_list;
}

/**
 * activates a privacy list
 *
 * @param s the session for which the privacy list should be activated
 * @param list the list to activate
 * @return if the given privacy list has been activated
 */
static int mod_privacy_activate_list(jsmi si, session s, xmlnode list) {
    struct mod_privacy_compiled_list_item* new_list = NULL;
    const char* list_name = NULL;
    xmlnode roster = NULL;
    jid cur = NULL;
    pool p = NULL;
    jid blocked_trustees_before = NULL;
    jid blocked_trustees_after = NULL;
    jid blocked_seen_jids_before = NULL;
    jid blocked_seen_jids_after = NULL;
    xmlnode_list_item group = NULL;

    /* sanity check */
    if (s == NULL || list == NULL)
	return 0;

    /* get memory pool used inside this function */
    p = pool_new();

    /* remember blocked trustees */
    blocked_trustees_before = mod_privacy_blocked_trustees(p, s);

    /* remember blocked seen_jids */
    blocked_seen_jids_before = mod_privacy_blocked_seen_jids(p, s);

    /* get the list name */
    list_name = xmlnode_get_attrib_ns(list, "name", NULL);

    /* keep the name of the list (compare with previous value and do not pstrdup if it is the same)*/
    if (j_strcmp(list_name, static_cast<char*>(xhash_get(s->aux_data, "mod_privacy_active"))) != 0)
	xhash_put(s->aux_data, "mod_privacy_active", pstrdup(s->p, list_name));

    /* free the old compiled filter lists */
    mod_privacy_free_current_list_definitions(s);

    /* get the user's roster, we need it to compile the list */
    roster = xdb_get(s->si->xc, s->u->id, NS_ROSTER);

    /* normalize roster group names */
    for (group = xmlnode_get_tags(roster, "roster:item/roster:group", si->std_namespace_prefixes); group != NULL; group = group->next) {
	/* get normalized group name */
	const char* group_name = xmlnode_get_data(group->node);
	jid normal_group = jid_new(p, "invalid");
	jid_set(normal_group, group_name, JID_RESOURCE);

	log_debug2(ZONE, LOGT_EXECFLOW, "Checking normalization of roster group: %s", group_name);

	/* could the name be normalized? */
	if (normal_group == NULL || normal_group->resource == NULL) {
	    log_debug2(ZONE, LOGT_EXECFLOW, "Could not normalize group name in roster: %s", group_name);
	    xmlnode_hide(group->node);
	    continue;
	}

	/* insert normalized data if necessary */
	if (j_strcmp(group_name, normal_group->resource) != 0) {
	    xmlnode_list_item text_node = xmlnode_get_tags(group->node, "text()", si->std_namespace_prefixes);

	    log_debug2(ZONE, LOGT_EXECFLOW, "Normalized '%s' to '%s'", group_name, normal_group->resource);

	    if (text_node != NULL) {
		xmlnode_hide(text_node->node);
	    }
	    xmlnode_insert_cdata(group->node, normal_group->resource, -1);
	}
    }

    /* normalize group names in a privacy list */
    for (group = xmlnode_get_tags(list, "privacy:item[@type='group']", si->std_namespace_prefixes); group != NULL; group = group->next) {
	const char* group_name = xmlnode_get_attrib_ns(group->node, "value", NULL);
	jid normal_group = jid_new(p, "invalid");
	jid_set(normal_group, group_name, JID_RESOURCE);

	log_debug2(ZONE, LOGT_EXECFLOW, "Checking normalization of group on list: %s", group_name);

	/* could the name be normalized? */
	if (normal_group == NULL || normal_group->resource == NULL) {
	    log_debug2(ZONE, LOGT_EXECFLOW, "Could not normalize group name on list: %s", group_name);
	    xmlnode_hide(group->node);
	    continue;
	}

	/* update value if necessary */
	if (j_strcmp(group_name, normal_group->resource) != 0) {
	    log_debug2(ZONE, LOGT_EXECFLOW, "Normalized '%s' to '%s'", group_name, normal_group->resource);
	    xmlnode_put_attrib_ns(group->node, "value", NULL, NULL, normal_group->resource);
	}
    }

    /* compile the new filter list */
    log_debug2(ZONE, LOGT_EXECFLOW, "Compiling list for 'message'");
    new_list = mod_privacy_compile_list(s->si, list, roster, "message");
    if (new_list)
	xhash_put(s->aux_data, "mod_privacy_list_message", new_list);

    log_debug2(ZONE, LOGT_EXECFLOW, "Compiling list for 'presence-out'");
    new_list = mod_privacy_compile_list(s->si, list, roster, "presence-out");
    if (new_list)
	xhash_put(s->aux_data, "mod_privacy_list_presence-out", new_list);

    log_debug2(ZONE, LOGT_EXECFLOW, "Compiling list for 'presence-in'");
    new_list = mod_privacy_compile_list(s->si, list, roster, "presence-in");
    if (new_list)
	xhash_put(s->aux_data, "mod_privacy_list_presence-in", new_list);

    log_debug2(ZONE, LOGT_EXECFLOW, "Compiling list for 'iq'");
    new_list = mod_privacy_compile_list(s->si, list, roster, "iq");
    if (new_list)
	xhash_put(s->aux_data, "mod_privacy_list_iq", new_list);

    /* free the roster */
    if (roster != NULL)
	xmlnode_free(roster);

    /* see which trustees are now blocked */
    blocked_trustees_after = mod_privacy_blocked_trustees(p, s);

    /* send presence updates to trustees not blocked anymore */
    for (cur = blocked_trustees_before; cur != NULL; cur=cur->next) {
	jid cur2 = NULL;
	xmlnode presence = NULL;

	log_debug2(ZONE, LOGT_EXECFLOW, "trustee blocked before: %s", jid_full(cur));

	/* no presence, if still denied */
	for (cur2 = blocked_trustees_after; cur2 != NULL; cur2=cur2->next) {
	    if (jid_cmp(cur, cur2) == 0) {
		continue;
	    }
	}

	log_debug2(ZONE, LOGT_EXECFLOW, "... not blocked anymore. Send current presence.");

	/* not blocked anymore. send current presence */
	presence = xmlnode_dup(s->presence);
	xmlnode_put_attrib_ns(presence, "to", NULL, NULL, jid_full(cur));
	js_deliver(si, jpacket_new(presence), s);
    }

    /* send presence unavailable to trustees now blocked */
    for (cur = blocked_trustees_after; cur != NULL; cur=cur->next) {
	jid cur2 = NULL;
	xmlnode presence = NULL;
	jpacket jp = NULL;

	log_debug2(ZONE, LOGT_EXECFLOW, "trustee now blocked: %s", jid_full(cur));

	/* no unavailable, if already blocked before */
	for (cur2 = blocked_trustees_before; cur2 != NULL; cur2=cur2->next) {
	    if (jid_cmp(cur, cur2) == 0) {
		continue;
	    }
	}

	log_debug2(ZONE, LOGT_EXECFLOW, "... not blocked before. Send presence unavailable.");

	/* new block, send unavailable */
	presence = jutil_presnew(JPACKET__UNAVAILABLE, jid_full(cur), NULL);
	xmlnode_put_attrib_ns(presence, "from", NULL, NULL, jid_full(s->id));
	jp = jpacket_new(presence);
	jp->flag = PACKET_PASS_FILTERS_MAGIC;
	js_deliver(si, jp, s);
    }

    /* see which seen JIDs are now blocked */
    blocked_seen_jids_after = mod_privacy_blocked_seen_jids(p, s);

    /* send presence probes to seen JIDs not blocked anymore */
    for (cur = blocked_seen_jids_before; cur != NULL; cur=cur->next) {
	jid cur2 = NULL;
	xmlnode probe = NULL;

	log_debug2(ZONE, LOGT_EXECFLOW, "seen JID blocked before: %s", jid_full(cur));

	/* no presence, if still denied */
	for (cur2 = blocked_seen_jids_after; cur2 != NULL; cur2=cur2->next) {
	    if (jid_cmp(cur, cur2) == 0) {
		continue;
	    }
	}

	log_debug2(ZONE, LOGT_EXECFLOW, "... not blocked anymore. Send presence probe.");

	/* not blocked anymore. send presence probe */
	probe = jutil_presnew(JPACKET__PROBE, jid_full(cur), NULL);
	xmlnode_put_attrib_ns(probe, "from", NULL, NULL, jid_full(s->u->id));
	js_deliver(si, jpacket_new(probe), s);
    }

    /* send presence unavailable for seen JIDs now blocked */
    for (cur = blocked_seen_jids_after; cur != NULL; cur=cur->next) {
	jid cur2 = NULL;
	xmlnode presence = NULL;
	jpacket jp = NULL;

	log_debug2(ZONE, LOGT_EXECFLOW, "seen JID now blocked: %s", jid_full(cur));

	/* no unavailable, if already blocked before */
	for (cur2 = blocked_seen_jids_before; cur2 != NULL; cur2=cur2->next) {
	    if (jid_cmp(cur, cur2) == 0) {
		continue;
	    }
	}

	log_debug2(ZONE, LOGT_EXECFLOW, "... not blocked before. Send presence unavailable.");

	/* new block, send unavailable */
	presence = jutil_presnew(JPACKET__UNAVAILABLE, jid_full(s->id), NULL);
	xmlnode_put_attrib_ns(presence, "from", NULL, NULL, jid_full(cur)); /* XXX: well actually we should send it from the resource, but we do not have it here */
	jp = jpacket_new(presence);
	jp->flag = PACKET_PASS_FILTERS_MAGIC;
	js_session_to(s, jp);
    }

    /* free local pool */
    pool_free(p);

    /* new list is active now */
    return 1;
}

/**
 * activates a named privacy list
 *
 * @param s the session for which the named privacy list should be activated
 * @param name the name of the list (or NULL for the default privacy list)
 * @return if the named privacy list has been enabled
 */
static int mod_privacy_activate_named(jsmi si, session s, const char* name) {
    xmlnode all_lists = NULL;
    xmlnode_list_item named_list = NULL;
    int result = 0;

    /* sanity check */
    if (s == NULL)
	return 0;

    log_debug2(ZONE, LOGT_EXECFLOW, "mod_privacy_activate_named() for '%s' list '%s'", jid_full(s->id), name);

    /* get all privacy lists and select the correct one */
    all_lists = xdb_get(s->si->xc, s->u->id, NS_PRIVACY);
    if (name == NULL) {
	named_list = xmlnode_get_tags(all_lists, "*[@jabberd:default]", s->si->std_namespace_prefixes);

	if (named_list == NULL) {
	    log_debug2(ZONE, LOGT_EXECFLOW, "Activating default list, with declined default list: disabling privacy lists for this session");
	    mod_privacy_no_active_list(si, s);
	    xmlnode_free(all_lists);
	    return 1;
	}
    } else {
	pool p = pool_new();
	named_list = xmlnode_get_tags(all_lists, spools(p, "*[@name='", name, "']", p), s->si->std_namespace_prefixes);
	pool_free(p);

	if (named_list == NULL) {
	    log_debug2(ZONE, LOGT_EXECFLOW, "privacy list '%s' not found for user %s", name, jid_full(s->id));
	    xmlnode_free(all_lists);
	    return 0;
	}
    }

    /* do the actual parsing and evaluation of the privacy list */
    result = mod_privacy_activate_list(si, s, named_list->node);

    /* free xdb result */
    xmlnode_free(all_lists);

    /* return */
    return result;
}


/**
 * activates the default privacy list
 *
 * @param s the session for which the default privacy list should be activated
 * @return if a default privacy list has been enabled
 */
static int mod_privacy_activate_default(jsmi si, session s) {
    return mod_privacy_activate_named(si, s, NULL);
}

/**
 * free privacy lists for offline delivery if user gets unloaded
 *
 * @param arg the user's udata
 */
static void mod_privacy_free_offline(void *arg) {
    udata user = (udata)arg;

    if (user == NULL)
	return;

    mod_privacy_free_current_offline_list_definitions(user);
}

/**
 * load the default privacy list for the user
 *
 * @param user the user to load the list for
 */
static void mod_privacy_load_offline_list(udata user) {
    xmlnode all_lists = NULL;
    xmlnode roster = NULL;
    xmlnode_list_item default_list = NULL;
    struct mod_privacy_compiled_list_item* new_list = NULL;

    log_debug2(ZONE, LOGT_EXECFLOW, "Loading (default) privacy list for offline handling of user %s", jid_full(user->id));

    /* get the privacy lists from xdb */
    all_lists = xdb_get(user->si->xc, user->id, NS_PRIVACY);

    /* no privacy lists at all? */
    if (all_lists == NULL)
	return;

    /* get the default privacy list */
    default_list = xmlnode_get_tags(all_lists, "*[@jabberd:default]", user->si->std_namespace_prefixes);

    /* is it the first list that is loaded? register cleanup handler */
    if (xhash_get(user->aux_data, "mod_privacy_lists_loaded") == NULL) {
	/* register cleanup handler */
	pool_cleanup(user->p, mod_privacy_free_offline, user);

	/* flag that the default list has been loaded */
	xhash_put(user->aux_data, "mod_privacy_lists_loaded", const_cast<char*>("loaded"));
    }

    /* no default list? we are finished */
    if (default_list == NULL) {
	log_debug2(ZONE, LOGT_EXECFLOW, "This user has no default list.");
	xmlnode_free(all_lists);
	return;
    }

    /* we may need the user's roster to compile the list */
    roster = xdb_get(user->si->xc, user->id, NS_ROSTER);

    /* take care that we have no previous lists */
    mod_privacy_free_current_offline_list_definitions(user);

    /* compile and register the lists */
    new_list = mod_privacy_compile_list(user->si, default_list->node, roster, "message");
    if (new_list)
	xhash_put(user->aux_data, "mod_privacy_list_message", new_list);
    new_list = mod_privacy_compile_list(user->si, default_list->node, roster, "presence-in");
    if (new_list)
	xhash_put(user->aux_data, "mod_privacy_list_presence-out", new_list);
    new_list = mod_privacy_compile_list(user->si, default_list->node, roster, "presence-out");
    if (new_list)
	xhash_put(user->aux_data, "mod_privacy_list_presence-in", new_list);
    new_list = mod_privacy_compile_list(user->si, default_list->node, roster, "iq");
    if (new_list)
	xhash_put(user->aux_data, "mod_privacy_list_iq", new_list);

    /* free loaded lists */
    xmlnode_free(all_lists);

    /* free loaded roster */
    xmlnode_free(roster);
}

/**
 * handle selecting a new active list
 *
 * @param m the mapi structure containing the request
 * @param new_active_list the list that should become active (NULL to decline active list)
 * @return M_HANDLED
 */
static mreturn mod_privacy_out_iq_set_active(mapi m, const char* new_active_list) {
    log_debug2(ZONE, LOGT_EXECFLOW, "Updating active privacy list selection");

    /* sanity check */
    if (m == NULL)
	return M_PASS;

    /* deactivating all lists? */
    if (new_active_list == NULL) {
	log_debug2(ZONE, LOGT_EXECFLOW, "decline active privacy list");

	/* disable privacy lists for this session */
	mod_privacy_no_active_list(m->si, m->s);

	/* send reply */
	jutil_iqresult(m->packet->x);
	jpacket_reset(m->packet);
	js_session_to(m->s, m->packet);
	return M_HANDLED;
    }

    /* we cannot handle some names */
    if (!mod_privacy_safe_name(new_active_list)) {
	js_bounce_xmpp(m->si, m->s, m->packet->x, (xterror){406, N_("The server cannot accept that privacy list name."), "modify", "not-acceptable"});
	return M_HANDLED;
    }

    /* activate a named list */
    if (mod_privacy_activate_named(m->si, m->s, new_active_list)) {
	/* success: send reply */
	jutil_iqresult(m->packet->x);
	jpacket_reset(m->packet);
	js_session_to(m->s, m->packet);
	return M_HANDLED;
    }

    /* failure: send error */
    js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_NOTFOUND);
    return M_HANDLED;
}

/**
 * handle selecting a new default list
 *
 * @param m the mapi structure containing the request
 * @param new_default_list the list that should become default (NULL to decline default list)
 * @return M_HANDLED
 */
static mreturn mod_privacy_out_iq_set_default(mapi m, const char* new_default_list) {
    xmlnode all_lists = NULL;
    xmlnode_list_item default_list = NULL;
    xmlnode_list_item default_list_new = NULL;
    const char* old_default_list = NULL;
    const char* current_active_list = NULL;

    log_debug2(ZONE, LOGT_EXECFLOW, "Updating default privacy list selection: %s", new_default_list);

    /* sanity check */
    if (m == NULL)
	return M_PASS;

    /* we cannot handle some names */
    if (!mod_privacy_safe_name(new_default_list)) {
	js_bounce_xmpp(m->si, m->s, m->packet->x, (xterror){406, N_("The server cannot accept that privacy list name."), "modify", "not-acceptable"});
	return M_HANDLED;
    }

    /* what is the current default list? */
    all_lists = xdb_get(m->si->xc, m->user->id, NS_PRIVACY);
    if (all_lists == NULL && new_default_list != NULL) {
	/* if there are no lists, there is nothing to set */
	js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_NOTFOUND);
	return M_HANDLED;
    }

    default_list = xmlnode_get_tags(all_lists, "privacy:list[@jabberd:default]", m->si->std_namespace_prefixes);
    if (default_list != NULL) {
	old_default_list = xmlnode_get_attrib_ns(default_list->node, "name", NULL);
    }

    /* is the current default list in use by any other session? */
    if (mod_privacy_list_in_use_by_other(m->s, old_default_list) > 0) {
	if (all_lists != NULL) {
	    xmlnode_free(all_lists);
	}
	js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_CONFLICT);
	return M_HANDLED;
    }

    /* is there any list with the requested name? */
    if (new_default_list != NULL) {
	default_list_new = xmlnode_get_tags(all_lists, spools(m->packet->p, "privacy:list[@name='", new_default_list, "']", m->packet->p), m->si->std_namespace_prefixes);
	if (default_list_new == NULL) {
	    /* requested list does not exist */
	    js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_NOTFOUND);
	    xmlnode_free(all_lists);
	    return M_HANDLED;
	}

	/* set the new list to be the default */
	xmlnode_put_attrib_ns(default_list_new->node, "default", "jabberd", NS_JABBERD_WRAPPER, "default");
	xdb_act_path(m->si->xc, m->user->id, NS_PRIVACY, "insert", spools(m->packet->p, "privacy:list[@name='", new_default_list, "']", m->packet->p), m->si->std_namespace_prefixes, default_list_new->node);
    }

    /* unselect the old default list */
    if (default_list != NULL) {
	xmlnode_hide_attrib_ns(default_list->node, "default", NS_JABBERD_WRAPPER);
	xdb_act_path(m->si->xc, m->user->id, NS_PRIVACY, "insert", spools(m->packet->p, "privacy:list[@name='", old_default_list, "']", m->packet->p), m->si->std_namespace_prefixes, default_list->node);
    }

    /* update the active list for the current session, if the default list was in use */
    current_active_list = static_cast<char*>(xhash_get(m->s->aux_data, "mod_privacy_active"));
    if (current_active_list == NULL && old_default_list == NULL || j_strcmp(current_active_list, old_default_list) == 0) {
	mod_privacy_activate_default(m->si, m->s);
    }

    /* update the default list for offline handling */
    if (xhash_get(m->user->aux_data, "mod_privacy_lists_loaded")) {
	mod_privacy_load_offline_list(m->user);
    }

    xmlnode_free(all_lists);
    jutil_iqresult(m->packet->x);
    jpacket_reset(m->packet);
    js_session_to(m->s, m->packet);
    return M_HANDLED;
}

/**
 * handle a privacy list update
 *
 * @todo RFC3920 requires that deleting a list fails if there is no such list. We are confirming such a deletion as well for performance reasons. Think about that.
 *
 * @param m the mapi structure containing the request
 * @param new_list the new list definition (empty list element, to delete a list)
 * @return M_HANDLED
 */
static mreturn mod_privacy_out_iq_set_list(mapi m, xmlnode new_list) {
    const char* edited_list = NULL;
    char* edited_list_path = NULL;
    xmlnode_list_item new_items = NULL;
    int xdb_result = 0;
    xmlnode previous_lists = NULL;
    xmlnode_list_item previous_list = NULL;
    int is_default_update = 0;
    int list_items = 0;

    /* sanity check */
    if (m == NULL || new_list == NULL)
	return M_PASS;

    edited_list = xmlnode_get_attrib_ns(new_list, "name", NULL);

    /* for editing we need a list name */
    if (edited_list == NULL) {
	js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_BAD);
	return M_HANDLED;
    }

    log_debug2(ZONE, LOGT_EXECFLOW, "Setting new privacy list definition for list '%s'", edited_list);

    /* we cannot handle some names */
    if (!mod_privacy_safe_name(edited_list)) {
	log_debug2(ZONE, LOGT_EXECFLOW, "We cannot accept this privacy list name.");
	js_bounce_xmpp(m->si, m->s, m->packet->x, (xterror){406, N_("The server cannot accept that privacy list name."), "modify", "not-acceptable"});
	return M_HANDLED;
    }

    /* the list must not be in use by another session */
    if (mod_privacy_list_in_use_by_other(m->s, edited_list) > 0) {
	log_debug2(ZONE, LOGT_EXECFLOW, "Privacy list is in use and cannot be updated.");
	js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_CONFLICT);
	return M_HANDLED;
    }

    /* is the edited list the default list? */
    previous_lists = xdb_get(m->si->xc, m->user->id, NS_PRIVACY);
    edited_list_path = spools(m->packet->p, "privacy:list[@name='", edited_list, "']", m->packet->p);
    previous_list = xmlnode_get_tags(previous_lists, edited_list_path, m->si->std_namespace_prefixes);
    if (previous_list != NULL && xmlnode_get_attrib_ns(previous_list->node, "default", NS_JABBERD_WRAPPER) != NULL) {
	is_default_update = 1;
	xmlnode_put_attrib_ns(new_list, "default", "jabberd", NS_JABBERD_WRAPPER, "default");
    }

    /* is it an edit or a delete request? */
    log_debug2(ZONE, LOGT_EXECFLOW, "Checking the new list: %s", xmlnode_serialize_string(new_list, xmppd::ns_decl_list(), 0));
    for (new_items = xmlnode_get_tags(new_list, "privacy:item", m->si->std_namespace_prefixes); new_items != NULL; new_items = new_items->next) {
	const char* type = xmlnode_get_attrib_ns(new_items->node, "type", NULL);
	const char* value = xmlnode_get_attrib_ns(new_items->node, "value", NULL);
	const char* action = xmlnode_get_attrib_ns(new_items->node, "action", NULL);
	const char* order = xmlnode_get_attrib_ns(new_items->node, "order", NULL);

	/* validate this item */
	if (order == NULL) {
	    xmlnode_free(previous_lists);
	    js_bounce_xmpp(m->si, m->s, m->packet->x, (xterror){400, N_("Privacy list is invalid: item without order attribute"),"modify","bad-request"});
	    return M_HANDLED;
	}
	if (j_strcmp(action, "deny") != 0 && j_strcmp(action, "allow") != 0) {
	    xmlnode_free(previous_lists);
	    js_bounce_xmpp(m->si, m->s, m->packet->x, (xterror){400, N_("Privacy list is invalid: item action has to be either 'deny' or 'allow'"),"modify","bad-request"});
	    return M_HANDLED;
	}
	if (type == NULL) {
	    if (value != NULL) {
		xmlnode_free(previous_lists);
		js_bounce_xmpp(m->si, m->s, m->packet->x, (xterror){400, N_("Privacy list is invalid: fall-through item is not allowed to have a value"),"modify","bad-request"});
		return M_HANDLED;
	    }
	} else if (j_strcmp(type, "jid") == 0) {
	    jid test_jid = jid_new(m->packet->p, value);
	    if (test_jid == NULL) {
		xmlnode_free(previous_lists);
		js_bounce_xmpp(m->si, m->s, m->packet->x, (xterror){400, N_("Privacy list is invalid: if type is 'jid', value has to be a valid JID"),"modify","bad-request"});
		return M_HANDLED;
	    }
	} else if (j_strcmp(type, "group") == 0) {
	    if (j_strlen(value) <= 0) {
		xmlnode_free(previous_lists);
		js_bounce_xmpp(m->si, m->s, m->packet->x, (xterror){400, N_("Privacy list is invalid: if type is 'group', value has to be a roster group name"),"modify","bad-request"});
		return M_HANDLED;
	    }
	    /* XXX TODO: check that roster group exists */
	} else if (j_strcmp(type, "subscription") == 0) {
	    if (j_strcmp(value, "both") != 0 && j_strcmp(value, "none") != 0 && j_strcmp(value, "to") != 0 && j_strcmp(value, "from") != 0) {
		xmlnode_free(previous_lists);
		js_bounce_xmpp(m->si, m->s, m->packet->x, (xterror){400, N_("Privacy list is invalid: if type is 'subscription', value has to be one of 'none', 'from', 'to', or 'both'"),"modify","bad-request"});
		return M_HANDLED;
	    }
	} else {
	    xmlnode_free(previous_lists);
	    js_bounce_xmpp(m->si, m->s, m->packet->x, (xterror){400, N_("Privacy list is invalid: if type is present, it has to be one of 'jid', 'group', or 'subscription'"),"modify","bad-request"});
	    return M_HANDLED;
	}

	list_items++;
    }

    if (new_items <= 0) {
	log_debug2(ZONE, LOGT_EXECFLOW, "This is a deletion request");
    }

    /* save the new list */
    xdb_result = xdb_act_path(m->si->xc, m->user->id, NS_PRIVACY, "insert", edited_list_path, m->si->std_namespace_prefixes, list_items > 0 ? new_list : NULL);
    if (xdb_result) {
	xmlnode_free(previous_lists);
	log_debug2(ZONE, LOGT_STORAGE, "Error updating stored data.");
	js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_INTERNAL);
	return M_HANDLED;
    }

    log_debug2(ZONE, LOGT_STORAGE, "New privacy list definition has been stored.");

    /* if it has been the default list, do we have to update the user's offline list? */
    if (xhash_get(m->user->aux_data, "mod_privacy_lists_loaded")) {
	mod_privacy_load_offline_list(m->user);
    }

    /* do we use this list? */
    if (j_strcmp(static_cast<char*>(xhash_get(m->s->aux_data, "mod_privacy_active")), edited_list) == 0) {
	log_debug2(ZONE, LOGT_EXECFLOW, "The edited list was in use by us. Updating used list.");
	if (list_items > 0) {
	    mod_privacy_activate_named(m->si, m->s, edited_list);
	} else {
	    mod_privacy_no_active_list(m->si, m->s);
	}
    }

    /* send push to all resources */
    mod_privacy_send_notify_new_list(m->user, edited_list);

    /* send result */
    jutil_iqresult(m->packet->x);
    jpacket_reset(m->packet);
    js_session_to(m->s, m->packet);
    xmlnode_free(previous_lists);
    return M_HANDLED;
}

/**
 * handle set requests in the jabber:iq:privacy namespace
 *
 * @param m the mapi struct holding the request
 * @return M_HANDLED if the request has been processed, M_PASS if not
 */
static mreturn mod_privacy_out_iq_set(mapi m) {
    xmlnode_list_item child_element = NULL;

    /* check the type of request: exactly one child element in the NS_PRIVACY namespace required */
    child_element = xmlnode_get_tags(m->packet->iq, "privacy:*", m->si->std_namespace_prefixes);
    if (child_element == NULL || child_element->next != NULL) {
	js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_BAD);
	return M_HANDLED;
    }

    if (j_strcmp(xmlnode_get_localname(child_element->node), "active") == 0) {
	return mod_privacy_out_iq_set_active(m, xmlnode_get_attrib_ns(child_element->node, "name", NULL));
    } else if (j_strcmp(xmlnode_get_localname(child_element->node), "default") == 0) {
	return mod_privacy_out_iq_set_default(m, xmlnode_get_attrib_ns(child_element->node, "name", NULL));
    } else if (j_strcmp(xmlnode_get_localname(child_element->node), "list") == 0) {
	return mod_privacy_out_iq_set_list(m, child_element->node);
    }

    js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_BAD);
    return M_HANDLED;
}

/**
 * handle get requests in the jabber:iq:privacy namespace
 *
 * @param m the mapi struct holding the request
 * @return M_HANDLED if the request has been processed, M_PASS if not
 */
static mreturn mod_privacy_out_iq_get(mapi m) {
    xmlnode storedlists = NULL;
    xmlnode_list_item query_data = NULL;
    xmlnode_list_item list_iter = NULL;
    const char* requested_list = NULL;

    /* get the lists from xdb */
    storedlists = xdb_get(m->si->xc, m->user->id, NS_PRIVACY);

    /* check if it is a request to get the names of the privacy lists */
    query_data = xmlnode_get_tags(m->packet->iq, "privacy:*", m->si->std_namespace_prefixes);
    if (query_data == NULL) {
	xmlnode firstchild = NULL;
	const char* active_list = NULL;

	log_debug2(ZONE, LOGT_EXECFLOW, "client request to list privacy lists");

	/* user wants to get the names of the lists, and which list is default or active */
	jutil_iqresult(m->packet->x);
	m->packet->iq = xmlnode_insert_tag_ns(m->packet->x, "query", NULL, NS_PRIVACY);
	if (storedlists != NULL) {
	    log_debug2(ZONE, LOGT_EXECFLOW, "we have stored lists to copy in");
	    xmlnode_insert_node(m->packet->iq, xmlnode_get_firstchild(storedlists));
	    xmlnode_free(storedlists);
	    storedlists = NULL;
	}

	/* iterate the lists and hide their child nodes */
	for (list_iter = xmlnode_get_tags(m->packet->iq, "privacy:list", m->si->std_namespace_prefixes); list_iter != NULL; list_iter = list_iter->next) {
	    /* check if it is the default list, and add <active/> element in that case */
	    const char* default_list = xmlnode_get_attrib_ns(list_iter->node, "default", NS_JABBERD_WRAPPER);
	    if (default_list != NULL) {
		default_list = xmlnode_get_attrib_ns(list_iter->node, "name", NULL);
		xmlnode default_element = xmlnode_insert_tag_ns(m->packet->iq, "default", NULL, NS_PRIVACY);
		xmlnode_put_attrib_ns(default_element, "name", NULL, NULL, default_list);
		xmlnode_hide_attrib_ns(list_iter->node, "default", NS_JABBERD_WRAPPER);
		log_debug2(ZONE, LOGT_EXECFLOW, "default list is: %s", default_list);
	    }

	    while (firstchild = xmlnode_get_firstchild(list_iter->node)) {
		log_debug2(ZONE, LOGT_EXECFLOW, "hiding list content");
		xmlnode_hide(firstchild);
	    }
	}

	/* add the indication of the active list */
	active_list = static_cast<char*>(xhash_get(m->s->aux_data, "mod_privacy_active"));
	if (active_list != NULL) {
	    xmlnode active_element = xmlnode_insert_tag_ns(m->packet->iq, "active", NULL, NS_PRIVACY);
	    xmlnode_put_attrib_ns(active_element, "name", NULL, NULL, active_list);
	    log_debug2(ZONE, LOGT_EXECFLOW, "active list is: %s", active_list);
	}

	/* send back */
	jpacket_reset(m->packet);
	js_session_to(m->s, m->packet);
	return M_HANDLED;
    }

    /* if query has more than one child in the privacy namespace, we deny the request */
    if (query_data->next != NULL || j_strcmp(xmlnode_get_localname(query_data->node), "list") != 0) {
	if (storedlists)
	    xmlnode_free(storedlists);
	js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_BAD);
	return M_HANDLED;
    }

    /* check which list is requested */
    requested_list = xmlnode_get_attrib_ns(query_data->node, "name", NULL);
    if (requested_list == NULL || !mod_privacy_safe_name(requested_list)) {
	if (storedlists)
	    xmlnode_free(storedlists);
	js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_BAD);
	return M_HANDLED;
    }
    log_debug2(ZONE, LOGT_EXECFLOW, "Client requested privacy list: %s", requested_list);

    /* get the requested list */
    list_iter = xmlnode_get_tags(storedlists, spools(m->packet->p, "privacy:list[@name='", requested_list, "']", m->packet->p), m->si->std_namespace_prefixes);

    /* no such list? */
    if (list_iter == NULL) {
	if (storedlists)
	    xmlnode_free(storedlists);
	js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_NOTFOUND);
	return M_HANDLED;
    }

    /* prepare result */
    jutil_iqresult(m->packet->x);
    m->packet->iq = xmlnode_insert_tag_ns(m->packet->x, "query", NULL, NS_PRIVACY);
    xmlnode_insert_tag_node(m->packet->iq, list_iter->node);
    jpacket_reset(m->packet);
    js_session_to(m->s, m->packet);

    xmlnode_free(storedlists);

    /* cleanup and return */
    return M_HANDLED;
}

/**
 * handle packets sent by the user
 *
 * Check for request of the user to change the privacy settings
 *
 * @param m the mapi structure holding the request
 * @param arg unused/ignored
 * @return always M_PASS for now
 */
static mreturn mod_privacy_out(mapi m, void* arg) {
    /* sanity checks */
    if (m == NULL)
	return M_PASS;

    /* check that it's a request we want to handle */
    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;
    if (!NSCHECK(m->packet->iq, NS_PRIVACY))
	return M_PASS;

    /* handle dependant of subtype */
    switch (jpacket_subtype(m->packet)) {
	case JPACKET__SET:
	    return mod_privacy_out_iq_set(m);
	case JPACKET__GET:
	    return mod_privacy_out_iq_get(m);
	default:
	    xmlnode_free(m->packet->x);
	    return M_HANDLED;
    }
}

/**
 * serialize data of mod_privacy for a user's session
 */
static mreturn mod_privacy_serialize(mapi m, void *arg) {
    const char* active_list = NULL;
    xmlnode mod_privacy_data = NULL;

    /* sanity check */
    if (m == NULL)
	return M_IGNORE;

    /* anything to serialize? */
    active_list = static_cast<char*>(xhash_get(m->s->aux_data, "mod_privacy_active"));
    if (active_list == NULL)
	return M_PASS;


    /* serialize our data */
    mod_privacy_data = xmlnode_insert_tag_ns(m->serialization_node, "modPrivacy", NULL, NS_JABBERD_STOREDSTATE);
    xmlnode_put_attrib_ns(xmlnode_insert_tag_ns(mod_privacy_data, "active", NULL, NS_PRIVACY), "name", NULL, NULL, active_list);

    return M_PASS;
}

/**
 * filter stanzas
 *
 * if m->s is NULL, it is a stanza to a offline user; else it is data to a session
 *
 * @param m the mapi event containing the event's data
 * @param arg (void*)0 for incoming filtering, (void*)1 for outgoing filtering
 * @return M_PASS if the stanza is accepted, M_HANDLED if it is rejected
 */
static mreturn mod_privacy_filter(mapi m, void* arg) {
    int do_bounce = 0;
    struct mod_privacy_compiled_list_item* affected_list = NULL;

    /* sanity check */
    if (m == NULL || m->packet == NULL || m->packet->to == NULL || m->packet->from == NULL || m->user == NULL)
	return M_PASS;

    /* don't filter packets from the user itself (for outgoing filtering this has been already checked) */
    if (arg == (void*)0 && jid_cmpx(m->packet->to, m->packet->from, JID_USER|JID_SERVER) == 0)
	return M_PASS;

    log_debug2(ZONE, LOGT_EXECFLOW, "filtering %s packet %s: %s", arg ? "outgoing" : "incoming", m->s ? "for session" : "for offline account", xmlnode_serialize_string(m->packet->x, xmppd::ns_decl_list(), 0));

    /* if it is to an offline user, we might have to load the privacy lists first */
    if (m->s == NULL && !xhash_get(m->user->aux_data, "mod_privacy_lists_loaded")) {
	mod_privacy_load_offline_list(m->user);
    }

    /* get the relevant list */
    switch (m->packet->type) {
	case JPACKET_IQ:
	    do_bounce = 1;
	    affected_list = static_cast<struct mod_privacy_compiled_list_item*>(xhash_get(m->s ? m->s->aux_data : m->user->aux_data, "mod_privacy_list_iq"));
	    break;
	case JPACKET_MESSAGE:
	    do_bounce = 1;
	    affected_list = static_cast<struct mod_privacy_compiled_list_item*>(xhash_get(m->s ? m->s->aux_data : m->user->aux_data, "mod_privacy_list_message"));
	    break;
	case JPACKET_PRESENCE:
	    /* do not block probes (the results might get blocked) */
	    if (jpacket_subtype(m->packet) == JPACKET__PROBE) {
		log_debug2(ZONE, LOGT_EXECFLOW, "not applying privacy lists to presence probes.");
		return M_PASS;
	    }

	    affected_list = static_cast<struct mod_privacy_compiled_list_item*>(xhash_get(m->s ? m->s->aux_data : m->user->aux_data, arg ? "mod_privacy_list_presence-out" : "mod_privacy_list_presence-in"));
	    break;
    }

    /* no list? no filter! */
    if (affected_list == NULL) {
	log_debug2(ZONE, LOGT_EXECFLOW, "there is no privacy list for this ... accept");
	return M_PASS;
    }

    log_debug2(ZONE, LOGT_EXECFLOW, "packet is filtered");

    /* is the stanza denied? */
    if (mod_privacy_denied(affected_list, m->user, arg ? m->packet->to : m->packet->from)) {
	log_debug2(ZONE, LOGT_EXECFLOW, "... and denied");

	if (do_bounce) {
	    xterror err = (xterror){503, N_("Blocked by recipient's privacy list"), "cancel", "service-unavailable"};
	    if (arg) {
		snprintf(err.msg, sizeof(err.msg), "%s", N_("Blocked by your own privacy list"));
	    }
	    js_bounce_xmpp(m->si, m->s, m->packet->x, err);
	    return M_HANDLED;
	}

	xmlnode_free(m->packet->x);
	return M_HANDLED;
    }

    log_debug2(ZONE, LOGT_EXECFLOW, "... and accepted");

    return M_PASS;
}

/**
 * event handler for updated roster items
 *
 * @param m the mapi struct containing the updated item
 * @param arg unused/ignored
 * @return always M_PASS
 */
static mreturn mod_privacy_rosterchange(mapi m, void* arg) {
    session cur = NULL;
    xmlnode_list_item roster_item = NULL;
    jid updated_jid = NULL;

    /* sanity check */
    if (m == NULL || m->user == NULL)
	return M_PASS;

    log_debug2(ZONE, LOGT_EXECFLOW, "received rosterchange event for user '%s'", jid_full(m->user->id));

    /* check if the default list has been loaded for offline delivery, and reload if yes */
    if (xhash_get(m->user->aux_data, "mod_privacy_lists_loaded")) {
	log_debug2(ZONE, LOGT_EXECFLOW, "reloading default list for offline handling");
	mod_privacy_load_offline_list(m->user);
    }

    /* reload the sessions' lists */
    for (cur = m->user->sessions; cur != NULL; cur = cur->next) {
	const char* active_list = static_cast<char*>(xhash_get(cur->aux_data, "mod_privacy_active"));

	if (active_list != NULL) {
	    log_debug2(ZONE, LOGT_EXECFLOW, "Reloading list '%s' for session '%s'", active_list, jid_full(cur->id));
	    mod_privacy_activate_named(m->si, cur, active_list);
	} else {
	    log_debug2(ZONE, LOGT_EXECFLOW, "No active list for session '%s'", jid_full(cur->id));
	}
    }

    return M_PASS;
}

/**
 * free data bound to a session
 */
static mreturn mod_privacy_end_session(mapi m, void* arg) {
    mod_privacy_free_current_list_definitions(m->s);
}

/**
 * callback, that gets called on new sessions
 *
 * Register handler for packets sent by the user with this session
 *
 * Register serialization handler.
 *
 * @param m the mapi structure containing the event's data
 * @param arg unused/ignored
 * @return always M_PASS
 */
static mreturn mod_privacy_session(mapi m, void* arg) {
    /* activate default privacy list */
    mod_privacy_activate_default(m->si, m->s);

    /* register callbacks */
    js_mapi_session(es_OUT, m->s, mod_privacy_out, NULL);
    js_mapi_session(es_SERIALIZE, m->s, mod_privacy_serialize, NULL);
    js_mapi_session(es_FILTER_IN, m->s, mod_privacy_filter, (void*)0);
    js_mapi_session(es_FILTER_OUT, m->s, mod_privacy_filter, (void*)1);
    js_mapi_session(es_END, m->s, mod_privacy_end_session, NULL);

    return M_PASS;
}

/**
 * callback, that gets called on deserialized sessions
 *
 * Register handler for packets sent by the user with this session
 *
 * Register serialization handler.
 *
 * @param m the mapi structure containing the event's data
 * @param arg unused/ignored
 * @return always M_PASS
 */
static mreturn mod_privacy_deserialize(mapi m, void* arg) {
    xmlnode_list_item active_list = xmlnode_get_tags(m->serialization_node, "state:modPrivacy/privacy:active", m->si->std_namespace_prefixes);
    if (active_list != NULL)
	mod_privacy_activate_named(m->si, m->s, xmlnode_get_attrib_ns(active_list->node, "name", NULL));

    /* register callbacks */
    js_mapi_session(es_OUT, m->s, mod_privacy_out, NULL);
    js_mapi_session(es_SERIALIZE, m->s, mod_privacy_serialize, NULL);
    js_mapi_session(es_FILTER_IN, m->s, mod_privacy_filter, (void*)0);
    js_mapi_session(es_FILTER_OUT, m->s, mod_privacy_filter, (void*)1);
    js_mapi_session(es_END, m->s, mod_privacy_end_session, NULL);

    return M_PASS;
}

/**
 * add disco feature when server is queried for supported features
 *
 */
static mreturn mod_privacy_server(mapi m, void *arg) {
    xmlnode feature = NULL;

    /* sanity check */
    if (m == NULL || m->packet == NULL)
	return M_PASS;

    /* only handle iqs */
    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;

    if (!NSCHECK(m->packet->iq, NS_DISCO_INFO))
	return M_PASS;

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
    xmlnode_put_attrib_ns(feature, "var", NULL, NULL, NS_PRIVACY);

    return M_PASS;
}

/**
 * init the module, register callbacks
 *
 * Register a callback, that is called when a new session is created.
 *
 * Register a callback, that is called when a existing session is deserialized.
 *
 * @param si the session manager instance
 */
extern "C" void mod_privacy(jsmi si) {
    log_debug2(ZONE, LOGT_INIT, "mod_privacy starting up");

    js_mapi_register(si, e_SESSION, mod_privacy_session, NULL);
    js_mapi_register(si, e_DESERIALIZE, mod_privacy_deserialize, NULL);
    js_mapi_register(si, e_FILTER_IN, mod_privacy_filter, (void*)0);
    js_mapi_register(si, e_FILTER_OUT, mod_privacy_filter, (void*)1);
    js_mapi_register(si, e_ROSTERCHANGE, mod_privacy_rosterchange, NULL);
    js_mapi_register(si, e_SERVER, mod_privacy_server, NULL);
}
