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
 * @file mod_roster.cc
 * @brief handle subscription state changes and the user's access to his roster
 *
 * The protocols implemented in this module are documented in XMPP IM.
 */

/**
 * get the roster of a user
 *
 * @param u for which user we want to get the roster
 * @return the user's roster
 */
static xmlnode mod_roster_get(udata u) {
    xmlnode ret;

    log_debug2(ZONE, LOGT_ROSTER, "getting %s's roster", u->id->user);

    /* get the existing roster */
    ret = xdb_get(u->si->xc, u->id, NS_ROSTER);
    if (ret == NULL) {
	/* there isn't one, sucky, create a container node and let xdb manage it */
        log_debug2(ZONE, LOGT_ROSTER, "creating");
        ret = xmlnode_new_tag_ns("query", NULL, NS_ROSTER);
    }

    return ret;
}

/**
 * get a single item from the user's roster
 *
 * @param roster the complete roster from which the item should be gotten
 * @param id which item should be gotten
 * @param newflag where to store 1 if the item did not exist and has just been created
 * @return the roster item
 */
static xmlnode mod_roster_get_item(xmlnode roster, jid id, int *newflag) {
    xmlnode ret;

    log_debug2(ZONE, LOGT_ROSTER, "getting item %s", jid_full(id));

    ret = jid_nodescan(id, roster);

    if (ret == NULL) {
	/* there isn't one, brew one up */
        log_debug2(ZONE, LOGT_ROSTER, "creating");
        ret = xmlnode_insert_tag_ns(roster, "item", NULL, NS_ROSTER);
        xmlnode_put_attrib_ns(ret, "jid", NULL, NULL, jid_full(id));
        xmlnode_put_attrib_ns(ret, "subscription", NULL, NULL, "none");
        *newflag = 1;
    }

    return ret;
}

/**
 * notify modules that are interested in, that a roster has changed
 *
 */
static void mod_roster_changed(udata user, xmlnode roster) {
    xmlnode iq = jutil_iqnew(JPACKET__SET, NULL);
    xmlnode_insert_tag_node(iq, roster);

    if (!js_mapi_call(user->si, e_ROSTERCHANGE, jpacket_new(iq), user, NULL)) {
	xmlnode_free(iq);
    }
}

/**
 * push a (changed) roster item to all sessions of a user
 *
 * @param user the user's data
 * @param item the (changed) roster item to be pushed
 */
static void mod_roster_push(udata user, xmlnode item) {
    session cur;
    xmlnode packet, query;

    log_debug2(ZONE, LOGT_ROSTER, "pushing %s", xmlnode_serialize_string(item, xmppd::ns_decl_list(), 0));

    if (xmlnode_get_attrib_ns(item, "hidden", NULL) != NULL)
	return;

    /* create a jpacket roster item push */
    packet = xmlnode_new_tag_ns("iq", NULL, NS_SERVER);
    xmlnode_put_attrib_ns(packet, "type", NULL, NULL, "set");
    query = xmlnode_insert_tag_ns(packet, "query", NULL, NS_ROSTER);
    xmlnode_insert_tag_node(query, item);
    xmlnode_hide_attrib_ns(xmlnode_get_firstchild(query), "subscribe", NULL); /* hide the server tirds */

    /* send a copy to all session that have a roster */
    for(cur = user->sessions; cur != NULL; cur = cur->next) {
        if (cur->roster) {
            js_session_to(cur, jpacket_new(xmlnode_dup(packet)));
	}
    }

    xmlnode_free(packet);
}

/**
 * helper function to update the subscription state in a roster item
 *
 * @param from if the is a subscription from the contact to the user's presence
 * @param to if the user is subscribed to the contact's presence
 * @param item the roster item in which the subscription state should be changed
 */
static void mod_roster_set_s10n(int from, int to, xmlnode item) {
    xmlnode_put_attrib_ns(item, "subscription", NULL, NULL, from ? (to ? "both" : "from") : (to ? "to" : "none"));
}

/**
 * force sending all presences of a user to a contact
 *
 * @param u the user's data
 * @param to to which contact the presence should be sent
 * @param uflag 1 for forcing offline presence, 0 else
 */
static void mod_roster_pforce(udata u, jid to, int uflag) {
    session s;
    xmlnode x;

    log_debug2(ZONE, LOGT_ROSTER, "brute forcing presence updates");

    /* loop through all the sessions */
    for (s = u->sessions; s != NULL; s = s->next) {
        if (uflag)
            x = jutil_presnew(JPACKET__UNAVAILABLE,NULL,NULL);
        else
            x = xmlnode_dup(s->presence);
        xmlnode_put_attrib_ns(x, "to", NULL, NULL, jid_full(to));
        js_session_from(s,jpacket_new(x));
    }
}

/**
 * handle subscription packets sent by a user
 *
 * @param m the mapi instance containing the packet
 * @return always M_PASS
 */
static mreturn mod_roster_out_s10n(mapi m) {
    xmlnode roster, item;
    int newflag=0, to=0, from=0, p_in=0, p_out=0, route=0, force_sent=0;
    jid curr;
    int rosterchange = 0;

    /* the packet needs a destination */
    if (m->packet->to == NULL)
	return M_PASS;

    /* don't handle subscription packets sent to the user itself */
    if (jid_cmpx(jid_user(m->s->id), m->packet->to, JID_USER|JID_SERVER) == 0)
	return M_PASS; /* vanity complex */

    log_debug2(ZONE, LOGT_ROSTER, "handling outgoing s10n");

    /* get the roster item */
    roster = mod_roster_get(m->user);
    item = mod_roster_get_item(roster, m->packet->to, &newflag);

    /* vars containing the old subscription state */
    if (j_strcmp(xmlnode_get_attrib_ns(item, "subscription", NULL), "to") == 0)
        to = 1;
    if (j_strcmp(xmlnode_get_attrib_ns(item, "subscription", NULL), "from") == 0)
        from = 1;
    if (j_strcmp(xmlnode_get_attrib_ns(item, "subscription", NULL), "both") == 0)
        to = from = 1;
    if (j_strcmp(xmlnode_get_attrib_ns(item, "ask", NULL), "subscribe") == 0)
	p_out = 1;
    if (xmlnode_get_attrib_ns(item, "subscribe", NULL) != NULL)
	p_in = 1;

    /* ask='unsubscribe' can be in xdb from old data written by jabberd up to version 1.4.3 */
    if (j_strcmp(xmlnode_get_attrib_ns(item, "ask", NULL), "unsubscribe") == 0) {
	to = 0;
	xmlnode_put_attrib_ns(item, "subscription", NULL, NULL, from ? "from" : "none");
    }

    /* if the packet is flagged with PACKET_FORCE_SENT_MAGIC we have to sent
     * it out without checking the previous subscription state. The packet
     * has been generated because a roster item has been removed, so we will
     * see a state of subscription "none" but we have to inform the other
     * server that the subscription has just been removed. */
    force_sent = m->packet->flag == PACKET_FORCE_SENT_MAGIC ? 1 : 0;

    switch(jpacket_subtype(m->packet)) {
	case JPACKET__SUBSCRIBE:
	    /* is the user already subscribed to this contact? */
	    if (!to) {
		/* no */
		xmlnode_put_attrib_ns(item, "ask", NULL, NULL, "subscribe");
		rosterchange = 1;
		mod_roster_push(m->user, item);
	    }
	    /* always route the packet, the user might have rerequested auth
	     * because the contact's server is out of sync */
	    route = 1;
	    break;
	case JPACKET__SUBSCRIBED:
	    if (force_sent || (!from && p_in)) {
		/* XMPP IM, sect. 9 states "None + Pending In", "None + Pending Out/In", and "To + Pending In" */
		route = 1;
		mod_roster_set_s10n(1, to, item); /* update subscription */
		jid_append(js_trustees(m->user), m->packet->to); /* make them trusted now */
		xmlnode_hide_attrib_ns(item, "subscribe", NULL); /* reset "Pending In" */
		xmlnode_hide_attrib_ns(item, "hidden", NULL); /* make it visible on the user's roster */
		mod_roster_pforce(m->user, m->packet->to, 0); /* they are now subscribed to us, send them our presence */
		rosterchange = 1;
		mod_roster_push(m->user, item); /* new roster to the user's other sessions */

		/* delete stored subscription request from xdb */
		xdb_act_path(m->si->xc, m->user->id, NS_JABBERD_STOREDREQUEST, "insert", spools(m->packet->p, "presence[@from='", jid_full(m->packet->to), "']", m->packet->p), m->si->std_namespace_prefixes, NULL);
	    } else {
		/* XMPP IM, sect. 9 other states */
		route = 0;
		/* no state change */
	    }
	    break;
	case JPACKET__UNSUBSCRIBE:
	    if (to) {
		/* changed behaviour since after version 1.4.3 ... we now immediatelly change to state "From" or "None"
		 * jabberd up to version 1.4.3 only set the flag ask="unsubscribe" and waited for an unsubscribed
		 * configirmation from the contact's server
		 */
		mod_roster_set_s10n(from, 0, item);
		xmlnode_hide_attrib_ns(item, "ask", NULL); /* reset Pending Out */
		rosterchange = 1;
		mod_roster_push(m->user, item);
		js_remove_seen(m->user, m->packet->to);
	    } else if (newflag) {
		/* the contact was not on the roster and should not become a roster item */
		xmlnode_hide(item);
	    }
	    /* always route the packet, the user might have unsubscribed a second time
	     * because the contact's server is out of sync */
	    route = 1;
	    break;
	case JPACKET__UNSUBSCRIBED:
	    if (!from && !p_in && !force_sent) {
		/* XMPP IM, sect. 9 states "None", "None + Pending Out", and "To" */
		route = 0;
		/* no state change */
	    } else {
		/* other states */
		route = 1;

		if (p_in) {
		    xmlnode_hide_attrib_ns(item, "subscribe", NULL); /* reset "Pending In" */
		}
		js_remove_trustee(m->user, m->packet->to);
		if (from) {
		    mod_roster_set_s10n(0, to, item); /* update subscription */
		    mod_roster_pforce(m->user, m->packet->to, 1); /* make us offline */
		    rosterchange = 1;
		    mod_roster_push(m->user, item);
		} else if (force_sent) {
		    mod_roster_pforce(m->user, m->packet->to, 1); /* make us offline */
		}
	    }

	    if ((!route || !from && !p_in && force_sent) && newflag || xmlnode_get_attrib_ns(item, "hidden", NULL)) {
		/* the contact was not on the roster and should not become a roster item */
		xmlnode_hide(item);
	    }
	    break;
    }

    /* save the roster */
    /* XXX what do we do if the set fails?  hrmf... */
    xdb_set(m->si->xc, m->user->id, NS_ROSTER, roster);

    if (rosterchange) {
	/* fire event to notify about changed roster */
	mod_roster_changed(m->user, roster);
    }

    /* make sure it's sent from the *user*, not the resource */
    xmlnode_put_attrib_ns(m->packet->x, "from", NULL, NULL, jid_full(jid_user(m->s->id)));
    jpacket_reset(m->packet);

    /* we don't need the roster anymore */
    xmlnode_free(roster);

    /* should the packet passed to the contact? */
    return route ? M_PASS : M_HANDLED;
}

/**
 * handle packets sent by the user in the jabber:iq:roster namespace
 *
 * @param mapi the mapi instance containing the packet
 * @return M_PASS if not in the jabber:iq:roster namespace, M_HANDLED otherwise
 */
static mreturn mod_roster_out_iq(mapi m) {
    xmlnode roster, pres, item;
    int newflag;
    jid id;
    xmlnode_list_item iter = NULL;
    int rosterchange = 0;

    if (!NSCHECK(m->packet->iq,NS_ROSTER)) return M_PASS;

    roster = mod_roster_get(m->user);

    switch(jpacket_subtype(m->packet)) {
	case JPACKET__GET:
	    log_debug2(ZONE, LOGT_ROSTER, "handling get request");
	    xmlnode_put_attrib_ns(m->packet->x, "type", NULL, NULL, "result");
	    m->s->roster = 1;

	    /* insert the roster into the result */
	    xmlnode_hide(m->packet->iq);
	    xmlnode_insert_tag_node(m->packet->x, roster);
	    jpacket_reset(m->packet);

	    /* filter out pending subscribes */
	    for (iter = xmlnode_get_tags(m->packet->iq, "roster:item", m->si->std_namespace_prefixes); iter != NULL; iter = iter->next) {
		if (xmlnode_get_attrib_ns(iter->node, "subscribe", NULL) != NULL)
		    xmlnode_hide_attrib_ns(iter->node, "subscribe", NULL);
		if (xmlnode_get_attrib_ns(iter->node, "hidden", NULL) != NULL)
		    xmlnode_hide(iter->node);
	    }

	    /* send to the user */
	    js_session_to(m->s,m->packet);

	    /* redeliver those subscribes */
	    for (iter = xmlnode_get_tags(roster, "roster:item", m->si->std_namespace_prefixes); iter != NULL; iter = iter->next) {
		if (xmlnode_get_attrib_ns(iter->node, "subscribe", NULL) != NULL) {
		    /* is there a stored version of the subscription request in xdb? */
		    xmlnode stored_subscribes = xdb_get(m->si->xc, m->user->id, NS_JABBERD_STOREDREQUEST);
		    pres =  xmlnode_dup(xmlnode_get_list_item(xmlnode_get_tags(stored_subscribes, spools(xmlnode_pool(iter->node), "presence[@from='", xmlnode_get_attrib_ns(iter->node, "jid", NULL), "']", xmlnode_pool(iter->node)), m->si->std_namespace_prefixes), 0));

		    /* if there is nothing in xdb, create a subscription request */
		    if (pres == NULL) {
			pres = xmlnode_new_tag_ns("presence", NULL, NS_SERVER);
			xmlnode_put_attrib_ns(pres, "type", NULL, NULL, "subscribe");
			xmlnode_put_attrib_ns(pres, "from", NULL, NULL, xmlnode_get_attrib_ns(iter->node, "jid", NULL));
			if (j_strlen(xmlnode_get_attrib_ns(iter->node, "subscribe", NULL)) > 0)
			    xmlnode_insert_cdata(xmlnode_insert_tag_ns(pres, "status", NULL, NS_SERVER), xmlnode_get_attrib_ns(iter->node, "subscribe", NULL),-1);
		    }
		    js_session_to(m->s,jpacket_new(pres));

		    if (stored_subscribes != NULL)
			xmlnode_free(stored_subscribes);
		}
	    }
	    break;
	case JPACKET__SET:
	    log_debug2(ZONE, LOGT_ROSTER, "handling set request");

	    /* loop through the incoming items updating or creating */
	    for (iter = xmlnode_get_tags(m->packet->iq, "roster:item[@jid]", m->si->std_namespace_prefixes); iter != NULL; iter = iter->next) {
		id = jid_new(m->packet->p, xmlnode_get_attrib_ns(iter->node, "jid", NULL));
		if (id == NULL || jid_cmpx(jid_user(m->s->id), id, JID_USER|JID_SERVER) == 0)
		    continue;

		/* zoom to find the existing item in the current roster, and hide it */
		item = mod_roster_get_item(roster, id, &newflag);
		xmlnode_hide(item);

		/* drop you sukkah */
		if (j_strcmp(xmlnode_get_attrib_ns(iter->node, "subscription", NULL),"remove") == 0) {
		    /* cancel our subscription to them */
		    if (j_strcmp(xmlnode_get_attrib_ns(item, "subscription", NULL),"both") == 0
			    || j_strcmp(xmlnode_get_attrib_ns(item, "subscription", NULL),"to") == 0
			    || j_strcmp(xmlnode_get_attrib_ns(item, "ask", NULL),"subscribe") == 0) {
			jpacket jp = jpacket_new(jutil_presnew(JPACKET__UNSUBSCRIBE,xmlnode_get_attrib_ns(iter->node, "jid", NULL), NULL));
			jp->flag = PACKET_FORCE_SENT_MAGIC; /* force to sent it, as we already remove the subscription state */
			js_session_from(m->s, jp);
		    }

		    /* tell them their subscription to us is toast */
		    if (j_strcmp(xmlnode_get_attrib_ns(item, "subscription", NULL),"both") == 0
			    || j_strcmp(xmlnode_get_attrib_ns(item, "subscription", NULL),"from") == 0) {
			jpacket jp = jpacket_new(jutil_presnew(JPACKET__UNSUBSCRIBED,xmlnode_get_attrib_ns(iter->node, "jid", NULL), NULL));
			jp->flag = PACKET_FORCE_SENT_MAGIC; /* force to sent it, as we already remove the subscription state */
			js_session_from(m->s, jp);
		    }

		    /* push this remove out */
		    rosterchange = 1;
		    mod_roster_push(m->user,iter->node);
		    continue;
		}

		/* copy the old stuff into the new one and insert it into the roster */
		xmlnode_put_attrib_ns(iter->node, "subscription", NULL, NULL, xmlnode_get_attrib_ns(item, "subscription", NULL));
		xmlnode_put_attrib_ns(iter->node, "ask", NULL, NULL, xmlnode_get_attrib_ns(item, "ask", NULL)); /* prolly not here, but just in case */
		xmlnode_put_attrib_ns(iter->node, "subscribe", NULL, NULL, xmlnode_get_attrib_ns(item, "subscribe", NULL));
		xmlnode_insert_tag_node(roster,iter->node);

		/* push the new item */
		rosterchange = 1;
		mod_roster_push(m->user,iter->node);
	    }

	    /* send to the user */
	    jutil_iqresult(m->packet->x);
	    jpacket_reset(m->packet);
	    js_session_to(m->s,m->packet);

	    /* save the changes */
	    log_debug2(ZONE, LOGT_ROSTER, "SROSTER: %s",xmlnode_serialize_string(roster, xmppd::ns_decl_list(), 0));
	    /* XXX what do we do if the set fails?  hrmf... */
	    xdb_set(m->si->xc, m->user->id, NS_ROSTER, roster);

	    break;
	default:
	    /* JPACKET__RESULT: result from a roster push to the client */
	    xmlnode_free(m->packet->x);
    }

    if (rosterchange) {
	/* fire event to notify about changed roster */
	mod_roster_changed(m->user, roster);
    }

    xmlnode_free(roster);
    return M_HANDLED;
}

/**
 * handle outgoing packets: check for iq and subscription stanzas
 *
 * @param m the mapi instance (containing the packet)
 * @param arg not used/ignored
 * @return M_IGNORE if the packet is not an iq or subscription packet, else M_PASS if packet not handled or M_HANDLED if packet handled
 */
static mreturn mod_roster_out(mapi m, void *arg) {
    if (m->packet->type == JPACKET_IQ)
	return mod_roster_out_iq(m);
    if (m->packet->type == JPACKET_S10N)
	return mod_roster_out_s10n(m);

    return M_IGNORE;
}

/**
 * register mod_roster_out callback for outgoing stanzas when a new session starts
 *
 * @param m the mapi instance
 * @param arg unused/ignored
 * @return always M_PASS
 */
static mreturn mod_roster_session(mapi m, void *arg) {
    js_mapi_session(es_OUT,m->s,mod_roster_out,NULL);
    return M_PASS;
}

/**
 * handles subscription stanzas sent to an user
 *
 * @param m the mapi instance
 * @param arg not used/ignored
 * @return I_IGNORE if not a subscription stanza, else M_PASS if not handled or M_HANDLED if handled
 */
static mreturn mod_roster_s10n(mapi m, void *arg) {
    xmlnode roster, item, reply, reply2;
    char *status;
    session top;
    int newflag, drop, to, from, push, p_in, p_out;
    int store_request = 0;

    push = newflag = drop = to = from = p_in = p_out = 0;

    /* check for incoming s10n (subscription) requests */
    if (m->packet->type != JPACKET_S10N) return M_IGNORE;

    /* the user must exist */
    if (m->user == NULL) return M_PASS;

    /* don't handle packets sent from the user to himself */
    if (jid_cmpx(m->packet->from, m->packet->to, JID_USER|JID_SERVER) == 0) return M_PASS; /* vanity complex */

    /* now we can get to work and handle this user's incoming subscription crap */
    roster = mod_roster_get(m->user);
    item = mod_roster_get_item(roster, m->packet->from, &newflag);
    reply2 = reply = NULL;
    jid_set(m->packet->to, NULL, JID_RESOURCE); /* make sure we're only dealing w/ the user id */

    log_debug2(ZONE, LOGT_ROSTER, "s10n %s request from %s with existing item %s", xmlnode_get_attrib_ns(m->packet->x, "type", NULL), jid_full(m->packet->from), xmlnode_serialize_string(item, xmppd::ns_decl_list(), 0));

    /* vars containing the old state of the subscritpion */
    if (j_strcmp(xmlnode_get_attrib_ns(item, "subscription", NULL), "to") == 0)
        to = 1;
    if (j_strcmp(xmlnode_get_attrib_ns(item, "subscription", NULL), "from") == 0)
        from = 1;
    if (j_strcmp(xmlnode_get_attrib_ns(item, "subscription", NULL), "both") == 0)
        to = from = 1;
    if (j_strcmp(xmlnode_get_attrib_ns(item, "ask", NULL), "subscribe") == 0)
	p_out = 1;
    if (xmlnode_get_attrib_ns(item, "subscribe", NULL) != NULL)
	p_in = 1;

    /* ask='unsubscribe' can be in xdb from old data written by jabberd up to version 1.4.3 */
    if (j_strcmp(xmlnode_get_attrib_ns(item, "ask", NULL), "unsubscribe") == 0) {
	to = 0;
	xmlnode_put_attrib_ns(item, "subscription", NULL, NULL, from ? "from" : "none");
    }

    switch(jpacket_subtype(m->packet)) {
	case JPACKET__SUBSCRIBE:
	    if (from) {
		/* already subscribed, respond automatically */
		reply = jutil_presnew(JPACKET__SUBSCRIBED, jid_full(m->packet->from), messages_get(xmlnode_get_lang(m->packet->x), N_("Already Subscribed")));
		jid_set(m->packet->to, NULL, JID_RESOURCE);
		xmlnode_put_attrib_ns(reply, "from", NULL, NULL, jid_full(m->packet->to));
		drop = 1;

		/* the other person obviously is re-adding them to their roster, and should be told of the current presence */
		reply2 = jutil_presnew(JPACKET__PROBE,jid_full(m->packet->to),NULL);
		xmlnode_put_attrib_ns(reply2, "from", NULL, NULL, jid_full(m->packet->from));
	    } else if (p_in) {
		/* we already know that this contact asked for subscription */
		drop = 1;
		/* no state change */

		/* but we update the subscription request in xdb */
		store_request = 1;
	    } else {
		/* tuck request in the roster */
		drop = 0;
		status = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(m->packet->x, "status", m->si->std_namespace_prefixes), 0));
		if (status == NULL)
		    xmlnode_put_attrib_ns(item, "subscribe", NULL, NULL, "");
		else
		    xmlnode_put_attrib_ns(item, "subscribe", NULL, NULL, status);
		if (newflag) /* SPECIAL CASE: special flag so that we can hide these incoming subscribe requests */
		    xmlnode_put_attrib_ns(item, "hidden", NULL, NULL, "");

		/* store the request stanza in xdb */
		store_request = 1;
	    }
	    break;
	case JPACKET__SUBSCRIBED:
	    if (to || !p_out) {
		/* already subscribed, or we don't want to subscribe: drop */
		drop = 1;
	    } else {
		/* cancel any ask, s10n=to */
		xmlnode_hide_attrib_ns(item, "ask", NULL);
		mod_roster_set_s10n(from, 1, item);
		push = 1;
		jid_append(js_seen_jids(m->user), m->packet->from); /* make them seen now */
	    }
	    break;
	case JPACKET__UNSUBSCRIBE:
	    if (from || p_in) {
		/* respond automatically */
		reply = jutil_presnew(JPACKET__UNSUBSCRIBED,jid_full(m->packet->from), messages_get(xmlnode_get_lang(m->packet->x), N_("Autoreply")));
		jid_set(m->packet->to,NULL,JID_RESOURCE);
		xmlnode_put_attrib_ns(reply, "from", NULL, NULL, jid_full(m->packet->to));

		/* update state */
		js_remove_trustee(m->user, m->packet->from);
		xmlnode_hide_attrib_ns(item, "subscribe", NULL);
		mod_roster_set_s10n(0, to, item);
		if (xmlnode_get_attrib_ns(item, "hidden", NULL) != NULL)
		    xmlnode_hide(item);
		else
		    push = 1;
	    } else {
		if (newflag)
		    xmlnode_hide(item);
		drop = 1;
	    }
	    break;
	case JPACKET__UNSUBSCRIBED:
	    if (to || p_out) {
		/* cancel any ask, remove s10n=to */
		xmlnode_hide_attrib_ns(item, "ask", NULL);
		mod_roster_set_s10n(from, 0, item);
		push = 1;
	    } else {
		if (newflag)
		    xmlnode_hide(item);
		drop = 1;
	    }
    }

    /* XXX what do we do if the set fails?  hrmf... */
    xdb_set(m->si->xc, m->user->id, NS_ROSTER, roster);

    /* store the request in xdb */
    if (store_request) {
	xmlnode request = xmlnode_dup(m->packet->x);
	jutil_delay(request, N_("Offline Storage"));
	xdb_act_path(m->si->xc, m->user->id, NS_JABBERD_STOREDREQUEST, "insert", spools(m->packet->p, "presence[@from='", jid_full(m->packet->from), "']", m->packet->p), m->si->std_namespace_prefixes, request);
    }

    /* these are delayed until after we check the roster back in, avoid rancid race conditions */
    if (reply != NULL)
	js_deliver(m->si, jpacket_new(reply), m->s);
    if (reply2 != NULL)
	js_deliver(m->si, jpacket_new(reply2), m->s);

    /* find primary session */
    top = js_session_primary(m->user);

    /* if we can, deliver this to that session */
    if (!drop && top != NULL && top->roster)
	js_session_to(top,m->packet);
    else
	xmlnode_free(m->packet->x);

    if (push) {
        mod_roster_push(m->user,item);

	/* fire event to notify about changed roster */
	mod_roster_changed(m->user, roster);
    }

    xmlnode_free(roster);
    return M_HANDLED;
}

/**
 * delete the roster of a user if the user is deleted
 *
 * @param m the mapi_struct
 * @param arg unused/ignored
 * @return always M_PASS
 */
static mreturn mod_roster_delete(mapi m, void *arg) {
    xmlnode roster = NULL;
    pool p = pool_new();
    xmlnode_list_item iter = NULL;

    /* remove subscriptions */
    roster = xdb_get(m->si->xc, m->user->id, NS_ROSTER);
    for (iter = xmlnode_get_tags(roster, "roster:item[@subscription]", m->si->std_namespace_prefixes); iter != NULL; iter = iter->next) {
	int unsubscribe = 0, unsubscribed = 0;
	jid peer;
	char *subscription;
	jpacket jp = NULL;

	peer = jid_new(p, xmlnode_get_attrib_ns(iter->node, "jid", NULL));
	subscription = xmlnode_get_attrib_ns(iter->node, "subscription", NULL);

	log_debug2(ZONE, LOGT_ROSTER, "removing subscription %s (%s)", subscription, jid_full(peer));

	if (subscription == NULL)
	    continue;

	/* unsubscribe for existing subscriptions */
	if (j_strcmp(subscription, "to") == 0)
	    unsubscribe = 1;
	else if (j_strcmp(subscription, "from") == 0)
	    unsubscribed = 1;
	else if (j_strcmp(subscription, "both") == 0)
	    unsubscribe = unsubscribed = 1;

	/* unsubscribe for requested subscriptions */
	if (xmlnode_get_attrib_ns(iter->node, "ask", NULL))
	    unsubscribe = 1;
	if (xmlnode_get_attrib_ns(iter->node, "subscribe", NULL))
	    unsubscribed = 1;

	/* send the unsubscribe/unsubscribed requests */
	if (unsubscribe) {
	    xmlnode pp = jutil_presnew(JPACKET__UNSUBSCRIBE, jid_full(peer), NULL);
	    xmlnode_put_attrib_ns(pp, "from", NULL, NULL, jid_full(m->user->id));
	    jp = jpacket_new(pp);
	    jp->flag = PACKET_FORCE_SENT_MAGIC; /* we are removing the roster, sent anyway */
	    js_deliver(m->si, jp, m->s);
	}
	if (unsubscribed) {
	    xmlnode pp = jutil_presnew(JPACKET__UNSUBSCRIBED, jid_full(peer), NULL);
	    xmlnode_put_attrib_ns(pp, "from", NULL, NULL, jid_full(m->user->id));
	    jp = jpacket_new(pp);
	    jp->flag = PACKET_FORCE_SENT_MAGIC; /* we are removing the roster, sent anyway */
	    js_deliver(m->si, jp, m->s);
	}
    }
    xmlnode_free(roster);

    pool_free(p);

    /* remove roster */
    xdb_set(m->si->xc, m->user->id, NS_ROSTER, NULL);

    /* remove stored subscription requests */
    xdb_set(m->si->xc, m->user->id, NS_JABBERD_STOREDREQUEST, NULL);

    return M_PASS;
}

/**
 * init the mod_roster module
 *
 * Register the following callbacks:
 * - mod_roster_session for new sessions
 * - mod_roster_s10n for stanzas send to a user
 *
 * @param si the session manager instance
 */
extern "C" void mod_roster(jsmi si) {
    /* we just register for new sessions */
    js_mapi_register(si,e_SESSION,mod_roster_session,NULL);
    js_mapi_register(si,e_DESERIALIZE, mod_roster_session, NULL);
    js_mapi_register(si,e_DELIVER,mod_roster_s10n,NULL);
    js_mapi_register(si, e_DELETE, mod_roster_delete, NULL);
}
