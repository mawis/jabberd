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
 * --------------------------------------------------------------------------*/
#include "jsm.h"

/**
 * @file mod_roster.c
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
xmlnode mod_roster_get(udata u) {
    xmlnode ret;

    log_debug2(ZONE, LOGT_ROSTER, "getting %s's roster", u->user);

    /* get the existing roster */
    ret = xdb_get(u->si->xc, u->id, NS_ROSTER);
    if (ret == NULL) {
	/* there isn't one, sucky, create a container node and let xdb manage it */
        log_debug2(ZONE, LOGT_ROSTER, "creating");
        ret = xmlnode_new_tag("query");
        xmlnode_put_attrib(ret, "xmlns", NS_ROSTER);
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
xmlnode mod_roster_get_item(xmlnode roster, jid id, int *newflag) {
    xmlnode ret;

    log_debug2(ZONE, LOGT_ROSTER, "getting item %s", jid_full(id));

    ret = jid_nodescan(id, roster);

    if (ret == NULL) {
	/* there isn't one, brew one up */
        log_debug2(ZONE, LOGT_ROSTER, "creating");
        ret = xmlnode_insert_tag(roster, "item");
        xmlnode_put_attrib(ret, "jid", jid_full(id));
        xmlnode_put_attrib(ret, "subscription", "none");
        *newflag = 1;
    }

    return ret;
}

/**
 * push a (changed) roster item to all sessions of a user
 *
 * @param user the user's data
 * @param item the (changed) roster item to be pushed
 */
void mod_roster_push(udata user, xmlnode item) {
    session cur;
    xmlnode packet, query;

    log_debug2(ZONE, LOGT_ROSTER, "pushing %s", xmlnode2str(item));

    if (xmlnode_get_attrib(item, "hidden") != NULL) return;

    /* create a jpacket roster item push */
    packet = xmlnode_new_tag("iq");
    xmlnode_put_attrib(packet, "type", "set");
    query = xmlnode_insert_tag(packet, "query");
    xmlnode_put_attrib(query, "xmlns", NS_ROSTER);
    xmlnode_insert_tag_node(query, item);
    xmlnode_hide_attrib(xmlnode_get_firstchild(query), "subscribe"); /* hide the server tirds */

    /* send a copy to all session that have a roster */
    for(cur = user->sessions; cur != NULL; cur = cur->next)
        if (cur->roster)
            js_session_to(cur, jpacket_new(xmlnode_dup(packet)));

    xmlnode_free(packet);
}

/**
 * helper function to update the subscription state in a roster item
 *
 * @param from if the is a subscription from the contact to the user's presence
 * @param to if the user is subscribed to the contact's presence
 * @param item the roster item in which the subscription state should be changed
 */
void mod_roster_set_s10n(int from, int to, xmlnode item) {
    xmlnode_put_attrib(item, "subscription", from ? (to ? "both" : "from") : (to ? "to" : "none"));
}

/**
 * force sending all presences of a user to a contact
 *
 * @param u the user's data
 * @param to to which contact the presence should be sent
 * @param uflag 1 for forcing offline presence, 0 else
 */
void mod_roster_pforce(udata u, jid to, int uflag)
{
    session s;
    xmlnode x;

    log_debug2(ZONE, LOGT_ROSTER, "brute forcing presence updates");

    /* loop through all the sessions */
    for(s = u->sessions; s != NULL; s = s->next) {
        if (uflag)
            x = jutil_presnew(JPACKET__UNAVAILABLE,NULL,NULL);
        else
            x = xmlnode_dup(s->presence);
        xmlnode_put_attrib(x,"to",jid_full(to));
        js_session_from(s,jpacket_new(x));
    }
}

/**
 * handle subscription packets sent by a user
 *
 * @param m the mapi instance containing the packet
 * @return always M_PASS
 */
mreturn mod_roster_out_s10n(mapi m) {
    xmlnode roster, item;
    int newflag=0, to=0, from=0, p_in=0, p_out=0, route=0, force_sent=0;
    jid curr;

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
    if (j_strcmp(xmlnode_get_attrib(item, "subscription"),"to") == 0)
        to = 1;
    if (j_strcmp(xmlnode_get_attrib(item, "subscription"),"from") == 0)
        from = 1;
    if (j_strcmp(xmlnode_get_attrib(item, "subscription"),"both") == 0)
        to = from = 1;
    if (j_strcmp(xmlnode_get_attrib(item, "ask"), "subscribe") == 0)
	p_out = 1;
    if (xmlnode_get_attrib(item, "subscribe") != NULL)
	p_in = 1;

    /* ask='unsubscribe' can be in xdb from old data written by jabberd up to version 1.4.3 */
    if (j_strcmp(xmlnode_get_attrib(item, "ask"), "unsubscribe") == 0) {
	to = 0;
	xmlnode_put_attrib(item, "subscription", from ? "from" : "none");
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
		xmlnode_put_attrib(item,"ask","subscribe");
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
		xmlnode_hide_attrib(item, "subscribe"); /* reset "Pending In" */
		xmlnode_hide_attrib(item, "hidden"); /* make it visible on the user's roster */
		mod_roster_pforce(m->user, m->packet->to, 0); /* they are now subscribed to us, send them our presence */
		mod_roster_push(m->user, item); /* new roster to the user's other sessions */
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
		xmlnode_hide_attrib(item, "ask"); /* reset Pending Out */
		mod_roster_push(m->user, item);
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
		    xmlnode_hide_attrib(item, "subscribe"); /* reset "Pending In" */
		}
		if (from) {
		    mod_roster_set_s10n(0, to, item); /* update subscription */
		    mod_roster_pforce(m->user, m->packet->to, 1); /* make us offline */
		    mod_roster_push(m->user, item);
		} else if (force_sent) {
		    mod_roster_pforce(m->user, m->packet->to, 1); /* make us offline */
		}
	    }

	    if ((!route || !from && !p_in && force_sent) && newflag || xmlnode_get_attrib(item, "hidden")) {
		/* the contact was not on the roster and should not become a roster item */
		xmlnode_hide(item);
	    }
	    break;
    }

    /* save the roster */
    /* XXX what do we do if the set fails?  hrmf... */
    xdb_set(m->si->xc, m->user->id, NS_ROSTER, roster);

    /* make sure it's sent from the *user*, not the resource */
    xmlnode_put_attrib(m->packet->x,"from",jid_full(jid_user(m->s->id)));
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
mreturn mod_roster_out_iq(mapi m) {
    xmlnode roster, cur, pres, item;
    int newflag;
    jid id;

    if (!NSCHECK(m->packet->iq,NS_ROSTER)) return M_PASS;

    roster = mod_roster_get(m->user);

    switch(jpacket_subtype(m->packet)) {
	case JPACKET__GET:
	    log_debug2(ZONE, LOGT_ROSTER, "handling get request");
	    xmlnode_put_attrib(m->packet->x,"type","result");
	    m->s->roster = 1;

	    /* insert the roster into the result */
	    xmlnode_hide(m->packet->iq);
	    xmlnode_insert_tag_node(m->packet->x, roster);
	    jpacket_reset(m->packet);

	    /* filter out pending subscribes */
	    for(cur = xmlnode_get_firstchild(m->packet->iq); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
		if (xmlnode_get_attrib(cur,"subscribe") != NULL)
		    xmlnode_hide_attrib(cur,"subscribe");
		if (xmlnode_get_attrib(cur,"hidden") != NULL)
		    xmlnode_hide(cur);
	    }

	    /* send to the user */
	    js_session_to(m->s,m->packet);

	    /* redeliver those subscribes */
	    for(cur = xmlnode_get_firstchild(roster); cur != NULL; cur = xmlnode_get_nextsibling(cur))
		if (xmlnode_get_attrib(cur,"subscribe") != NULL) {
		    pres = xmlnode_new_tag("presence");
		    xmlnode_put_attrib(pres,"type","subscribe");
		    xmlnode_put_attrib(pres,"from",xmlnode_get_attrib(cur,"jid"));
		    if (strlen(xmlnode_get_attrib(cur,"subscribe")) > 0)
			xmlnode_insert_cdata(xmlnode_insert_tag(pres,"status"),xmlnode_get_attrib(cur,"subscribe"),-1);
		    js_session_to(m->s,jpacket_new(pres));
		}
	    break;
	case JPACKET__SET:
	    log_debug2(ZONE, LOGT_ROSTER, "handling set request");

	    /* loop through the incoming items updating or creating */
	    for(cur = xmlnode_get_firstchild(m->packet->iq); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
		if (xmlnode_get_type(cur) != NTYPE_TAG || xmlnode_get_attrib(cur,"jid") == NULL)
		    continue;

		id = jid_new(m->packet->p,xmlnode_get_attrib(cur,"jid"));
		if (id == NULL || jid_cmpx(jid_user(m->s->id),id,JID_USER|JID_SERVER) == 0) continue;

		/* zoom to find the existing item in the current roster, and hide it */
		item = mod_roster_get_item(roster, id, &newflag);
		xmlnode_hide(item);

		/* drop you sukkah */
		if (j_strcmp(xmlnode_get_attrib(cur,"subscription"),"remove") == 0) {
		    /* cancel our subscription to them */
		    if (j_strcmp(xmlnode_get_attrib(item,"subscription"),"both") == 0 || j_strcmp(xmlnode_get_attrib(item,"subscription"),"to") == 0 || j_strcmp(xmlnode_get_attrib(item,"ask"),"subscribe") == 0) {
			jpacket jp = jpacket_new(jutil_presnew(JPACKET__UNSUBSCRIBE,xmlnode_get_attrib(cur,"jid"),NULL));
			jp->flag = PACKET_FORCE_SENT_MAGIC; /* force to sent it, as we already remove the subscription state */
			js_session_from(m->s, jp);
		    }

		    /* tell them their subscription to us is toast */
		    if (j_strcmp(xmlnode_get_attrib(item,"subscription"),"both") == 0 || j_strcmp(xmlnode_get_attrib(item,"subscription"),"from") == 0) {
			jpacket jp = jpacket_new(jutil_presnew(JPACKET__UNSUBSCRIBED,xmlnode_get_attrib(cur,"jid"),NULL));
			jp->flag = PACKET_FORCE_SENT_MAGIC; /* force to sent it, as we already remove the subscription state */
			js_session_from(m->s, jp);
		    }

		    /* push this remove out */
		    mod_roster_push(m->user,cur);
		    continue;
		}

		/* copy the old stuff into the new one and insert it into the roster */
		xmlnode_put_attrib(cur,"subscription",xmlnode_get_attrib(item,"subscription"));
		xmlnode_put_attrib(cur,"ask",xmlnode_get_attrib(item,"ask")); /* prolly not here, but just in case */
		xmlnode_put_attrib(cur,"subscribe", xmlnode_get_attrib(item, "subscribe"));
		xmlnode_insert_tag_node(roster,cur);

		/* push the new item */
		mod_roster_push(m->user,cur);
	    }

	    /* send to the user */
	    jutil_iqresult(m->packet->x);
	    jpacket_reset(m->packet);
	    js_session_to(m->s,m->packet);

	    /* save the changes */
	    log_debug2(ZONE, LOGT_ROSTER, "SROSTER: %s",xmlnode2str(roster));
	    /* XXX what do we do if the set fails?  hrmf... */
	    xdb_set(m->si->xc, m->user->id, NS_ROSTER, roster);

	    break;
	default:
	    /* JPACKET__RESULT: result from a roster push to the client */
	    xmlnode_free(m->packet->x);
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
mreturn mod_roster_out(mapi m, void *arg)
{
    if (m->packet->type == JPACKET_IQ) return mod_roster_out_iq(m);
    if (m->packet->type == JPACKET_S10N) return mod_roster_out_s10n(m);

    return M_IGNORE;
}

/**
 * register mod_roster_out callback for outgoing stanzas when a new session starts
 *
 * @param m the mapi instance
 * @param arg unused/ignored
 * @return always M_PASS
 */
mreturn mod_roster_session(mapi m, void *arg)
{
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
mreturn mod_roster_s10n(mapi m, void *arg) {
    xmlnode roster, item, reply, reply2;
    char *status;
    session top;
    int newflag, drop, to, from, push, p_in, p_out;

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

    log_debug2(ZONE, LOGT_ROSTER, "s10n %s request from %s with existing item %s", xmlnode_get_attrib(m->packet->x, "type"), jid_full(m->packet->from), xmlnode2str(item));

    /* vars containing the old state of the subscritpion */
    if (j_strcmp(xmlnode_get_attrib(item,"subscription"),"to") == 0)
        to = 1;
    if (j_strcmp(xmlnode_get_attrib(item,"subscription"),"from") == 0)
        from = 1;
    if (j_strcmp(xmlnode_get_attrib(item,"subscription"),"both") == 0)
        to = from = 1;
    if (j_strcmp(xmlnode_get_attrib(item, "ask"), "subscribe") == 0)
	p_out = 1;
    if (xmlnode_get_attrib(item, "subscribe") != NULL)
	p_in = 1;

    /* ask='unsubscribe' can be in xdb from old data written by jabberd up to version 1.4.3 */
    if (j_strcmp(xmlnode_get_attrib(item, "ask"), "unsubscribe") == 0) {
	to = 0;
	xmlnode_put_attrib(item, "subscription", from ? "from" : "none");
    }

    switch(jpacket_subtype(m->packet)) {
	case JPACKET__SUBSCRIBE:
	    if (from) {
		/* already subscribed, respond automatically */
		reply = jutil_presnew(JPACKET__SUBSCRIBED, jid_full(m->packet->from), "Already Subscribed");
		jid_set(m->packet->to, NULL, JID_RESOURCE);
		xmlnode_put_attrib(reply, "from", jid_full(m->packet->to));
		drop = 1;

		/* the other person obviously is re-adding them to their roster, and should be told of the current presence */
		reply2 = jutil_presnew(JPACKET__PROBE,jid_full(m->packet->to),NULL);
		xmlnode_put_attrib(reply2,"from",jid_full(m->packet->from));
	    } else if (p_in) {
		/* we already know that this contact asked for subscription */
		drop = 1;
		/* no state change */
	    } else {
		/* tuck request in the roster */
		drop = 0;
		status = xmlnode_get_tag_data(m->packet->x,"status");
		if (status == NULL)
		    xmlnode_put_attrib(item,"subscribe","");
		else
		    xmlnode_put_attrib(item,"subscribe",status);
		if (newflag) /* SPECIAL CASE: special flag so that we can hide these incoming subscribe requests */
		    xmlnode_put_attrib(item,"hidden","");
	    }
	    break;
	case JPACKET__SUBSCRIBED:
	    if (to || !p_out) {
		/* already subscribed, or we don't want to subscribe: drop */
		drop = 1;
	    } else {
		/* cancel any ask, s10n=to */
		xmlnode_hide_attrib(item,"ask");
		mod_roster_set_s10n(from, 1, item);
		push = 1;
	    }
	    break;
	case JPACKET__UNSUBSCRIBE:
	    if (from || p_in) {
		/* respond automatically */
		reply = jutil_presnew(JPACKET__UNSUBSCRIBED,jid_full(m->packet->from),"Autoreply");
		jid_set(m->packet->to,NULL,JID_RESOURCE);
		xmlnode_put_attrib(reply,"from",jid_full(m->packet->to));

		/* update state */
		xmlnode_hide_attrib(item,"subscribe");
		mod_roster_set_s10n(0, to, item);
		if (xmlnode_get_attrib(item,"hidden") != NULL)
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
		xmlnode_hide_attrib(item,"ask");
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

    /* these are delayed until after we check the roster back in, avoid rancid race conditions */
    if (reply != NULL)
	js_deliver(m->si,jpacket_new(reply));
    if (reply2 != NULL)
	js_deliver(m->si,jpacket_new(reply2));

    /* find primary session */
    top = js_session_primary(m->user);

    /* if we can, deliver this to that session */
    if (!drop && top != NULL && top->roster)
	js_session_to(top,m->packet);
    else
	xmlnode_free(m->packet->x);

    if (push)
        mod_roster_push(m->user,item);

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
mreturn mod_roster_delete(mapi m, void *arg) {
    xmlnode roster = NULL;
    xmlnode cur = NULL;
    pool p = pool_new();

    /* remove subscriptions */
    roster = xdb_get(m->si->xc, m->user->id, NS_ROSTER);
    for (cur = xmlnode_get_firstchild(roster); cur!=NULL; cur=xmlnode_get_nextsibling(cur)) {
	int unsubscribe = 0, unsubscribed = 0;
	jid peer;
	char *subscription;
	jpacket jp = NULL;

	peer = jid_new(p, xmlnode_get_attrib(cur, "jid"));
	subscription = xmlnode_get_attrib(cur, "subscription");

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
	if (xmlnode_get_attrib(cur, "ask"))
	    unsubscribe = 1;
	if (xmlnode_get_attrib(cur, "subscribe"))
	    unsubscribed = 1;

	/* send the unsubscribe/unsubscribed requests */
	if (unsubscribe) {
	    xmlnode pp = jutil_presnew(JPACKET__UNSUBSCRIBE, jid_full(peer), NULL);
	    xmlnode_put_attrib(pp, "from", jid_full(m->user->id));
	    jp = jpacket_new(pp);
	    jp->flag = PACKET_FORCE_SENT_MAGIC; /* we are removing the roster, sent anyway */
	    js_deliver(m->si, jp);
	}
	if (unsubscribed) {
	    xmlnode pp = jutil_presnew(JPACKET__UNSUBSCRIBED, jid_full(peer), NULL);
	    xmlnode_put_attrib(pp, "from", jid_full(m->user->id));
	    jp = jpacket_new(pp);
	    jp->flag = PACKET_FORCE_SENT_MAGIC; /* we are removing the roster, sent anyway */
	    js_deliver(m->si, jp);
	}
    }
    xmlnode_free(roster);

    pool_free(p);

    /* remove roster */
    xdb_set(m->si->xc, m->user->id, NS_ROSTER, NULL);
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
void mod_roster(jsmi si)
{
    /* we just register for new sessions */
    js_mapi_register(si,e_SESSION,mod_roster_session,NULL);
    js_mapi_register(si,e_DELIVER,mod_roster_s10n,NULL);
    js_mapi_register(si, e_DELETE, mod_roster_delete, NULL);
}
