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
 * @file jsm/deliver.cc
 * @brief handle incoming packets and check how they can be delivered
 */

/**
 * handle stanzas addressed to one of the users handled by this jsm's hosts.
 *
 * Attempts to deliver it to the correct session/thread,
 * must have a valid to/from address already before getting here
 *
 * It is first tried if one of the e_DELIVER modules handles the packets,
 * iff not stanzas addressed to the server itself are passed to
 * js_server_main(), packets explicitly addressed to a resource (session)
 * are passed to js_session_to(), and packets addressed to a user are passed
 * to js_offline_main(), other stanzas are bounced as "item-not-found".
 *
 * @param si the session manager instance
 * @param p the packet to deliver
 * @param ht the hash table containing the users of the relevant host
 */
static void js_deliver_local(jsmi si, jpacket p, xht ht) {
    int incremented = 0;
    udata user = NULL;
    session s = NULL;

    /* first, collect some facts */
    user = js_user(si, p->to, ht);
    s = js_session_get(user, p->to->resource);

    /* lock the udata from being freed while we are working on it */
    if (user != NULL) {
	user->ref++;
	incremented++;
    }

    log_debug2(ZONE, LOGT_DELIVER, "delivering locally to %s",jid_full(p->to));
    /* let some modules fight over it */
    if(js_mapi_call(si, e_DELIVER, p, user, s)) {
	/* the packet has been handled by one of the modules */

	if (incremented != 0) {
	    user->ref--;	/* release lock */
	}
        return;
    }

    if(p->to->user == NULL) {
	/* this is for the server */
        js_psend(si,p,js_server_main);
	if (incremented != 0) {
	    user->ref--;	/* release lock */
	}
        return;
    }

    /* the packet has neither been handled by the e_DELIVER modules nor was for the server */

    /* if the stanza is a message, we reroute to the top session, if we have no session yet */
    if (p->type == JPACKET_MESSAGE && user != NULL && s == NULL) {
	session top = js_session_primary(user);

	if (top != NULL && top->priority >= 0) {
	    s = top;
	}
    }

    if(s != NULL) {
	/* it's sent right to the resource */
        js_session_to(s, p);
	if (incremented != 0) {
	    user->ref--;	/* release lock */
	}
        return;
    }

    if(user != NULL) {
	/* valid user, but no session */
        p->aux1 = (void *)user; /* performance hack, we already know the user */
        js_psend(si,p,js_offline_main);
	/* the offline thread will release our lock on the udata structure */
        return;
    }

    /* release lock on the udata structure */
    if (incremented != 0) {
	user->ref--;
    }

    /* presence probe for a non-existant user? send unsubscribed */
    if (p->type == JPACKET_PRESENCE && jpacket_subtype(p)==JPACKET__PROBE) {
	jpacket jp = NULL;
	xmlnode presence_unsubscribed = jutil_presnew(JPACKET__UNSUBSCRIBED, jid_full(p->from), NULL);
	xmlnode_put_attrib_ns(presence_unsubscribed, "from", NULL, NULL, jid_full(jid_user(p->to)));
	jp = jpacket_new(presence_unsubscribed);
	jp->flag = PACKET_FORCE_SENT_MAGIC;
	js_deliver(si, jp, NULL);

	log_notice(si->i->id, "got presence probe from '%s' for non-existant user '%s' => sent unsubscribed", jid_full(p->from), jid_full(p->to));
    } else if (p->type == JPACKET_PRESENCE && jpacket_subtype(p) != JPACKET__ERROR && jpacket_subtype(p) != JPACKET__UNAVAILABLE) {
	/* presence to an unexistant user ... send unsubscribe */
	jpacket jp = NULL;
	xmlnode presence_unsubscribe = jutil_presnew(JPACKET__UNSUBSCRIBE, jid_full(p->from), NULL);
	xmlnode_put_attrib_ns(presence_unsubscribe, "from", NULL, NULL, jid_full(jid_user(p->to)));
	jp = jpacket_new(presence_unsubscribe);
	jp->flag = PACKET_FORCE_SENT_MAGIC;
	js_deliver(si, jp, NULL);

	log_notice(si->i->id, "got presence from '%s' for non-existant user '%s' => sent unsubscribe", jid_full(p->from), jid_full(p->to));
    }

    /* no user, so bounce the packet */
    js_bounce_xmpp(si, NULL, p->x, XTERROR_NOTFOUND);
}

/**
 * handle incoming &lt;route type='session'/&gt; packets, we get passed from jabberd:
 * create a new session
 *
 * @param i the jsm instance we are running in
 * @param p the packet we should receive
 * @param si our jsm instance internal data
 * @return always r_DONE
 */
result _js_routed_session_packet(instance i, dpacket p, jsmi si) {
    session s = NULL;		/* the new session */

    /* try to create the new session */
    if ((s = js_session_new(si, p)) == NULL) {
	/* session start failed */
	log_warn(p->host,"Unable to create session %s",jid_full(p->id));
	xmlnode_put_attrib_ns(p->x, "type", NULL, NULL, "error");
	xmlnode_put_attrib_ns(p->x, "error", NULL, NULL, messages_get(xmlnode_get_lang(p->x), N_("Session Failed")));
    } else {
	/* reset to the routed id for this session for the reply below */
	xmlnode_put_attrib_ns(p->x, "to", NULL, NULL, jid_full(s->route));
    }

    /* reply */
    jutil_tofrom(p->x);
    deliver(dpacket_new(p->x), i);
    return r_DONE;
}

/**
 * handle incoming &lt;route type='auth'/&gt; packets, we get passed from jabberd:
 * authentication or registration requests
 *
 * Check if another component is configured to handle the auth packets
 * using the &lt;auth/&gt; element containing the other component's address
 * in jsm's configuration.
 *
 * If not let js_authreg process the request.
 *
 * @param i the jsm instance we are running in
 * @param p the packet we should receive
 * @param si our jsm instance internal data
 * @param jp the wrapped packet we received
 * @return always r_DONE
 */
result _js_routed_auth_packet(instance i, dpacket p, jsmi si, jpacket jp) {
    char *authto = NULL;

    /* check and see if we're configured to forward auth packets for processing elsewhere */
    if (si->auth != NULL) {
	xmlnode_put_attrib_ns(p->x, "oto", NULL, NULL, xmlnode_get_attrib_ns(p->x, "to", NULL)); /* preserve original to */
	xmlnode_put_attrib_ns(p->x, "to", NULL, NULL, si->auth);
	deliver(dpacket_new(p->x), i);
	return r_DONE;
    }

    /* internally, hide the route to/from addresses on the authreg request */
    xmlnode_put_attrib_ns(jp->x, "to", NULL, NULL, xmlnode_get_attrib_ns(p->x, "to", NULL));
    xmlnode_put_attrib_ns(jp->x, "from", NULL, NULL, xmlnode_get_attrib_ns(p->x, "from", NULL));
    xmlnode_put_attrib_ns(jp->x, "route", NULL, NULL, xmlnode_get_attrib_ns(p->x, "type", NULL));
    jpacket_reset(jp);
    jp->aux1 = (void *)si;
    mtq_send(NULL,jp->p,js_authreg,(void *)jp);
    return r_DONE;
}

/**
 * handle incoming &lt;route type='error'/&gt; packets, we get passed from jabberd:
 * most likely returned packets we sent to the client connection manager - the
 * user seems to have disconnected (or the component has crashed *g*)
 *
 * Cancel the session, store bounced messages offline again.
 * 
 * @param i the jsm instance we are running in
 * @param p the packet we should receive
 * @param si our jsm instance internal data
 * @param ht the hash table containing the users of the relevant host
 * @param jp the wrapped packet we received
 * @param s the session this packet is for
 * @param u the user data for the receipient
 * @return always r_DONE
 */
result _js_routed_error_packet(instance i, dpacket p, jsmi si, xht ht, jpacket jp, session s, udata u) {
    /* ooh, incoming routed errors in reference to this session, the session is kaput */
    if (s != NULL) {
	s->sid = NULL; /* they generated the error, no use in sending there anymore! */
	js_session_end(s, N_("Disconnected"));
    } else if (p->id->resource == NULL) {
	/* a way to boot an entire user off */
	for(s = u->sessions; s != NULL; s = s->next)
	    js_session_end(s, N_("Removed"));
	/* ... removing pass from udata, authentication should always fetch a new copy of the password from xdb
	u->pass = NULL; */ /* so they can't log back in */
	xmlnode_free(p->x);
	return r_DONE;
    }

    /* if this was a message, it should have been delievered to that session, store offline */
    if (jp != NULL && jp->type == JPACKET_MESSAGE) {
	js_deliver_local(si, jp, ht); /* (re)deliver it locally again, should go to another session or offline */
	return r_DONE;
    }
    
    /* drop and return */
    if(xmlnode_get_firstchild(p->x) != NULL)
	log_notice(p->host, "Dropping a bounced session packet to %s", jid_full(p->id));
    xmlnode_free(p->x);

    return r_DONE;
}

/**
 * handle incoming route packets, that contain sc:session elements
 * for the new session control protocol
 *
 * @param i the jsm instance we are running in
 * @param p the route packet
 * @param sc_session the xmlnode containing the sc:session element
 * @param si the session manager instance
 * @return always r_DONE
 */
result _js_routed_session_control_packet(instance i, dpacket p, xmlnode sc_session, jsmi si) {
    char *action = xmlnode_get_attrib_ns(sc_session, "action", NULL);

    if (j_strcmp(action, "start") == 0) {
	session s = js_sc_session_new(si, p, sc_session);
	/* try to create the new session */
	if (s == NULL) {
	    /* session start failed */
	    log_warn(p->host,"Unable to create session %s",jid_full(p->id));
	    xmlnode_put_attrib_ns(sc_session, "failed", NULL, NULL, messages_get(xmlnode_get_lang(sc_session), N_("Session Failed")));
	} else {
	    /* confirm the session */
	    xmlnode_put_attrib_ns(sc_session, "action", NULL, NULL, "started");
	    xmlnode_put_attrib_ns(sc_session, "sm", "sc", NS_SESSION, s->sc_sm);
	}
    } else if (j_strcmp(action, "end") == 0) {
	session s = NULL;

	/* close existing session */
	char *sc_sm = xmlnode_get_attrib_ns(sc_session, "sm", NS_SESSION);
	udata u = (udata)xhash_get(si->sc_sessions, sc_sm);
	if (sc_sm != NULL && u != NULL) {
	    for (s = u->sessions; s != NULL; s = s->next) {
		if (j_strcmp(sc_sm, s->sc_sm) == 0) {
		    break;
		}
	    }
	    if (s != NULL)
		js_session_end(s, N_("Disconnected"));
	}

	/* confirm closed session */
	xmlnode_put_attrib_ns(sc_session, "action", NULL, NULL, "ended");
    } else if (j_strcmp(action, "create") == 0) {
	/* notify modules */
	jid user_id = jid_new(p->p, xmlnode_get_attrib_ns(sc_session, "target", NULL));
	if (user_id != NULL) {
	    js_user_create(si, user_id);
    
	    /* confirm creation */
	    xmlnode_put_attrib_ns(sc_session, "action", NULL, NULL, "created");
	} else {
	    xmlnode_put_attrib_ns(sc_session, "failed", NULL, NULL, messages_get(xmlnode_get_lang(sc_session), N_("no valid target")));
	}
    } else if (j_strcmp(action, "delete") == 0) {
	/* notify modules */
	jid user_id = jid_new(p->p, xmlnode_get_attrib_ns(sc_session, "target", NULL));
	if (user_id != NULL) {
	    js_user_delete(si, user_id);
	    
	    /* confirm deletion */
	    xmlnode_put_attrib_ns(sc_session, "action", NULL, NULL, "deleted");
	} else {
	    xmlnode_put_attrib_ns(sc_session, "failed", NULL, NULL, messages_get(xmlnode_get_lang(sc_session), N_("no valid target")));
	}
    } else {
	/* unknown action */
	log_warn(p->host, "Session control packet with unknown action: %s", action);
	xmlnode_put_attrib_ns(sc_session, "failed", NULL, NULL, messages_get(xmlnode_get_lang(sc_session), N_("Unknown session control action")));
    }

    /* reply */
    jutil_tofrom(p->x);
    deliver(dpacket_new(p->x), i);

    return r_DONE;
}

/**
 * handle incoming &lt;route/&gt; packets, we get passed from the @link jabberd XML router (jabberd)@endlink
 *
 * &lt;route/&gt; packets are normally received from the client connection manager, that puts the
 * stanzas received from the client inside the &lt;route/&gt; packet to ensure, that the packet is
 * routed to the session manager component instead of directly to the destination address. This is
 * necessary as the session manager might want to trigger actions, drop the stanza, or just has to
 * ensure, that the client is not spoofing the source address.
 *
 * The function checks if it is a special stanza used to establish sessions of a user (in which case
 * the client connection manager also tells the session manager, how it has to identify the
 * connection on packets it sends to the client connection manager to get delivered to the client),
 * or if it is a forwarded stanza of a user for an existing connection.
 *
 * In case of a special stanza to establish sessions, this function has to check which protocol
 * is used by this session. This version of the session manager supports two protocols for this.
 * On the one hand the traditional jabberd 1.x protocol (handled by _js_routed_session_packet()),
 * and on the other hand the session control protocol introduced by jabberd2 (handled by
 * _js_routed_session_control_packet()).
 *
 * In case of the traditional jabberd 1.x protocol establishing a session consists of multiple steps
 * and before the session is really established, the authentication has to be done by the session
 * manager (for the new jabberd2 protocol, authentication has to be done by the client connection
 * manager itself). For handling packets of the traditional protocol until authentication has been
 * done, the packet is passed to _js_routed_auth_packet().
 *
 * If it is no session establishment packet, it is then checked if the stanza is an error stanza,
 * in which case it is passed to _js_routed_error_packet(). If it is no error stanza, the session
 * of this packet is identified. If there is no such session, the stanza gets bounced back to
 * the forwarder of it (which normally will be the client connection manager, which then closes
 * the corresponding connection to the user). If there is such a session, the stanza is passed
 * together with the corresponding session data to the function js_session_from().
 *
 * @param i the jsm instance we are running in
 * @param p the packet we should receive
 * @param si our jsm instance internal data
 * @param ht the hash table containing the users of the relevant host
 * @return always r_DONE
 */
result _js_routed_packet(instance i, dpacket p, jsmi si, xht ht) {
    jpacket jp = NULL;
    xmlnode child = NULL;	/* the actual stanza in the <route/> element */
    char *type = NULL;		/* the type of the route packet: NULL, auth, session, or error */
    session s = NULL;		/* the session this packet is for */
    udata u = NULL;		/* the user's data */
    char *sc_sm = NULL;		/* sc:sm attribute value for new session control protocol */

    type = xmlnode_get_attrib_ns(p->x, "type", NULL);

    /* new session requests */
    if(j_strcmp(type,"session") == 0)
	return _js_routed_session_packet(i, p, si);

    /* Find the first real element */
    child = xmlnode_get_firstchild(p->x);
    while (child != NULL) {
	if (xmlnode_get_type(child) == NTYPE_TAG)
	    break;
	child = xmlnode_get_nextsibling(child);
    }
    
    /* packets for the new session control protocol */
    if (child != NULL && j_strcmp(xmlnode_get_localname(child), "session") == 0 && j_strcmp(xmlnode_get_namespace(child), NS_SESSION) == 0)
	return _js_routed_session_control_packet(i, p, child, si);

    /* As long as we found one process */
    if (child != NULL)
	jp = jpacket_new(child);

    /* auth/reg requests */
    if(jp != NULL && j_strcmp(type,"auth") == 0)
	return _js_routed_auth_packet(i, p, si, jp);

    /* this is a packet to be processed as outgoing for a session */

    /* find session using old or new c2s-sm-protocol? */
    sc_sm = xmlnode_get_attrib_ns(child, "sm", NS_SESSION);

    /* get user data */
    u = sc_sm == NULL ? js_user(si, p->id, ht) : (udata)xhash_get(si->sc_sessions, sc_sm);
    /* is it a packet the c2s bounced back because there is no session anymore? Try to find the user anyway */
    if (u == NULL && sc_sm != NULL) {
	const char *to_jid = xmlnode_get_attrib_ns(child, "to", NULL);
	u = js_user(si, jid_new(xmlnode_pool(child), to_jid), ht);
    }
    if (u == NULL) {
	/* no user!?!?! */
	log_notice(p->host, "Bouncing packet intended for non-existant %s: %s", sc_sm == NULL ? "user" : "session",xmlnode_serialize_string(p->x, xmppd::ns_decl_list(), 0));
	deliver_fail(dpacket_new(p->x), N_("Invalid User"));
	return r_DONE;
    }

    /* get session */
    if (sc_sm == NULL) {
	/* old protocol */
	for (s = u->sessions; s != NULL; s = s->next)
	    if(j_strcmp(p->id->resource, s->route->resource) == 0)
		break;
    } else {
	/* new session control protocol */
	for (s = u->sessions; s != NULL; s = s->next)
	    if (j_strcmp(sc_sm, s->sc_sm) == 0)
		break;

	/* hide routing attributes */
	xmlnode_hide_attrib_ns(child, "sc", NS_XMLNS);
	xmlnode_hide_attrib_ns(child, "sm", NS_SESSION);
	xmlnode_hide_attrib_ns(child, "c2s", NS_SESSION);
    }

    /* if it's an error */
    if(j_strcmp(type,"error") == 0)
	return _js_routed_error_packet(i, p, si, ht, jp, s, u);

    if(jp == NULL) {
	/* uhh, empty packet, *shrug* */
	log_notice(p->host,"Dropping an invalid or empty route packet: %s",xmlnode_serialize_string(p->x, xmppd::ns_decl_list(), 0),jid_full(p->id));
	xmlnode_free(p->x);
	return r_DONE;
    }

    if(s != NULL) {
	/* just pass to the session normally */
	js_session_from(s, jp);
    } else {
	/* bounce back as an error */
	log_notice(p->host, "Bouncing %s packet intended for session %s", xmlnode_get_localname(jp->x), jid_full(p->id));
	deliver_fail(dpacket_new(p->x), N_("Invalid Session"));
    }

    return r_DONE;
}

/**
 * handle packets we get passed from the @link jabberd XML router (jabberd)@endlink
 *
 * The JSM component receives the packets from the XML router by a call to this function. Therefore each incoming
 * stanza (either from other servers received by the @link dialback dialback component@endlink or from a client
 * connection received by the @link pthsock client connection manager@endlink) generates a call of this function.
 *
 * This function ensures, that there is a hash table for the destination domain containing all users, that
 * are currently online on this host (it might be the first packet addresses to this host in which case this
 * hash is not present before). After this is done, it checks if it is either a stanza, that has been forwarded
 * by an other component on the XML router (typically this is the client connection manager) in which case the
 * stanza is passed to _js_routed_packet(), or if it is a non-forwarded packet, which typically means it is an
 * incoming stanza from either a remote server or another session manager instance on the same XML router, or
 * a stanza from a transport/gateway. In the second case of a non-forwarded stanza, the stanza is passed to the
 * function js_deliver_local().
 *
 * @param i the jsm instance we are running in
 * @param p the packet we should receive
 * @param arg our jsm instance internal data
 * @return always r_DONE
 */
result js_packet(instance i, dpacket p, void *arg) {
    jsmi si = (jsmi)arg;
    jpacket jp = NULL;
    xht ht = NULL;

    log_debug2(ZONE, LOGT_DELIVER, "(%X)incoming packet %s",si,xmlnode_serialize_string(p->x, xmppd::ns_decl_list(), 0));

    /* make sure this hostname is in the master table */
    if ((ht = (xht)xhash_get(si->hosts,p->host)) == NULL) {
	xmlnode maxusers = js_config(si, "jsm:maxusers", NULL);
        ht = xhash_new(j_atoi(xmlnode_get_data(maxusers), USERS_PRIME));
	xmlnode_free(maxusers);
	maxusers = NULL;
        log_debug2(ZONE, LOGT_DELIVER, "creating user hash %X for %s", ht,p->host);
        xhash_put(si->hosts,pstrdup(si->p,p->host), (void *)ht);
        log_debug2(ZONE, LOGT_DELIVER, "checking %X", xhash_get(si->hosts, p->host));
    }

    /* if this is a routed packet */
    if (p->type == p_ROUTE) {
	return _js_routed_packet(i, p, si, ht);
    }

    /* normal server-server packet, should we make sure it's not spoofing us?  if so, if xhash_get(p->to->server) then bounce w/ security error */

    jp = jpacket_new(p->x);
    if (jp == NULL) {
        log_warn(p->host, "Dropping invalid incoming packet: %s", xmlnode_serialize_string(p->x, xmppd::ns_decl_list(), 0));
        xmlnode_free(p->x);
        return r_DONE;
    }

    js_deliver_local(si, jp, ht);

    return r_DONE;
}


/**
 * take a packet and deliver it either locally if it has ourself as the destination
 * or deliver it using jabberd if it is for a non-instance-local host
 *
 * This function checks if the packet is local, and will then call j_deliver_local() to deliver it.
 * If it is not instance-local it will call deliver() to deliver it using jabberd.
 *
 * @note any jpacket sent to deliver *MUST* match jpacket_new(p->x),
 * jpacket is simply a convenience wrapper
 * 
 * @param si the session manager instance this is called in
 * @param p the packet to deliver
 * @param sending_s the sending session of the packet (used to select the correct outgoing filter), NULL if packet is not related to a session
 */
void js_deliver(jsmi si, jpacket p, session sending_s) {
    xht ht;		/* hashtable containing the users of the relevant host */

    /* does it have a destination address? */
    if (p->to == NULL) {
        log_warn(NULL, "jsm: Invalid Recipient, returning data %s", xmlnode_serialize_string(p->x, xmppd::ns_decl_list(), 0));
        js_bounce_xmpp(si, sending_s, p->x, XTERROR_BAD);
        return;
    }

    /* does it have a sender address? */
    if (p->from == NULL) {
        log_warn(NULL, "jsm: Invalid Sender, discarding data %s", xmlnode_serialize_string(p->x, xmppd::ns_decl_list(), 0));
        xmlnode_free(p->x);
        return;
    }

    /* do we have to pass it through the outgoing filters? */

    /* only filter if packet is from a user, and if the packet is not to the user himself */
    if (p->flag != PACKET_PASS_FILTERS_MAGIC && p->from->user != NULL && jid_cmpx(p->to, p->from, JID_USER|JID_SERVER) != 0) {
	/* filter through a session's filter? */
	if (sending_s != NULL) {
	    if (js_mapi_call(NULL, es_FILTER_OUT, p, sending_s->u, sending_s)) {
		return; /* blocked by a filter module */
	    }
	} else {
	    /* sending through offline filter */
	    udata sending_user = js_user(si, p->from, NULL);

	    if (js_mapi_call(si, e_FILTER_OUT, p, sending_user, NULL)) {
		return; /* blocked by a filter module */
	    }
	}
    }


    log_debug2(ZONE, LOGT_DELIVER, "deliver(to[%s],from[%s],type[%d],packet[%s])", jid_full(p->to), jid_full(p->from), p->type, xmlnode_serialize_string(p->x, xmppd::ns_decl_list(), 0));

    /* external or local delivery? */
    if ((ht = (xht)xhash_get(si->hosts,p->to->server)) != NULL) {
        js_deliver_local(si, p, ht);
        return;
    }
    deliver(dpacket_new(p->x), si->i);
}

/**
 * send a packet to a function
 *
 * @param si the instance local data
 * @param p the packet to send
 * @param f the function to send the packet to
 */
void js_psend(jsmi si, jpacket p, mtq_callback f) {
    jpq q;

    if(p == NULL || si == NULL)
        return;

    log_debug2(ZONE, LOGT_DELIVER, "psending to %X packet %X",f,p);

    q = static_cast<jpq>(pmalloco(p->p, sizeof(_jpq)));
    q->p = p;
    q->si = si;

    mtq_send(NULL, p->p, f, (void *)q);
}


/* for fun, a tidbit from late nite irc (ya had to be there)
<temas> What is 1+1
<temas> Why did you hardcode stuff
<temas> Was the movie good?
<temas> DId the nukes explode?
*/
