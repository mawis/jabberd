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
 * @file mod_offline.c
 * @brief Handle offline messages to users (including message expiration (JEP-0023), that is DEPRICATED by JEP-0079, message events (JEP-0022), that might become DEPRICATED by JEP-0085 or a successor, and flexible offline message retrieval (JEP-0013))
 * 
 * This module is responsible for checking if a message can be delivered to a user session
 * or if it has to be stored in xdb for later delivery.
 *
 * If a user comes online this module will check if there are stored messages for this user
 * (only if the user's presence has a non-negative priority) and deliver them, if the have
 * not yet expired (using JEP-0023 processing).
 *
 * If a message is stored offline, this module will check if the sender wants to get an event and send it
 * if requested. (Message Events - JEP-0022)
 *
 * This module supports flexible offline message retrieval (JEP-0013)
 *
 * mod_offline must go before mod_presence
 *
 * @todo Handling of message events makes invisible presence visible to the sender of a message.
 * Maybe we should generate offline events if a message is delivered to an invisible session as well.
 */

/* THIS MODULE will soon be depreciated by mod_filter -- really? */

/**
 * configuration of mod_offline
 */
typedef struct modoffline_conf_struct {
    int store_type_normal;		/**< store message type normal offline? */
    int store_type_chat;		/**< store message type chat offline? */
    int store_type_headline;		/**< store message type headline offline? */
    int store_type_groupchat;		/**< store message type groupchat offline? */
    int store_type_error;		/**< store message type error offline? */
} *modoffline_conf, _modoffline_conf;

/**
 * data that is held for a single session of a user
 */
typedef struct modoffline_session_struct {
    int jep0013;			/**< 0 for message flood after available presence, 1 for jep0013 */
} *modoffline_session, _modoffline_session;

/**
 * handle a message to the user
 *
 * checks if the user has an active session, that gets messages (has a non-negative priority) and delivers the message.
 *
 * If there is no active session the message is stored offline.
 *
 * If the message cannot be stored offline or the message has already expired, this module will return M_PASS
 * so other modules will process the message. If the message is not handled by any other module it will bounce back
 * to the sender.
 *
 * @param m the mapi structure
 * @return M_HANDLED if the message has been stored offline or delivered to a user's session, M_PASS if the message is expired or could not be stored offline
 */
mreturn mod_offline_message(mapi m, modoffline_conf conf) {
    session top;
    xmlnode cur = NULL, cur2;
    char str[11];
    char timestamp[25];

    /* if there's an existing session with a priority of at least 0, just give it to them */
    if ((top = js_session_primary(m->user)) != NULL && top->priority >= 0) {
        js_session_to(top,m->packet);
        return M_HANDLED;
    }

   /* look for event messages */
    for (cur = xmlnode_get_firstchild(m->packet->x); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
        if (NSCHECK(cur,NS_EVENT)) {
            if (xmlnode_get_tag(cur,"id") != NULL)
                return M_PASS; /* bah, we don't want to store events offline (XXX: do we?) */
            if (xmlnode_get_tag(cur,"offline") != NULL)
                break; /* cur remaining set is the flag */
        }
    }

    log_debug2(ZONE, LOGT_DELIVER, "handling message for %s",m->user->user);

    if ((cur2 = xmlnode_get_tag(m->packet->x,"x?xmlns=" NS_EXPIRE)) != NULL) {
        if (j_atoi(xmlnode_get_attrib(cur2, "seconds"),0) == 0)
            return M_PASS; 
        
        snprintf(str, sizeof(str), "%d", (int)time(NULL));
        xmlnode_put_attrib(cur2,"stored",str);
    }

    /* check if the message type should be stored offline */
    switch (jpacket_subtype(m->packet)) {
	case JPACKET__CHAT:
	    if (!conf->store_type_chat) {
		js_bounce_xmpp(m->si, m->packet->x, XTERROR_RECIPIENTUNAVAIL);
		return M_HANDLED;
	    }
	    break;
	case JPACKET__GROUPCHAT:
	    if (!conf->store_type_groupchat) {
		js_bounce_xmpp(m->si, m->packet->x, XTERROR_RECIPIENTUNAVAIL);
		return M_HANDLED;
	    }
	    break;
	case JPACKET__HEADLINE:
	    if (!conf->store_type_headline) {
		js_bounce_xmpp(m->si, m->packet->x, XTERROR_RECIPIENTUNAVAIL);
		return M_HANDLED;
	    }
	    break;
	case JPACKET__ERROR:
	    if (!conf->store_type_error) {
		/* we shouldn't bouce messages of type error, this could result in loops */
		xmlnode_free(m->packet->x);
		return M_HANDLED;
	    }
	    break;
	default:
	    if (!conf->store_type_normal) {
		js_bounce_xmpp(m->si, m->packet->x, XTERROR_RECIPIENTUNAVAIL);
		return M_HANDLED;
	    }
	    break;
    }

    /* stamp the message to keep information when it has been received */
    jutil_delay(m->packet->x,"Offline Storage");

    /* add node id for flexible offline message retrieval */
    xmlnode_put_attrib(m->packet->x, "node", jutil_timestamp_ms(timestamp));

    if (xdb_act(m->si->xc, m->user->id, NS_OFFLINE, "insert", NULL, m->packet->x)) /* feed the message itself, and do an xdb insert */
        return M_PASS;

    if (cur != NULL) {
	/* if there was an offline event to be sent, send it for gosh sakes! */

        jutil_tofrom(m->packet->x);

        /* erease everything else in the message */
        for (cur2 = xmlnode_get_firstchild(m->packet->x); cur2 != NULL; cur2 = xmlnode_get_nextsibling(cur2))
            if (cur2 != cur)
                xmlnode_hide(cur2);

        /* erase any other events */
        for (cur2 = xmlnode_get_firstchild(cur); cur2 != NULL; cur2 = xmlnode_get_nextsibling(cur2))
            xmlnode_hide(cur2);

        /* fill it in and send it on */
        xmlnode_insert_tag(cur,"offline");
        xmlnode_insert_cdata(xmlnode_insert_tag(cur,"id"),xmlnode_get_attrib(m->packet->x,"id"), -1);
        js_deliver(m->si, jpacket_reset(m->packet));

    } else {
        xmlnode_free(m->packet->x);
    }
    return M_HANDLED;

}

/**
 * callback that handles messages sent to a user address
 *
 * check that it's a message stanza and call mod_offline_message
 *
 * all other stanza types are ignored
 *
 * @param m the mapi structure
 * @param arg modoffline_conf configuration structure
 * @return M_IGNORE if no message stanza, M_PASS if the message already expired or could not stored offline, M_HANDLED if it has been delivered or stored offline
 */
mreturn mod_offline_handler(mapi m, void *arg) {
    if (m->packet->type == JPACKET_MESSAGE)
	return mod_offline_message(m, (modoffline_conf)arg);

    return M_IGNORE;
}

/**
 * remove a single message from offline storage
 *
 * @param m the mapi structure
 * @param filter which message to remove, NULL for all messages
 */
void mod_offline_remove_message(mapi m, const char *filter) {
    spool s = NULL;

    if (m == NULL)
	return;

    if (filter == NULL) {
	xdb_set(m->si->xc, m->user->id, NS_OFFLINE, NULL); /* can't do anything if this fails anyway :) */
	return;
    }

    /* generate the node path for the message to delete */
    s = spool_new(m->packet->p);
    spool_add(s, "message?node=");
    spool_add(s, filter);

    log_debug2(ZONE, LOGT_STORAGE, "removing message by matched xdb: %s", spool_print(s));

    /* replace this message with nothing */
    xdb_act(m->si->xc, m->user->id, NS_OFFLINE, "insert", spool_print(s), NULL);
}

/**
 * check if a message has expired
 *
 * @param m the mapi_struct
 * @param message xmlnode containing the message
 * @return 1 if the message has expired, 0 else
 */
int mod_offline_check_expired(mapi m, xmlnode message) {
    int expire = 0;
    int stored = 0;
    int diff = 0;
    char str[11];
    int now = time(NULL);
    xmlnode x = xmlnode_get_tag(message, "x?xmlns=" NS_EXPIRE);

    /* messages without expire information will never expire */
    if (x == NULL)
	return 0;

    /* check if it expired */
    expire = j_atoi(xmlnode_get_attrib(x,"seconds"),0);
    stored = j_atoi(xmlnode_get_attrib(x,"stored"),now);
    diff = now - stored;
    if (diff >= expire) {
	char *node = xmlnode_get_attrib(message, "node");

	log_debug2(ZONE, LOGT_DELIVER, "dropping expired message %s",xmlnode2str(message));

	/* delete the message from offline storage */
	if (node != NULL) {
	    mod_offline_remove_message(m, node);
	}

	return 1;
    }

    snprintf(str, sizeof(str), "%d", expire - diff);
    xmlnode_put_attrib(x, "seconds", str);
    xmlnode_hide_attrib(x, "stored");
    return 0;
}

/**
 * send out offline messages
 *
 * @param m the mapi structure
 * @param filter NULL to send all messages, else send only message with that node id
 * @param offline_element 0 to not include the offline element, 1 to send offline element from JEP-0013
 * @return number of messages that were sent
 */
int mod_offline_send_messages(mapi m, const char *filter, int offline_element) {
    xmlnode opts = NULL;
    xmlnode cur = NULL;
    int sent_messages = 0;

    if ((opts = xdb_get(m->si->xc, m->user->id, NS_OFFLINE)) == NULL)
        return 0;

    /* check for msgs */
    for (cur = xmlnode_get_firstchild(opts); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
	xmlnode x = NULL;
	jpacket read_stanza = NULL;

	/* ignore CDATA between <message/> elements */
	if (xmlnode_get_type(cur) != NTYPE_TAG)
	    continue;

	/* if there is a filter, only process messages matching the filter */
	if (filter != NULL && j_strcmp(xmlnode_get_attrib(cur, "node"), filter) != 0) {
	    continue;
	}

        /* check for expired stuff */
	if (mod_offline_check_expired(m, cur)) {
	    xmlnode_hide(cur);
	    continue;
	}

	/* insert information for flexible offline message retrieval JEP-0013 */
	if (offline_element != 0) {
	    xmlnode offline = NULL;
	    xmlnode item = NULL;

	    offline = xmlnode_insert_tag(cur, "offline");
	    xmlnode_put_attrib(offline, "xmlns", NS_FLEXIBLE_OFFLINE);

	    item = xmlnode_insert_tag(offline, "item");
	    xmlnode_put_attrib(item, "node", xmlnode_get_attrib(cur, "node"));
	}

	/* hide our node attribute, we added for flexible offline message retrieval handling */
	xmlnode_hide_attrib(cur, "node");

	/* send the message */
	read_stanza = jpacket_new(xmlnode_dup(cur));
	read_stanza->flag = PACKET_FROM_OFFLINE_MAGIC;
	log_debug2(ZONE, LOGT_DELIVER, "js_session_to for %s", xmlnode2str(cur));
        js_session_to(m->s,read_stanza);
	sent_messages++;
        xmlnode_hide(cur);
    }

    /* free the xdb result containing the messages */
    xmlnode_free(opts);

    /* return the number of sent messages */
    return sent_messages;
}

/**
 * watches for when the user is available and sends out offline messages
 *
 * if a user gets available we have to send out the offline messages
 *
 * This function checks if a message has expired and won't sent expired messages to the
 * user.
 *
 * @param m the mapi strcuture
 * @param session_conf configuration data for the user's session
 */
void mod_offline_out_available(mapi m, modoffline_session session_conf) {
    if (session_conf->jep0013) {
	log_debug2(ZONE, LOGT_DELIVER, "session used Flexible Offline Message Retrieval (JEP-0013) not flooding messages");
	return;
    }

    if (j_atoi(xmlnode_get_tag_data(m->packet->x, "priority"), 0) < 0) {
	log_debug2(ZONE, LOGT_DELIVER, "negative priority, not delivering offline messages");
	return;
    }

    log_debug2(ZONE, LOGT_DELIVER, "avability established, check for messages");

    /* send out messages and delete them from offline storage */
    if (mod_offline_send_messages(m, NULL, 0) > 0) {
	mod_offline_remove_message(m, NULL);
    }
}

/**
 * handle requests for the list of offline messages
 *
 * @param m the mapi structure
 */
void mod_offline_out_get_message_list(mapi m) {
    xmlnode offline_messages = NULL;
    xmlnode cur = NULL;
    xmlnode query = NULL;

    /* get messages from xdb storage */
    offline_messages = xdb_get(m->si->xc, m->user->id, NS_OFFLINE);

    log_debug2(ZONE, LOGT_STORAGE, "got offline messages from xdb: %s", xmlnode2str(offline_messages));

    jutil_iqresult(m->packet->x);
    query = xmlnode_insert_tag(m->packet->x, "query");
    xmlnode_put_attrib(query, "xmlns", NS_DISCO_ITEMS);
    xmlnode_put_attrib(query, "node", NS_FLEXIBLE_OFFLINE);

    /* iterate over the messages and add them to the result */
    for (cur = xmlnode_get_firstchild(offline_messages); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
	xmlnode item = NULL;

	/* ignore CDATA between <message/> elements */
	if (xmlnode_get_type(cur) != NTYPE_TAG)
	    continue;

	log_debug2(ZONE, LOGT_STORAGE, "processing message %s", xmlnode2str(cur));

	/* check if the message expired */
	if (mod_offline_check_expired(m, cur)) {
	    xmlnode_hide(cur);
	    continue;
	}

	/* add an item element */
	item = xmlnode_insert_tag(query, "item");
	xmlnode_put_attrib(item, "jid", jid_full(m->user->id));
	xmlnode_put_attrib(item, "node", xmlnode_get_attrib(cur, "node"));
	xmlnode_put_attrib(item, "name", xmlnode_get_attrib(cur, "from"));
    }
    
    jpacket_reset(m->packet);
    js_deliver(m->si,m->packet);

    if (offline_messages != NULL) {
	xmlnode_free(offline_messages);
    }
}

/**
 * process iqs that contain an offline element
 * (retrieving and deleting offline messages)
 *
 * This function "consumes" the packet and frees it.
 *
 * @param m the mapi_struct
 */
mod_offline_out_handle_query(mapi m) {
    xmlnode cur = NULL;
    int subtype = jpacket_subtype(m->packet);
    
    /* iterate over the commands */
    for (cur = xmlnode_get_firstchild(m->packet->iq); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
	/* ignore CDATA between <message/> elements */
	if (xmlnode_get_type(cur) != NTYPE_TAG)
	    continue;

	if (j_strcmp(xmlnode_get_name(cur), "purge") == 0 && subtype == JPACKET__SET) {
	    /* purge command */
	    xdb_set(m->si->xc, m->user->id, NS_OFFLINE, NULL); /* can't do anything if this fails anyway :) */
	} else if (j_strcmp(xmlnode_get_name(cur), "fetch") == 0 && subtype == JPACKET__GET) {
	    /* fetch all messages */
	    mod_offline_send_messages(m, NULL, 1);
	} else if (j_strcmp(xmlnode_get_name(cur), "item") == 0) {
	    if (j_strcmp(xmlnode_get_attrib(cur, "action"), "view") == 0 && subtype == JPACKET__GET) {
		/* view a single message */
		mod_offline_send_messages(m, xmlnode_get_attrib(cur, "node"), 1);
	    } else if (j_strcmp(xmlnode_get_attrib(cur, "action"), "remove") == 0 && subtype == JPACKET__SET) {
		/* remove a single message */
		mod_offline_remove_message(m, xmlnode_get_attrib(cur, "node"));
	    }
	}

	log_debug2(ZONE, LOGT_STORAGE, "processing offline command %s", xmlnode2str(cur));
    }

    /* confirm that we processed the request */
    jutil_iqresult(m->packet->x);
    jpacket_reset(m->packet);
    js_deliver(m->si, m->packet);
}

/**
 * handle iq stanzas send by the user to himself ... check for JEP-0013 queries
 *
 * @param m the mapi structure
 * @param session_conf configuration data for this users session
 * @return M_HANDLED if the iq has been handled, M_PASS else
 */
mreturn mod_offline_out_iq(mapi m, modoffline_session session_conf) {
    /* only packets sent by the user to himself */
    if (m->packet->to != NULL)
	return M_PASS;

    /* handle requests for message list */
    if (NSCHECK(m->packet->iq, NS_DISCO_ITEMS)) {
	if (j_strcmp(xmlnode_get_attrib(m->packet->iq, "node"), NS_FLEXIBLE_OFFLINE) == 0) {
	    if (jpacket_subtype(m->packet) == JPACKET__GET) {
		/* don't flood messages on available presence */
		session_conf->jep0013 = 1;

		mod_offline_out_get_message_list(m);
	    } else {
		js_bounce_xmpp(m->si, m->packet->x, XTERROR_FORBIDDEN);
	    }
	    return M_HANDLED;
	}
    }

    /* handle request for retrieving and deleting offline messages */
    if (NSCHECK(m->packet->iq, NS_FLEXIBLE_OFFLINE)) {
	if (j_strcmp(xmlnode_get_name(m->packet->iq), "offline") == 0) {
	    /* don't flood messages on available presence */
	    session_conf->jep0013 = 1;

	    mod_offline_out_handle_query(m);
	    return M_HANDLED;
	}
    }

    return M_PASS;
}

/**
 * callback that handles outgoing presences and iqs of the user, we are waiting for the user to come online
 *
 * if the user sends an available presence, we have to check for offline messages and send them to the user
 *
 * @param m the mapi structure
 * @param arg unused/ignored
 * @return M_IGNORE if the stanza is no presence, M_HANDLED if we handled an iq query, M_PASS else
 */
mreturn mod_offline_out(mapi m, void *arg) {
    if (m->packet->type == JPACKET_IQ)
	return mod_offline_out_iq(m, (modoffline_session)arg);

    if (m->packet->type != JPACKET_PRESENCE) return M_IGNORE;

    log_debug2(ZONE, LOGT_IO, "handling presence packet: %s", xmlnode2str(m->packet->x));

    /* If its an available presence, we have to check for offline messages */
    if (m != NULL && m->packet != NULL && (jpacket_subtype(m->packet) == JPACKET__AVAILABLE || jpacket_subtype(m->packet) == JPACKET__INVISIBLE)) {
        mod_offline_out_available(m, (modoffline_session)arg);
    }

    return M_PASS;
}

/**
 * set up the per-session listeners: we want to get outgoing messages because we need to get the user's presence to deliver stored messages
 *
 * @param m the mapi structure
 * @param arg unused/ignored
 * @return always M_PASS
 */
mreturn mod_offline_session(mapi m, void *arg) {
    modoffline_session session_data = NULL;

    log_debug2(ZONE, LOGT_SESSION, "session init");

    /* allocate configuration data structure for this session */
    session_data = (modoffline_session)pmalloco(m->s->p, sizeof(_modoffline_session));

    /* register handler for packets the user sends */
    js_mapi_session(es_OUT, m->s, mod_offline_out, session_data);

    return M_PASS;
}

/**
 * delete offline messages if a user gets deleted
 *
 * @param m the mapi_struct
 * @param arg unused/ignored
 * @return always M_PASS
 */
mreturn mod_offline_delete(mapi m, void *arg) {
    /* XXX should we bounce the messages instead of just deleting them? */
    xdb_set(m->si->xc, m->user->id, NS_OFFLINE, NULL);
    return M_PASS;
}

/**
 * startup this module, register its callbacks
 *
 * two callbacks have to be registered: we have to receive the messages addressed to the user (mod_offline_handler)
 * and we need noticed if a user comes online (mod_offline_session)
 *
 * @param si the session manager instance
 */
void mod_offline(jsmi si) {
    xmlnode cfg = js_config(si, "mod_offline");
    modoffline_conf conf = (modoffline_conf)pmalloco(si->p, sizeof(_modoffline_conf));

    /* which types of messages should be stored offline? */
    if (cfg == NULL) {
	/* default is to store all types */
	conf->store_type_normal = 1;
	conf->store_type_chat = 1;
	conf->store_type_headline = 1;
	conf->store_type_groupchat = 1;
	conf->store_type_error = 1;
    } else {
	conf->store_type_normal = xmlnode_get_tag(cfg, "normal") == NULL ? 0 : 1;
	conf->store_type_chat = xmlnode_get_tag(cfg, "chat") == NULL ? 0 : 1;
	conf->store_type_headline = xmlnode_get_tag(cfg, "headline") == NULL ? 0 : 1;
	conf->store_type_groupchat = xmlnode_get_tag(cfg, "groupchat") == NULL ? 0 : 1;
	conf->store_type_error = xmlnode_get_tag(cfg, "error") == NULL ? 0 : 1;
    }

    log_debug2(ZONE, LOGT_INIT, "init");
    js_mapi_register(si,e_OFFLINE, mod_offline_handler, (void*)conf);
    js_mapi_register(si,e_SESSION, mod_offline_session, NULL);
    js_mapi_register(si, e_DELETE, mod_offline_delete, NULL);
}
