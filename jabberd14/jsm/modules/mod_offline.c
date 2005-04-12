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
 * @brief Handle offline messages to users (including message expiration (JEP-0023), that is DEPRICATED by JEP-0079, and message events (JEP-0022), that might become DEPRICATED by JEP-0085 or a successor)
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
mreturn mod_offline_message(mapi m, modoffline_conf conf)
{
    session top;
    xmlnode cur = NULL, cur2;
    char str[11];

    /* if there's an existing session, just give it to them */
    if((top = js_session_primary(m->user)) != NULL)
    {
        js_session_to(top,m->packet);
        return M_HANDLED;
    }

   /* look for event messages */
    for (cur = xmlnode_get_firstchild(m->packet->x); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
        if(NSCHECK(cur,NS_EVENT))
        {
            if(xmlnode_get_tag(cur,"id") != NULL)
                return M_PASS; /* bah, we don't want to store events offline (XXX: do we?) */
            if(xmlnode_get_tag(cur,"offline") != NULL)
                break; /* cur remaining set is the flag */
        }
    }

    log_debug2(ZONE, LOGT_DELIVER, "handling message for %s",m->user->user);

    if((cur2 = xmlnode_get_tag(m->packet->x,"x?xmlns=" NS_EXPIRE)) != NULL)
    {
        if(j_atoi(xmlnode_get_attrib(cur2, "seconds"),0) == 0)
            return M_PASS; 
        
        sprintf(str,"%d",(int)time(NULL));
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

    if(xdb_act(m->si->xc, m->user->id, NS_OFFLINE, "insert", NULL, m->packet->x)) /* feed the message itself, and do an xdb insert */
        return M_PASS;

    if(cur != NULL)
    { /* if there was an offline event to be sent, send it for gosh sakes! */

        jutil_tofrom(m->packet->x);

        /* erease everything else in the message */
        for(cur2 = xmlnode_get_firstchild(m->packet->x); cur2 != NULL; cur2 = xmlnode_get_nextsibling(cur2))
            if(cur2 != cur)
                xmlnode_hide(cur2);

        /* erase any other events */
        for(cur2 = xmlnode_get_firstchild(cur); cur2 != NULL; cur2 = xmlnode_get_nextsibling(cur2))
            xmlnode_hide(cur2);

        /* fill it in and send it on */
        xmlnode_insert_tag(cur,"offline");
        xmlnode_insert_cdata(xmlnode_insert_tag(cur,"id"),xmlnode_get_attrib(m->packet->x,"id"), -1);
        js_deliver(m->si, jpacket_reset(m->packet));

    }else{
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
    if(m->packet->type == JPACKET_MESSAGE) return mod_offline_message(m, (modoffline_conf)arg);

    return M_IGNORE;
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
 */
void mod_offline_out_available(mapi m)
{
    xmlnode opts, cur, x;
    int now = time(NULL);
    int expire, stored, diff;
    char str[11];
    jpacket read_stanza = NULL;

    if (j_atoi(xmlnode_get_tag_data(m->packet->x, "priority"), 0) < 0) {
	log_debug2(ZONE, LOGT_DELIVER, "negative priority, not delivering offline messages");
	return;
    }

    log_debug2(ZONE, LOGT_DELIVER, "avability established, check for messages");

    if((opts = xdb_get(m->si->xc, m->user->id, NS_OFFLINE)) == NULL)
        return;

    /* check for msgs */
    for(cur = xmlnode_get_firstchild(opts); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
	/* ignore CDATA between <message/> elements */
	if (xmlnode_get_type(cur) != NTYPE_TAG)
	    continue;

        /* check for expired stuff */
        if((x = xmlnode_get_tag(cur,"x?xmlns=" NS_EXPIRE)) != NULL)
        {
            expire = j_atoi(xmlnode_get_attrib(x,"seconds"),0);
            stored = j_atoi(xmlnode_get_attrib(x,"stored"),now);
            diff = now - stored;
            if(diff >= expire)
            {
                log_debug2(ZONE, LOGT_DELIVER, "dropping expired message %s",xmlnode2str(cur));
                xmlnode_hide(cur);
                continue;
            }
            sprintf(str,"%d",expire - diff);
            xmlnode_put_attrib(x,"seconds",str);
            xmlnode_hide_attrib(x,"stored");
        }
	read_stanza = jpacket_new(xmlnode_dup(cur));
	read_stanza->flag = PACKET_FROM_OFFLINE_MAGIC;
	log_debug2(ZONE, LOGT_DELIVER, "js_session_to for %s", xmlnode2str(cur));
        js_session_to(m->s,read_stanza);
        xmlnode_hide(cur);
    }
    /* messages are gone, save the new sun-dried opts container */
    xdb_set(m->si->xc, m->user->id, NS_OFFLINE, NULL); /* can't do anything if this fails anyway :) */
    xmlnode_free(opts);
}

/**
 * callback that handles outgoing presences of the user, we are waiting for the user to come online
 *
 * if the user sends an available presence, we have to check for offline messages and send them to the user
 *
 * @param m the mapi structure
 * @param arg unused/ignored
 * @return M_IGNORE if the stanza is no presence, M_PASS else
 */
mreturn mod_offline_out(mapi m, void *arg)
{
    if(m->packet->type != JPACKET_PRESENCE) return M_IGNORE;

    if(js_online(m))
        mod_offline_out_available(m);

    return M_PASS;
}

/**
 * set up the per-session listeners: we want to get outgoing messages because we need to get the user's presence to deliver stored messages
 *
 * @param m the mapi structure
 * @param arg unused/ignored
 * @return always M_PASS
 */
mreturn mod_offline_session(mapi m, void *arg)
{
    log_debug2(ZONE, LOGT_SESSION, "session init");

    js_mapi_session(es_OUT, m->s, mod_offline_out, NULL);

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
}
