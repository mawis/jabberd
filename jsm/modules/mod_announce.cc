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
 * @file mod_announce.cc
 * @brief This session manager module implements the message of the day and the online user announcement functionality (undocumented)
 *
 * This module implements the 'message of the day' and the 'announcement to online users' functionality.
 *
 * message of the day: users with write admin access can send a message to serverdomain/announce/motd which
 * will set the motd. The message is then broadcasted to all online users and to users coming online if the
 * message is not older then their last session (do not deliver a message twice). By sending a message to
 * serverdomain/announce/motd/update the motd is replaced but users that already got the old message won't get
 * the new one. By sending a message to serverdomain/announce/delete a user with write admin access can delete
 * the motd.
 *
 * announcement to online users: users with write admin access can send a message to serverdomain/announce/online
 * which will be broadcasted to all online users.
 */

/**
 * @brief structure that holds the active message of the day
 *
 * There is one instance of motd_struct per mod_announce instance. It is used to
 * hold the active message of the day in the x element. If this is a NULL pointer
 * there is no active motd.
 *
 * In the set element the time when the motd has been set is kept. This is used
 * to determine if a user that comes online has to receive the motd or if he already
 * got it.
 */
typedef struct motd_struct {
    xmlnode x; /**< the motd */
    time_t set;	/**< when the message has been set */
} *motd, _motd;

/**
 * This is used as an xhash_walker by _mod_announce_avail_hosts to
 * broadcast a message to all online users.
 *
 * @param h the hash containing all sessions of a host (ignored)
 * @param key (ignored)
 * @param data the user data structure
 * @param arg the message that should be broadcasted
 */
static void _mod_announce_avail(xht h, const char *key, void *data, void *arg) {
    xmlnode msg = (xmlnode)arg;
    udata u = (udata)data;
    session s = js_session_primary(u);

    /* no active session */
    if (s == NULL)
	return;
    
    /* no broadcast to users with a priority below 0 */
    if (s->priority < 0)
	return;

    msg = xmlnode_dup(msg);
    xmlnode_put_attrib_ns(msg, "to", NULL, NULL, jid_full(s->id));
    js_session_to(s,jpacket_new(msg));
}

/**
 * this is used as a xhash_walker by mod_announce_avail and mod_announce_motd
 * to iterate over all hosts configured on the session manager. For each host
 * we start an iteration over all user sessions and send them the message we
 * get passed as arg
 *
 * @param h the hash containing all hosts (ignored)
 * @param key the configured host domain (ignored)
 * @param data the hash containing all user sessions of this host
 * @param arg the message that should be broadcasted
 */
static void _mod_announce_avail_hosts(xht h, const char *key, void *data, void *arg) {
    xht ht = (xht)data;

    xhash_walk(ht,_mod_announce_avail,arg);
}

/**
 * process a message that should be broadcasted to all online users
 *
 * @param si the session manager instance
 * @param p the packet containing the message, that should be broadcasted
 * @return always M_HANDLED
 */
static mreturn mod_announce_avail(jsmi si, jpacket p) {
    xmlnode_put_attrib_ns(p->x, "from", NULL, NULL, p->to->server);
    xhash_walk(si->hosts,_mod_announce_avail_hosts,(void *)(p->x));
    xmlnode_free(p->x);
    return M_HANDLED;
}

/**
 * process an already authenticated motd configuration message
 *
 * @param si the session manager instance
 * @param p the packet containing the configuration
 * @param a structure to hold the active motd
 * @return always M_HANDLED
 */
static mreturn mod_announce_motd(jsmi si, jpacket p, motd a) {
    /* ditch old message */
    if (a->x != NULL)
        xmlnode_free(a->x);

    if (j_strcmp(p->to->resource,"announce/motd/delete") == 0) {
        a->x = NULL;
        xmlnode_free(p->x);
        return M_HANDLED;
    }

    /* store new message for all new sessions */
    xmlnode_put_attrib_ns(p->x, "from", NULL, NULL, p->to->server);
    jutil_delay(p->x,"Announced"); /* at a timestamp to the element */
    a->x = p->x; /* keep the motd message */
    a->set = time(NULL); /* XXX shouldn't we only update this timestamp if it isn't an update? */

    /* tell current sessions if this wasn't an update */
    if(j_strcmp(p->to->resource,"announce/motd/update") != 0)
        xhash_walk(si->hosts, _mod_announce_avail_hosts, (void *)(a->x));

    return M_HANDLED;
}

/**
 * Callback that checks messages sent to the server address, if they are configuration
 * messages sent by users with admin privileges. If the sender has no administrative write
 * privileges, the configuration message will be bounced.
 *
 * @param m the mapi
 * @param arg the data structure holding the active motd
 * @return M_IGNORE if the stanza is no message, M_PASS if it's not configuration message, M_HANDLED else.
 */
static mreturn mod_announce_dispatch(mapi m, void *arg) {
    int admin = 0;
    xmlnode cur;

    if (m->packet->type != JPACKET_MESSAGE)
	return M_IGNORE; /* ignore everything but messages */
    if (j_strncmp(m->packet->to->resource,"announce/",9) != 0)
	return M_PASS; /* not a configuration message */

    log_debug2(ZONE, LOGT_DELIVER, "handling announce message from %s",jid_full(m->packet->from));

    /* if he is, process the message */
    if (acl_check_access(m->si->xc, ADMIN_MOTD, m->packet->from)) {
        if (j_strncmp(m->packet->to->resource,"announce/online",15) == 0)
	    return mod_announce_avail(m->si, m->packet);
        if (j_strncmp(m->packet->to->resource,"announce/motd",13) == 0)
	    return mod_announce_motd(m->si, m->packet, (motd)arg);
    }

    /* if he isn't, bounce the message */
    js_bounce_xmpp(m->si, NULL, m->packet->x, XTERROR_NOTALLOWED);
    return M_HANDLED;
}

/**
 * callback that waits for first available presence of a user that just came online
 *
 * If there is an active motd and the users last session is older then the motd,
 * the motd will be sent to this user. Motd announcement won't be sent if the presence
 * has negative priority.
 *
 * @param m the mapi structure
 * @param arg the active motd
 * @return M_IGNORE if we don't need to be notified again, M_PASS if we want to get more notifies
 */
static mreturn mod_announce_sess_avail(mapi m, void *arg) {
    motd a = (motd)arg;
    xmlnode last;
    session s;
    xmlnode msg;
    int lastt;

    if (m->packet->type != JPACKET_PRESENCE)
	return M_IGNORE;
    if (a->x == NULL)
	return M_IGNORE;

    /* as soon as we become available */
    if (!js_online(m)) {
        return M_PASS;
    }

    /* no announces to sessions with negative priority */
    if (j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(m->packet->x, "priority", m->si->std_namespace_prefixes), 0)), 0) < 0) {
	return M_PASS;
    }

    /* check the last time we were on to see if we haven't gotten the announcement yet */
    last = xdb_get(m->si->xc, m->user->id, NS_LAST);
    lastt = j_atoi(xmlnode_get_attrib_ns(last, "last", NULL),0);
    xmlnode_free(last);
    if (lastt > 0 && lastt > a->set) {
	/* if there's a last and it's newer than the announcement, ignore us */
        return M_IGNORE;
    }

    /* check the primary session, if it's older than the announcement, we'll just assume we've already seen it */
    s = js_session_primary(m->user);
    if (s != NULL && s->started > a->set) {
        return M_IGNORE;
    }

    /* well, we met all the criteria, we should be announced to */
    msg = xmlnode_dup(a->x);
    xmlnode_put_attrib_ns(msg, "to", NULL, NULL, jid_full(m->s->id));
    js_session_to(m->s, jpacket_new(msg));

    return M_PASS;
}

/**
 * callback on which mod_announce gets notified about new user sessions
 *
 * If a motd has been set, this callback will register an other callback,
 * that waits for the available presence of the user. The user won't get the
 * motd before his client sents an available presence.
 *
 * @param m the mapi structure
 * @param arg pointer to the active motd structure
 * @return allways M_PASS
 */
static mreturn mod_announce_sess(mapi m, void *arg) {
    motd a = (motd)arg;

    if (a->x != NULL)
        js_mapi_session(es_OUT, m->s, mod_announce_sess_avail, arg);

    return M_PASS;
}

/**
 * startup the mod_announce module
 *
 * will register two callbacks: one for receiving configuration messages
 * and one to be notified about new user sessions
 *
 * @param si the session manager instance
 */
extern "C" void mod_announce(jsmi si) {
    motd a;

    a = static_cast<motd>(pmalloco(si->p, sizeof(_motd)));
    js_mapi_register(si, e_SERVER, mod_announce_dispatch, (void *)a);
    js_mapi_register(si, e_SESSION, mod_announce_sess, (void *)a);
}
