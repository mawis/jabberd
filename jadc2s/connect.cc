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
 * --------------------------------------------------------------------------*/
 
#include "jadc2s.h"

#include <sstream>

/**
 * get the child element of a route element, that represents the base element
 * of the stanza
 *
 * @param nad the nad containing the route element
 * @param root_element the handle for the route element (typically 0)
 * @return -1 if no base element found, handle for the stanza base element else
 */
static int _connect_get_stanza_element(nad_t nad, int root_element) {
    int stanza_element = -1;

    stanza_element = nad_find_elem(nad, root_element, "message", 1);
    if (stanza_element >= 0)
	return stanza_element;
    stanza_element = nad_find_elem(nad, root_element, "iq", 1);
    if (stanza_element >= 0)
	return stanza_element;
    return nad_find_elem(nad, root_element, "presence", 1);
}

/**
 * bounce back a packet to the session manager
 */
static void _connect_bounce_packet(conn_t c, chunk_t chunk) {
    std::ostringstream from;
    std::ostringstream to;
    std::ostringstream sc_sm;
    std::ostringstream sc_c2s;
    int attr = -1;
    int stanza_element = -1;
    int is_sc_packet = 0;

    /* sanity check */
    if (c == NULL || chunk == NULL)
	return;

    /* get addresses */
    attr = nad_find_attr(chunk->nad, 0, "from", NULL);
    if (attr < 0)
	return;
    from.write(NAD_AVAL(chunk->nad, attr), NAD_AVAL_L(chunk->nad, attr));

    attr = nad_find_attr(chunk->nad, 0, "to", NULL);
    if (attr < 0)
	return;
    to.write(NAD_AVAL(chunk->nad, attr), NAD_AVAL_L(chunk->nad, attr));

    /* get sc protocol data */
    stanza_element = _connect_get_stanza_element(chunk->nad, 0);
    if (stanza_element < 0) {
	stanza_element = nad_find_elem(chunk->nad, 0, "sc:session", 1);
	if (stanza_element < 0)
	    return;
	is_sc_packet = 1;
    }
    attr = nad_find_attr(chunk->nad, stanza_element, "sc:sm", NULL);
    if (attr >= 0) {
	sc_sm.write(NAD_AVAL(chunk->nad, attr), NAD_AVAL_L(chunk->nad, attr));
    }

    attr = nad_find_attr(chunk->nad, stanza_element, "sc:c2s", NULL);
    if (attr >= 0) {
	sc_c2s.write(NAD_AVAL(chunk->nad, attr), NAD_AVAL_L(chunk->nad, attr));
    }

    /* bounce back */
    if (!is_sc_packet)
	chunk_write(c, chunk, from.str().c_str(), to.str().c_str(), "error");

    /* end the session, the session manager expects to exist */
    if (sc_sm.str() != "" && sc_c2s.str() != "")
	client_send_sc_command(c, to.str().c_str(), from.str().c_str(), "end", NULL, NULL, sc_sm.str().c_str(), sc_c2s.str().c_str());
}

/**
 * check if there has been a routing error for the packet
 *
 * Checks several things if thay match expected values
 *
 * @param sm_conn the connection to the jabber server, where the packet has been received
 * @param client_conn the connection to the expected user, where the packet should be delivered to
 * @param stanza_element the NAD id of the stanza base element in sm_conn->nad
 * @return 0 = packet is sane and should be delivered, 1 = packet is routed to the wrong destination and should not further being processed
 */
static int _connect_packet_is_unsane_new_sc_proto(conn_t sm_conn, conn_t client_conn, int stanza_element) {
    int sc_sm = -1;

    /* first check for new protocol: expected to use the new protocol? */
    if (client_conn->sc_sm == NULL) {
	sm_conn->c2s->log->level(LOG_WARNING) << "got packet from session manager using new sc protocol for target using old protocol: bouncing";
	_connect_bounce_packet(sm_conn, chunk_new_packet(sm_conn, 1));
	return 1;
    }

    /* second check for new protocol: is the session manager id matching? */
    sc_sm = nad_find_attr(sm_conn->nad, stanza_element, "sc:sm", NULL);
    if (sc_sm < 0) {
	sm_conn->c2s->log->level(LOG_ERR) << "got packet from session manager using new sc protocol, that has no sm id: dropping";
	return 1;
    }
    if (j_strlen(client_conn->sc_sm) != NAD_AVAL_L(sm_conn->nad, sc_sm) || j_strncmp(NAD_AVAL(sm_conn->nad, sc_sm), client_conn->sc_sm, NAD_AVAL_L(sm_conn->nad, sc_sm)) != 0) {
	sm_conn->c2s->log->level(LOG_WARNING) << "got packet from session manager using new sc protocol, that has unexpected sm id: bouncing";
	_connect_bounce_packet(sm_conn, chunk_new_packet(sm_conn, 1));
	return 1;
    }

    return 0;
}
	
/**
 * check if there has been a routing error for the packet
 *
 * Checks several things if thay match expected values
 *
 * @return 0 = packet is sane and should be delivered, 1 = packet is routed to the wrong destination and should not further being processed
 */
static int _connect_packet_is_unsane_old_sc_proto(conn_t sm_conn, conn_t client_conn) {
    std::ostringstream from_jid;
    pool local_pool = NULL;
    int from = -1;

    /* first check for old protocol: expected to use the old protocol? */
    if (client_conn->sc_sm != NULL) {
	sm_conn->c2s->log->level(LOG_WARNING) << "got packet from session manager using old sc protocol for target using new protocol: bouncing";
	_connect_bounce_packet(sm_conn, chunk_new_packet(sm_conn, 1));
	return 1;
    }

    /* second check for new protocol: is the session manager JID matching? */
    from = nad_find_attr(sm_conn->nad, 0, "from", NULL);
    if (from < 0) {
	sm_conn->c2s->log->level(LOG_ERR) << "no from attribute on route element from session manager! Dropping packet.";
	return 1;
    }
    from_jid.write(NAD_AVAL(sm_conn->nad, from), NAD_AVAL_L(sm_conn->nad, from));
    local_pool = pool_new();
    if (jid_cmpx(client_conn->smid, jid_new(local_pool, sm_conn->c2s->jid_environment, from_jid.str().c_str()), JID_USER|JID_SERVER) != 0) {
	pool_free(local_pool);

	(sm_conn->c2s->log->level(LOG_WARNING) << "got packet from session manager using old sc protocol, that has unexpected route from attribute: bouncing (got from: ").write(NAD_AVAL(sm_conn->nad, from), NAD_AVAL_L(sm_conn->nad, from)) << ", expected from: " << jid_full(client_conn->smid);
	_connect_bounce_packet(sm_conn, chunk_new_packet(sm_conn, 1));
	return 1;
    }
    pool_free(local_pool);

    return 0;
}

/**
 * handle a stanza received for a old sc protocol connection
 */
static void _connect_handle_error_packet(conn_t sm_conn, conn_t client_conn) {
    int from_attr = -1;
    int error_attr = -1;
    char *smid = NULL;

    /* if our target is in state_SESS, then the sm is telling us about
     * the end of our old session which has the same cid, so just ignore it */
    if (client_conn->state == state_SESS) {
	log_debug(ZONE, "session end for dead session, dropping");
	return;
    }

    /* if there is no such client connection => ignore */
    if (client_conn->fd < 0) {
	log_debug(ZONE, "Got session close for connection, that is already disconnected");
	return;
    }

    /* disconnect if they come from a target with matching sender */
    /* simple auth responses that don't have a client connected get dropped */
    from_attr = nad_find_attr(sm_conn->nad, 0, "from", NULL);
    smid = jid_full(client_conn->smid);
    if (from_attr >= 0 && NAD_AVAL_L(sm_conn->nad, from_attr) == j_strlen(smid) && j_strncmp(smid, NAD_AVAL(sm_conn->nad, from_attr), NAD_AVAL_L(sm_conn->nad, from_attr)) == 0) {
	std::ostringstream reason;

	/* not all errors have error attributes */
	if ((error_attr = nad_find_attr(sm_conn->nad, 0, "error", NULL)) >= 0)
	    reason.write(NAD_AVAL(sm_conn->nad, error_attr), NAD_AVAL_L(sm_conn->nad, error_attr));
	else
	    reason << "Server Error";

	if (client_conn->state == state_OPEN) {
	    if (reason.str() == "Disconnected") {
		conn_close(client_conn, STREAM_ERR_CONFLICT, reason.str().c_str());
	    } else {
		conn_close(client_conn, STREAM_ERR_INTERNAL_SERVER_ERROR, reason.str().c_str());
	    }
	} else {
	    if (reason.str() == "Internal Timeout") {
		conn_close(client_conn, STREAM_ERR_REMOTE_CONNECTION_FAILED, reason.str().c_str());
	    } else {
		conn_close(client_conn, STREAM_ERR_NOT_AUTHORIZED, reason.str().c_str());
	    }
	}
    }
}

static void _connect_handle_sc_packet_started(conn_t sm_conn, int sc_element, conn_t client_conn) {
    int sc_sm = -1;

    /* get the session manager's id for the session */
    sc_sm = nad_find_attr(sm_conn->nad, sc_element, "sc:sm", NULL);
    if (sc_sm < 0) {
	sm_conn->c2s->log->level(LOG_WARNING) << "Got sc packet for action 'started' without an sc:sm attribute. Connot handle this ...";
	return;
    }

    /* did we wait for the confirmation? */
    if (client_conn->sasl_state == state_auth_BOUND_RESOURCE) {
	chunk_t chunk = NULL;

	/* update state */
	client_conn->sasl_state = state_auth_SESSION_STARTED;
	client_conn->state = state_OPEN;
	sm_conn->c2s->pending->erase(jid_full(client_conn->myid));

	/* keep session manager's id */
	if (client_conn->sc_sm != NULL) {
	    free(client_conn->sc_sm);
	}
	std::ostringstream sc_sm_stream;
	sc_sm_stream.write(NAD_AVAL(sm_conn->nad, sc_sm), NAD_AVAL_L(sm_conn->nad, sc_sm));
	client_conn->sc_sm = strdup(sc_sm_stream.str().c_str());

	/* confirm session start */
	nad_free(sm_conn->nad);
	sm_conn->nad = NULL;
	sm_conn->nad = nad_new(sm_conn->c2s->nads);
	chunk = chunk_new(sm_conn);

	nad_append_elem(chunk->nad, "iq", 0);
	nad_append_attr(chunk->nad, "from", client_conn->authzid->server);
	nad_append_attr(chunk->nad, "type", "result");
	if (client_conn->id_session_start != NULL)
	    nad_append_attr(chunk->nad, "id", client_conn->id_session_start);
	nad_append_elem(chunk->nad, "session", 1);
	nad_append_attr(chunk->nad, "xmlns", "urn:ietf:params:xml:ns:xmpp-session");

	/* send response */
	chunk_write(client_conn, chunk, NULL, NULL, NULL);

	/* cleanup */
	if (client_conn->id_session_start != NULL) {
	    free(client_conn->id_session_start);
	    client_conn->id_session_start = NULL;
	}
    }
}

static void _connect_handle_sc_packet_ended(conn_t sm_conn, int sc_element, conn_t client_conn) {
    int sc_c2s = -1;
    int sc_sm = -1;

    /* session using the new protocol has been ended */

    /* get the required attribute values */
    sc_c2s = nad_find_attr(sm_conn->nad, sc_element, "sc:sm", NULL);
    sc_sm = nad_find_attr(sm_conn->nad, sc_element, "sc:c2s", NULL);

    /* check if we have to close a connection */
    if (NAD_AVAL_L(sm_conn->nad, sc_sm) == j_strlen(client_conn->sc_sm) && j_strncmp(NAD_AVAL(sm_conn->nad, sc_sm), client_conn->sc_sm, NAD_AVAL_L(sm_conn->nad, sc_sm)) == 0 && client_conn->fd >= 0) {
	sm_conn->c2s->log->level(LOG_NOTICE) << "session manager requested, that we close fd " << client_conn->fd;
	conn_close(client_conn, STREAM_ERR_TIMEOUT, "session manager requested to close connection");
    } else {
	sm_conn->c2s->log->level(LOG_NOTICE) << "session manager confirmed ended session for fd " << client_conn->fd;
    }
}

static void _connect_handle_sc_packet(conn_t sm_conn, int sc_element, conn_t client_conn) {
    int action = -1;

    /* get the sc action of the packet */
    action = nad_find_attr(sm_conn->nad, sc_element, "action", NULL);
    if (action < 0) {
	sm_conn->c2s->log->level(LOG_WARNING) << "Got session control packet without an action";
	return;
    }
    std::ostringstream action_stream;
    action_stream.write(NAD_AVAL(sm_conn->nad, action), NAD_AVAL_L(sm_conn->nad, action));
    std::string action_str = action_stream.str();

    /* switch depending on action */
    if (action_str == "started") {
	_connect_handle_sc_packet_started(sm_conn, sc_element, client_conn);
    } else if (action_str == "ended") {
	_connect_handle_sc_packet_ended(sm_conn, sc_element, client_conn);
    } else {
	sm_conn->c2s->log->level(LOG_NOTICE) << "Got session control packet for action '" << action_str << "', that we do not handle yet.";
    }
}

/* process completed nads */
static void _connect_process(conn_t c) {
    chunk_t chunk = NULL;
    int attr = -1; /* used for searching various attributes in NAD */
    int id = 0; /* id of the target session (index in c2s->conns) */
    int element = -1;
    int stanza_element = -1; /* NAD handle of the message, iq, or presence element of the stanza */
    int uses_new_sc_protocol = 0; /* sc proto version of processed stanza: 0 for old protocol, 1 for new protocol */
    conn_t target = NULL; /* the connection where to forward the stanza to */
    conn_t pending = NULL;

    log_debug(ZONE, "got packet from sm, processing");

    /* always check for the return handshake :) */
    if (c->state != state_OPEN) {
        if (j_strncmp(NAD_ENAME(c->nad, 0), "handshake", 9) == 0) {
            c->state = state_OPEN;
            log_debug(ZONE,"handshake accepted, we're connected to the sm");
        }
        return;
    }

    /* just ignore anything except route packets */
    if (j_strncmp(NAD_ENAME(c->nad, 0), "route", 5) != 0) {
	log_debug(ZONE, "got non-route packet: %.*", NAD_ENAME_L(c->nad, 0), NAD_ENAME(c->nad, 0));
	return;
    }

    /* get the target connection of the packet */

    /* every route must have a target client id */
    attr = nad_find_attr(c->nad, 0, "to", NULL);
    if (attr == -1) {
	c->c2s->log->level(LOG_ERR) << "Got a <route/> stanza with no 'to' attribute. This should not happen, we cannot process this.";
	return;
    }
    std::ostringstream cid;
    cid.write(NAD_AVAL(c->nad, attr), NAD_AVAL_L(c->nad, attr));
    std::istringstream id_stream(cid.str());
    id_stream >> id;

    /* check if the packet uses the new session control protocol */
    stanza_element = _connect_get_stanza_element(c->nad, 0);
    if (stanza_element >= 0 && nad_find_attr(c->nad, stanza_element, "xmlns:sc", "http://jabberd.jabberstudio.org/ns/session/1.0") >= 0) {
	attr = nad_find_attr(c->nad, stanza_element, "sc:c2s", NULL);
	if (attr >= 0) {
	    uses_new_sc_protocol = 1;
	    std::ostringstream c2s_id;
	    c2s_id.write(NAD_AVAL(c->nad, attr), NAD_AVAL_L(c->nad, attr));
	    std::istringstream c2s_stream(c2s_id.str());
	    c2s_stream >> id;
	}
    }

    /* does not matter if old or new session control protocol: id should now have the target fd */
    if (id >= c->c2s->max_fds || ((target = &c->c2s->conns[id]) && (target->fd == -1 || target == c))) {
        log_debug(ZONE, "dropping packet for invalid conn %d (%s)", id, uses_new_sc_protocol ? "new sc" : stanza_element >= 0 ? "old sc" : "sc:session");
        return;
    }

    /* look for packets of the new session manager protocol */
    element = nad_find_elem(c->nad, 0, "sc:session", 1);
    if (element >= 0) {
	attr = nad_find_attr(c->nad, element, "xmlns:sc", "http://jabberd.jabberstudio.org/ns/session/1.0");
	if (attr >= 0) {
	    _connect_handle_sc_packet(c, element, target);
	    return;
	}
    }

    /* sanity check on the packet: is it the right recipient? */
    if (uses_new_sc_protocol ? _connect_packet_is_unsane_new_sc_proto(c, target, stanza_element) : _connect_packet_is_unsane_old_sc_proto(c, target)) {
	return;
    }

    log_debug(ZONE, "processing route to %s with target %X", cid.str().c_str(), target);

    /* handle type='error' packets for old sc protocol */
    if (nad_find_attr(c->nad, 0, "type", "error") >= 0 && target->sasl_state == state_auth_NONE) {
	_connect_handle_error_packet(c, target);
	return;
    }

    /* get packet source address */
    if ((attr = nad_find_attr(c->nad, 0, "from", NULL)) < 0) {
        log_debug(ZONE, "missing sender on route?");
        return;
    }
    std::ostringstream from_str;
    from_str.write(NAD_AVAL(c->nad, attr), NAD_AVAL_L(c->nad, attr));

    /* look for session creation responses and change client accordingly 
     * (note: if no target drop through w/ chunk since it'll error in endElement) */
    if (target->fd >= 0) {
        attr = nad_find_attr(c->nad, 0, "type", "session");
        if (attr >= 0) {
            log_debug(ZONE, "client %d now has a session %s", target->fd, from_str.str().c_str());
            target->state = state_OPEN;
	    c->c2s->pending->erase(jid_full(target->myid));
            target->smid = jid_new(target->idp, c->c2s->jid_environment, from_str.str().c_str());
            mio_read(c->c2s->mio, target->fd); /* start reading again now */
        }
    }

    /* the rest of them we just need a chunk to store until they get sent to the client */
    chunk = chunk_new_packet(c, 1);

    /* look for iq results for auths */
    if (c->c2s->pending->find(cid.str()) != c->c2s->pending->end() && (pending = (*c->c2s->pending)[cid.str()]) != NULL && target->state == state_AUTH) {
        /* got a result, start a session */
        attr = nad_find_attr(chunk->nad, 1, "type", NULL);
        if(attr >= 0 && j_strncmp(NAD_AVAL(chunk->nad, attr), "result", 6) == 0)
        {
            /* auth was ok, send session request */
            log_debug(ZONE,"client %d authorized, requesting session",target->fd);
            chunk_write(c, chunk, jid_full(target->smid), jid_full(pending->myid), "session");
            pending->state = state_SESS;

	    /* log the successfull login */
	    c->c2s->log->level(LOG_NOTICE) << "user " << jid_full(target->userid) << " connected on fd " << target->fd << (target->c2s->iplog ? " from " : "") << (target->c2s->iplog ? target->ip : "");
	   
	    /* send a notification message if requested */
	    connectionstate_send(c->c2s->config, c, target, 1);

            return;
        }else{ /* start over */
            pending->state = state_NONE;
            target = pending;
        }
    }

    /* now we have to do something with our chunk */
    log_debug(ZONE,"sm sent us a chunk for %s", cid.str().c_str());

    /* either bounce or send the chunk to the client */
    if (target->fd >= 0) {
	if (stanza_element >= 0) {
	    nad_set_attr(chunk->nad, stanza_element, "xmlns:sc", NULL);
	    nad_set_attr(chunk->nad, stanza_element, "sc:c2s", NULL);
	    nad_set_attr(chunk->nad, stanza_element, "sc:sm", NULL);
	}

        chunk_write(target, chunk, NULL, NULL, NULL);
	target->out_stanzas++;
    }
    else
	_connect_bounce_packet(c, chunk);
}

/* handle new elements */
static void _connect_startElement(void *arg, const char* name, const char** atts)
{
    conn_t c = (conn_t)arg;
    int i = 0;

    /* track how far down we are in the xml */
    c->depth++;

    /* process stream header first */
    if(c->depth == 1) {
	std::ostringstream id_secret;
	char handshake[41];

        /* Extract stream ID and generate a key to hash */
	id_secret << j_attr(atts, "id") << c->c2s->sm_secret;
	shahash_r(id_secret.str().c_str(), handshake);

        /* create a new nad */
        c->nad = nad_new(c->c2s->nads);
        nad_append_elem(c->nad, "handshake", 1);
        nad_append_cdata(c->nad, handshake, strlen(handshake), 2);

        log_debug(ZONE,"handshaking with sm");

        /* create a chunk and write it */
        chunk_write(c, chunk_new(c), NULL, NULL, NULL);

        return;
    }

    /* make a new nad if we don't already have one */
    if(c->nad == NULL)
        c->nad = nad_new(c->c2s->nads);

    /* append new element data to nad */
    nad_append_elem(c->nad, (char *) name, c->depth - 1);
    i = 0;
    while(atts[i] != '\0')
    {
        nad_append_attr(c->nad, (char *) atts[i], (char *) atts[i + 1]);
        i += 2;
    }
}

static void _connect_endElement(void *arg, const char* name)
{
    conn_t c = (conn_t)arg;

    /* going up for air */
    c->depth--;

    if(c->depth == 1)
    {
        _connect_process(c);
        if(c->nad != NULL)
        {
            nad_free(c->nad);
            c->nad = NULL;
        }
    }

    /* if we processed the closing stream root, flag to close l8r */
    if(c->depth == 0)
        c->depth = -1; /* we can't close here, expat gets free'd on close :) */
}


static void _connect_charData(void *arg, const char *str, int len)
{
    conn_t c = (conn_t)arg;

    /* no nad? no cdata */
    if(c->nad == NULL) return;

    nad_append_cdata(c->nad, (char *) str, len, c->depth);
}


/* internal handler to read incoming data from the sm and parse/process it */
static int _connect_io(mio_t m, mio_action_t a, int fd, const void *data, void *arg)
{
    char buf[1024]; /* !!! make static when not threaded? move into conn_st? */
    int len, ret, x, retries;
    conn_t c = (conn_t)arg;
    c2s_t c2s;

    log_debug(ZONE,"io action %d with fd %d",a,fd);

    switch(a)
    {
    case action_READ:

        /* read as much data as we can from the sm */
        while(1)
        {
            len = read(fd, buf, 1024);
            if((ret = conn_read(c, buf, len)) != 1 || len < 1024) break;
        }
        return 1;

    case action_WRITE:

        /* let's break this into another function, it's a bit messy */
        return conn_write(c);

    case action_CLOSE:

        /* if we're closing before we're open, we've got issues */
        if(c->state != state_OPEN) {
            /* XXX handle this better */
	    c->c2s->log->level(LOG_ERR) << "secret is wrong or SM kicked us off for some other reason";
            exit(1);
        }

        log_debug(ZONE,"reconnecting to sm");

        /* try to connect again */
        c2s = c->c2s;
	if (!c2s->shutting_down) {
	    retries = j_atoi(config_get_one(c2s->config, "sm.retries", 0), 5);
	    for (x = 0; x < retries; x++) {
		if (connect_new(c2s))
		    break;
		/* XXX: Make this an option? */
		sleep(5);
	    }

	    /* See if we were able to reconnect */
	    if (x == retries) {
		c2s->log->level(LOG_ERR) << "Unable to reconnect ot the SM.";
		exit(1);
	    }

	    /* copy over old write queue if any */
	    if(c->writeq != NULL) {
		c2s->sm->writeq = c->writeq;
		c2s->sm->qtail = c->qtail;
		mio_write(c2s->mio, c2s->sm->fd);
	    }
	}

        conn_free(c);
        break;

    case action_ACCEPT:
    case action_IDLE:
        break;
    }
    return 0;
}


int connect_new(c2s_t c2s)
{
    int fd;
#ifdef USE_IPV6
    std::ostringstream port;
    struct addrinfo hints, *addr_res, *addr_itr;
#else
    unsigned long int ip = 0;
    struct hostent *h;
    char iphost[16];
    struct sockaddr_in sa;
#endif
    conn_t c;
    char dummy[] = "<stream:stream xmlns='jabber:component:accept' xmlns:stream='http://etherx.jabber.org/streams' to='";

    c2s->log->level(LOG_NOTICE) << "attempting connection to sm at " << c2s->sm_host << ":" << c2s->sm_port << " as " << c2s->sm_id;

#ifdef USE_IPV6
    /* prepare resolving of router address */
    port << c2s->sm_port;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    /* resolve all addresses */
    if (getaddrinfo(c2s->sm_host, port.str().c_str(), &hints, &addr_res)) {
	c2s->log->level(LOG_ERR) << "DNS lookup for " << c2s->sm_host << " failed";
	exit(1);
    }

    /* iterate through the resolved addresses and try to connect */
    for (addr_itr = addr_res; addr_itr != NULL; addr_itr = addr_itr->ai_next) {
	fd = socket(addr_itr->ai_family, addr_itr->ai_socktype, addr_itr->ai_protocol);
	if (fd != -1) {
	    if (connect(fd, addr_itr->ai_addr, addr_itr->ai_addrlen)) {
		close(fd);
		continue;
	    }
	    break;
	}
    }

    /* free the result of the resolving */
    freeaddrinfo(addr_res);

    if (addr_itr == NULL) {
	c2s->log->level(LOG_ERR) << "failed to connect to router";
	if (fd != -1) {
	    close(fd);
	}
	return 0;
    }
#else
    /* get the ip to connect to */
    if (c2s->sm_host != NULL) {
        h = gethostbyname(c2s->sm_host);
        if (h == NULL) {
	    c2s->log->level(LOG_ERR) << "DNS lookup for " << c2s->sm_host << " failed: " << hstrerror(h_errno);
            exit(1);
        }
        inet_ntop(AF_INET, h->h_addr_list[0], iphost, 16);
        ip = inet_addr(iphost);

        log_debug(ZONE, "resolved: %s = %s", c2s->sm_host, iphost);
    }

    /* attempt to create a socket */
    if ((fd = socket(AF_INET,SOCK_STREAM,0)) < 0) {
	c2s->log->level(LOG_ERR) << "failed to connect to SM: " << strerror(errno);
        return 0;
    }

    /* set up and bind address info */
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(c2s->sm_port);
    if (ip > 0)
	sa.sin_addr.s_addr = ip;

    /* connect to the sm please */
    if (connect(fd,(struct sockaddr*)&sa,sizeof(sa)) < 0) {
	c2s->log->level(LOG_ERR) << "failed to connect to SM: " << strerror(errno);

        close(fd);
        return 0;
    }
#endif

    /* make sure mio will take this fd */
    if(mio_fd(c2s->mio, fd, NULL, NULL) < 0) {
	c2s->log->level(LOG_ERR) << "failed to connect to SM: " << strerror(errno);

        close(fd);
        return 0;
    }

    /* make our conn_t from this */
    c2s->sm = c = conn_new(c2s, fd);
    mio_app(c2s->mio, fd, _connect_io, (void*)c);
    mio_read(c2s->mio,fd);

    /* set up expat callbacks */
    XML_SetUserData(c->expat, (void*)c);
    XML_SetElementHandler(c->expat, _connect_startElement, _connect_endElement);
    XML_SetCharacterDataHandler(c->expat, _connect_charData);

    /* send stream header */
    write(fd,dummy,strlen(dummy));
    write(fd,c2s->sm_id,strlen(c2s->sm_id));
    write(fd,"'>",2);

    /* keep the name of the root element */
    c->root_element = root_element_NORMAL;

    /* loop reading until it's open or dead */
    while (c->state != state_OPEN)
	_connect_io(c2s->mio, action_READ, fd, NULL, (void*)c);    

    c2s->log->level(LOG_NOTICE) << "connection to SM completed on fd " << fd;

    return 1;
}
