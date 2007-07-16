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

/**
 * @file dialback_out.cc
 * @brief handle outgoing server to server connections
 *
 * This is where the server to server connection manager handles outgoing connections.
 *
 * There might be two types of outgoing connections:
 * - We want to send stanzas to the user of an other server, we then have to
 *   convince the peer, that we are who we claim to be (using dialback)
 * - We want to verify the identity of a peer that connected to us, using the
 *   dialback protocol. (We might reuse an outgoing connection of the other type
 *   if there is already one.)
 *
 * On outgoing connections, we need to send:
 * - An initial db:result element to tell the peer, that we want to authorize for
 *   the use of a domain, that the peer should verify that we are allowed to use
 *   this sending domain - and watch for the results to this
 * - db:verify elements to verify if a peer is allowed to use a domain as
 *   sender - and watch for the results
 * - After we are authorized by the peer to send stanzas from a domain, we send them.
 * - The starttls command, if the peer and we are supporting TLS.
 */
#include "dialback.h"

/* forward declaration */
void dialback_out_read(mio m, int flags, void *arg, xmlnode x, char* unused1, int unused2);

/**
 * try to start a connection based upon a given connect object
 *
 * Tell mio to connect to the peer and make dialback_out_read() the first mio handler
 *
 * @param c the connect object
 */
void dialback_out_connect(dboc c) {
    char *ip, *col;
    int port = 5269;

    if(c->ip == NULL)
        return;

    ip = c->ip;
    c->ip = strchr(ip,',');
    if (c->ip != NULL) {
	/* chop off this ip if there is another, track the other */
        *c->ip = '\0';
        c->ip++;
    }

    log_debug2(ZONE, LOGT_IO, "Attempting to connect to %s at %s",jid_full(c->key),ip);

    /* to which IP we connect, for logging */
    if (c->connect_results != NULL) {
	spool_add(c->connect_results, ip);
	spool_add(c->connect_results, ": ");
    }

    /* get the ip/port for io_select */
#ifdef WITH_IPV6
    if (ip[0] == '[') {
	/* format "[ipaddr]:port" or "[ipaddr]" */
	ip++;
	col=strchr(ip,']');
	if (col != NULL) {
	    *col = '\0';
	    if (col[1]==':') {
		col++;
	    }
	}
    } else {
	/* format "ipaddr" or "ipaddr:port" */
	col = strchr(ip, ':');
	/* if it has at least two colons it is an IPv6 address */
	if (col!=NULL && strchr(col+1,':')) {
	    col = NULL;
	}
    }
#else
    col = strchr(ip,':');
#endif
    if (col != NULL) {
        *col = '\0';
        col++;
        port = atoi(col);
    }

    /* we are now in the state of connecting */
    c->connection_state = connecting;
    
    mio_connect(ip, port, dialback_out_read, (void *)c, 20, MIO_CONNECT_XML);
}

/**
 * make a new outgoing connect(ion) object, and start to connect to the peer
 *
 * @param d the dialback instance
 * @param key destination and source for this connection
 * @param ip where to connect to (format see description to the _dboc structure)
 * @param db_state if sending a <db:result/> is requested
 * @return the newly created object
 */
dboc dialback_out_connection(db d, jid key, char *ip, db_request db_state) {
    dboc c;
    pool p;

    if((c = static_cast<dboc>(xhash_get(d->out_connecting, jid_full(key)))) != NULL) {
	/* db:request now wanted? */
	if (db_state == want_request) {
	    if (c->db_state == not_requested) {
		log_debug2(ZONE, LOGT_IO, "packet for existing connection: state change not_requested -> want_request");
		c->db_state = want_request;
	    } else if (c->db_state == could_request) {
		/* send <db:result/> to request dialback */
		xmlnode db_result = xmlnode_new_tag_ns("result", "db", NS_DIALBACK);
		xmlnode_put_attrib_ns(db_result, "to", NULL, NULL, c->key->server);
		xmlnode_put_attrib_ns(db_result, "from", NULL, NULL, c->key->resource);
		xmlnode_insert_cdata(db_result,  dialback_merlin(xmlnode_pool(db_result), c->d->secret, c->key->server, c->key->resource, c->stream_id), -1);
		mio_write(c->m,db_result, NULL, 0);
		c->db_state = sent_request;
		log_debug2(ZONE, LOGT_IO, "packet for existing connection: state change could_request -> sent_request");
	    }
	}
        return c;
    }

    if(ip == NULL)
        return NULL;

    /* none, make a new one */
    p = pool_heap(2*1024);
    c = static_cast<dboc>(pmalloco(p, sizeof(_dboc)));
    c->p = p;
    c->d = d;
    c->key = jid_new(p,jid_full(key));
    c->stamp = time(NULL);
    c->verifies = xmlnode_new_tag_pool_ns(p, "v", NULL, NS_JABBERD_WRAPPER);
    c->ip = pstrdup(p,ip);
    c->db_state = db_state;
    c->connection_state = created;
    c->connect_results = spool_new(p);
    c->xmpp_version = -1;

    /* insert in the hash */
    xhash_put(d->out_connecting, jid_full(c->key), (void *)c);

    /* start the conneciton process */
    dialback_out_connect(c);

    return c;
}

/**
 * get the textual representation of a db_connection_state
 *
 * @param state the state
 * @return the textual representation
 */
static const char *dialback_out_connection_state_string(db_connection_state state) {
    switch (state) {
	case created:
	    return N_("connection object just created");
	case connecting:
	    return N_("connecting to other host");
	case connected:
	    return N_("connected to other host");
	case got_streamroot:
	    return N_("got the stream root");
	case waiting_features:
	    return N_("waiting for stream features on XMPP stream");
	case got_features:
	    return N_("got stream features on XMPP stream");
	case sent_db_request:
	    return N_("sent out dialback request");
	case db_succeeded:
	    return N_("dialback succeeded");
	case db_failed:
	    return N_("dialback failed");
	case sasl_started:
	    return N_("started using SASL");
	case sasl_fail:
	    return N_("failed to auth using SASL");
	case sasl_success:
	    return N_("SASL succeeded");
    }
    return N_("unknown connection state");
}

/**
 * handle failed connection attempts, bounce pending stanzas and db:verify elements
 *
 * either we're connected, or failed, or something like that, but the connection process is kaput
 *
 * @param c the outgoing connect that failed
 */
void dialback_out_connection_cleanup(dboc c)
{
    dboq cur, next;
    xmlnode x;
    spool errmsg = NULL;
    char *connect_results = NULL;
    char *bounce_reason = NULL;
    const char* lang = NULL;

    xhash_zap(c->d->out_connecting,jid_full(c->key));

    /* get the results of connection attempts */
    if (c->connect_results != NULL) {
	connect_results = spool_print(c->connect_results);
    }

    /* if there was never any ->m set but there's a queue yet, then we probably never got connected, just make a note of it */
    if(c->m == NULL && c->q != NULL) {
	log_notice(c->d->i->id, "failed to establish connection to %s, %s: %s", c->key->server, dialback_out_connection_state_string(c->connection_state), connect_results);
    }

    /* if there's any packets in the queue, flush them! */
    cur = c->q;
    if (cur != NULL) {
	lang = xmlnode_get_lang(cur->x);
	/* generate bounce message, but only if there are queued messages */
	errmsg = spool_new(c->p);
	if (c->settings_failed) {
	    spool_add(errmsg, messages_get(lang, N_("Failed to deliver stanza to other server because of configured stream parameters.")));
	} else {
	    spool_add(errmsg, messages_get(lang, N_("Failed to deliver stanza to other server while ")));
	    spool_add(errmsg, messages_get(lang, N_(dialback_out_connection_state_string(c->connection_state))));
	    spool_add(errmsg, ": ");
	    spool_add(errmsg, connect_results);
	}
	bounce_reason = spool_print(errmsg);
    }
    while(cur != NULL) {
        next = cur->next;
        deliver_fail(dpacket_new(cur->x), bounce_reason ? bounce_reason : messages_get(lang, N_("Could not send stanza to other server")));
        cur = next;
	lang = cur == NULL ? NULL : xmlnode_get_lang(cur->x);
    }

    /* also kill any validations still waiting */
    for(x = xmlnode_get_firstchild(c->verifies); x != NULL; x = xmlnode_get_nextsibling(x)) {
        jutil_tofrom(x);
        dialback_in_verify(c->d, xmlnode_dup(x)); /* it'll take these verifies and trash them */
    }

    pool_free(c->p);
}

/**
 * handle packets we receive from our router for other hosts
 *
 * (packets to our instances address are not handled here, but in dialback_in_verify())
 *
 * We have to:
 * - revert some magic we are using to talk to the dns resolver for db:verify packets
 * - check if there is already a connection and establish one else
 * - send or queue the packet (depending if we already authorized and if it's a db:verify)
 *
 * @param d the dialback instance
 * @param x the packet
 * @param ip where to connect to (if necessary)
 */
void dialback_out_packet(db d, xmlnode x, char *ip) {
    jid to, from, key;
    miod md;
    int verify = 0;
    dboq q;
    dboc c;

    to = jid_new(xmlnode_pool(x),xmlnode_get_attrib_ns(x, "to", NULL));
    from = jid_new(xmlnode_pool(x),xmlnode_get_attrib_ns(x, "from", NULL));
    if (to == NULL || from == NULL) {
        log_warn(d->i->id, "dropping packet, invalid to or from: %s", xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));
        xmlnode_free(x);
        return;
    }

    log_debug2(ZONE, LOGT_IO, "dbout packet[%s]: %s", ip, xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));

    /* db:verify packets come in with us as the sender */
    if (j_strcmp(from->server, d->i->id) == 0) {
        verify = 1;
        /* fix the headers, restore the real from */
	/* (I think we wouldn't need to from/ofrom thing anymore because we have dnsqueryby, that we need for s2s clustering) */
        xmlnode_put_attrib_ns(x, "from", NULL, NULL, xmlnode_get_attrib_ns(x, "ofrom", NULL));
        xmlnode_hide_attrib_ns(x, "ofrom", NULL);
	xmlnode_hide_attrib_ns(x, "dnsqueryby", NULL);
        from = jid_new(xmlnode_pool(x),xmlnode_get_attrib_ns(x, "from", NULL));
    }

    /* build the standard key */
    key = jid_new(xmlnode_pool(x), to->server);
    jid_set(key, from->server, JID_RESOURCE);

    /* try to get an active connection */
    md = static_cast<miod>(xhash_get(d->out_ok_db, jid_full(key)));

    log_debug2(ZONE, LOGT_IO, "outgoing packet with key %s and located existing %X",jid_full(key),md);

    /* yay! that was easy, just send the packet :) */
    if (md != NULL) {
        /* if we've got an ip sent, and a connected host, we should be registered! */
        if (ip != NULL)
            register_instance(md->d->i, key->server);
        dialback_miod_write(md, x);
        return;
    }

    /* get a connection to the other server */
    c = dialback_out_connection(d, key, dialback_ip_get(d, key, ip), verify ? not_requested : want_request);
    log_debug2(ZONE, LOGT_IO, "got connection %x for request %s (%s)", c, jid_full(key), verify ? "not_requested" : "want_request");

    /* verify requests can't be queued, they need to be sent outright */
    if (verify) {
        if (c == NULL) {
            jutil_tofrom(x); /* pretend it bounced */
            dialback_in_verify(d, x); /* no connection to send db:verify to, bounce back to in to send failure */
            return;
        }

        /* if the server is already connected, just write it */
        if (c->m != NULL) {
            mio_write(c->m, x, NULL, -1);
        } else {  /* queue it so that it's written after we're connected */
            xmlnode_insert_tag_node(c->verifies, x);
            xmlnode_free(x);
        }

        return;
    }

    if (c == NULL) {
        log_warn(d->i->id, "dropping a packet that was missing an ip to connect to: %s", xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));
        xmlnode_free(x);
        return;
    }

    /* insert into the queue */
    q = static_cast<dboq>(pmalloco(xmlnode_pool(x), sizeof(_dboq)));
    q->stamp = time(NULL);
    q->x = x;
    q->next = c->q;
    c->q = q;

}

/**
 * handle the events (incoming stanzas) on an outgoing dialback socket, which isn't much of a job
 *
 * The only packets we have to expect on an outgoing dialback socket are db:verify and maybe stream:error
 *
 * @param m the connection the packet has been received on
 * @param flags the mio action, we ignore anything but MIO_XML_NODE
 * @param arg the dialback instance
 * @param x the packet that has been received
 * @param unused1 unused/ignored
 * @param unused2 unused/ignored
 */
void dialback_out_read_db(mio m, int flags, void *arg, xmlnode x, char* unused1, int unused2) {
    db d = (db)arg;

    if(flags != MIO_XML_NODE) return;

    /* it's either a valid verify response, or bust! */
    if (j_strcmp(xmlnode_get_localname(x),"verify") == 0 && j_strcmp(xmlnode_get_namespace(x), NS_DIALBACK) == 0) {
        dialback_in_verify(d, x);
        return;
    }

    if (j_strcmp(xmlnode_get_localname(x),"error") == 0 && j_strcmp(xmlnode_get_namespace(x), NS_STREAM) == 0) {
	spool s = spool_new(x->p);
	streamerr errstruct = static_cast<streamerr>(pmalloco(x->p, sizeof(_streamerr)));
	char *errmsg = NULL;

	/* generate the error message */
	xstream_parse_error(x->p, x, errstruct);
	xstream_format_error(s, errstruct);
	errmsg = spool_print(s);

	/* logging */
	switch (errstruct->severity) {
	    case normal:
		log_debug2(ZONE, LOGT_IO, "stream error on outgoing db conn to %s: %s", mio_ip(m), errmsg);
		break;
	    case configuration:
	    case feature_lack:
	    case unknown:
		log_warn(d->i->id, "received stream error on outgoing db conn to %s: %s", mio_ip(m), errmsg);
		break;
	    case error:
	    default:
		log_error(d->i->id, "received stream error on outgoing db conn to %s: %s", mio_ip(m), errmsg);
	}
    } else {
        mio_write(m, NULL, "<stream:error><undefined-condition xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Received data on a send-only socket. You are not Allowed to send data on this socket!</text></stream:error>", -1);
    }
    
    mio_close(m);
    xmlnode_free(x);
}

/**
 * util to flush queue to mio
 *
 * Take elements from the queue and send it to a miod connection.
 *
 * @param md the miod connection
 * @param q the queue to flush
 */
void dialback_out_qflush(miod md, dboq q) {
    dboq cur, next;

    cur = q;
    while (cur != NULL) {
        next = cur->next;
        dialback_miod_write(md, cur->x);
        cur = next;
    }
}

/**
 * send pending db:verify requests, when the connection is read
 *
 * @param m the ::mio to send the verifies to
 * @param c the ::dboc containing the db:verify packets
 */
static void dialback_out_send_verifies(mio m, dboc c) {
    xmlnode cur = NULL;

    /* sanity check */
    if (m == NULL || c == NULL)
	return;

    for (cur = xmlnode_get_firstchild(c->verifies); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
	mio_write(m, xmlnode_dup(cur), NULL, -1);
	xmlnode_hide(cur);
    }
}

/**
 * handle the early connection process
 *
 * What to do:
 * - Send stream header after mio connected a socket for us
 * - Process the incoming stream header
 * - Check for incoming stream:features
 * - Generate db:result queries to start authorizing for a domain
 * - Process incoming db:verify queries
 * - Process incoming db:result responses (flush/send queue of waiting stanzas)
 */
void dialback_out_read(mio m, int flags, void *arg, xmlnode x, char* unused1, int unused2) {
    dboc c = (dboc)arg;
    xmlnode cur;
    miod md;

    log_debug2(ZONE, LOGT_IO, "dbout read: fd %d flag %d key %s", m->fd, flags, jid_full(c->key));

    switch (flags) {
	case MIO_NEW:
	    log_debug2(ZONE, LOGT_IO, "NEW outgoing server socket connected at %d", m->fd);

	    /* add to the connect result messages */
	    if (c->connection_state != sasl_success) {
		if (c->connect_results != NULL && c->connection_state != connected) {
		    spool_add(c->connect_results, "Connected");
		}
		c->connection_state = connected;
	    }

	    /* outgoing conneciton, write the header */
	    cur = xstream_header(c->key->server, c->key->resource);
	    xmlnode_hide_attrib_ns(cur, "id", NULL);					/* no, we don't need the id on this stream */
	    if (j_strcmp(static_cast<char*>(xhash_get_by_domain(c->d->hosts_auth, c->key->server)), "sasl") != 0)
		xmlnode_put_attrib_ns(cur, "db", "xmlns", NS_XMLNS, NS_DIALBACK);	/* flag ourselves as dialback capable */
	    if (j_strcmp(static_cast<char*>(xhash_get_by_domain(c->d->hosts_xmpp, c->key->server)), "no") != 0) {
		/* we flag support for XMPP 1.0 */
		xmlnode_put_attrib_ns(cur, "version", NULL, NULL, "1.0");
	    }
	    xmlnode_put_attrib_ns(cur, "check", "loop", NS_JABBERD_LOOPCHECK, dialback_get_loopcheck_token(c->d));
	    mio_write_root(m, cur, 0);
	    return;

	case MIO_XML_ROOT:
	    log_debug2(ZONE, LOGT_IO, "Incoming root %s", xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));
	    if (c->connection_state != sasl_success)
		c->connection_state = got_streamroot;
	    else {
		if (dialback_check_settings(c->d, m, c->key->server, 1, 1, c->xmpp_version) == 0) {
		    c->settings_failed = 1;
		    break;
		}
	    }

	    /* remember the stream id the connected entity assigned ... required to do dialback */
	    c->stream_id = pstrdup(c->p, xmlnode_get_attrib_ns(x, "id", NULL));
	    if (c->stream_id == NULL) {
		mio_write(m, NULL, "<stream:error><invalid-id xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>You are missing the id attribute in your stream header!</text></stream:error>", -1);
		mio_close(m);
		break;
	    }

	    /* make sure we're not connecting to ourselves */
	    if (xhash_get(c->d->in_id,c->stream_id) != NULL) {
		log_alert(c->key->server,"hostname maps back to ourselves!- No service defined for this hostname, can not handle request. Check jabberd configuration.");
		mio_write(m, NULL, "<stream:error><internal-server-error xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Mirror Mirror on the wall (we connected to ourself)</text></stream:error>", -1);
		mio_close(m);
		break;
	    }

	    /* check version */
	    c->xmpp_version = j_atoi(xmlnode_get_attrib_ns(x, "version", NULL), 0);
	    try {
		m->in_root->get_nsprefix(NS_DIALBACK);
		c->flags.db = 1;
	    } catch (std::invalid_argument) {
		c->flags.db = 0;
	    }

	    /* deprecated non-dialback protocol, reject connection */
	    if (c->xmpp_version < 1 && !c->flags.db) {
		/* Muahahaha!  you suck! *click* */
		log_notice(c->key->server,"Legacy server access denied");
		mio_write(m, NULL, "<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Legacy Access Denied!</text></stream:error>", -1);
		mio_close(m);
		break;
	    }

	    /* create and send our result request to initiate dialback for non XMPP-sessions (XMPP has to wait for stream features) */
	    if (c->xmpp_version < 1) {
		/* check the require-tls setting */
		if (dialback_check_settings(c->d, m, c->key->server, 1, 0, c->xmpp_version) == 0) {
		    c->settings_failed = 1;
		    break;
		}

		if (j_strcmp(static_cast<char*>(xhash_get_by_domain(c->d->hosts_auth, "sasl")), "sasl") == 0) {
		    log_warn(c->d->i->id, "pre-XMPP 1.0 peer %s cannot support SASL, but we are configured to require this.", c->key->server);
		    mio_write(m, NULL, "<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xml:lang='en' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>Sorry, but we require SASL auth, but you seem to only support dialback.</text></stream:error>", -1);
		    mio_close(m);
		    break;
		}

		log_debug2(ZONE, LOGT_IO, "pre-XMPP 1.0 stream could now send <db:result/>");
		if (c->db_state == want_request) {
		    /* send db request */
		    cur = xmlnode_new_tag_ns("result", "db", NS_DIALBACK);
		    xmlnode_put_attrib_ns(cur, "to", NULL, NULL, c->key->server);
		    xmlnode_put_attrib_ns(cur, "from", NULL, NULL, c->key->resource);
		    xmlnode_insert_cdata(cur,  dialback_merlin(xmlnode_pool(cur), c->d->secret, c->key->server, c->key->resource, c->stream_id), -1);
		    mio_write(m,cur, NULL, 0);
		    c->db_state = sent_request;
		    c->connection_state = sent_db_request;
		    log_debug2(ZONE, LOGT_IO, "... and we wanted ... and we sent <db:result/>");
		} else if (c->db_state == not_requested) {
		    c->db_state = could_request;
		    log_debug2(ZONE, LOGT_IO, "... but we didn't want yet");
		}
	    } else if (c->connection_state != sasl_success) {
		c->connection_state = waiting_features;
	    }

	    /* well, we're connected to a dialback server, we can at least send verify requests now */
	    c->m = m;
	    if (c->xmpp_version < 1) {
		for(cur = xmlnode_get_firstchild(c->verifies); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
		    mio_write(m, xmlnode_dup(cur), NULL, -1);
		    xmlnode_hide(cur);
		}
	    }

	    break;
	case MIO_XML_NODE:
	    /* watch for stream errors */
	    if (j_strcmp(xmlnode_get_localname(x), "error") == 0 && j_strcmp(xmlnode_get_namespace(x), NS_STREAM) == 0) {
		spool s = spool_new(x->p);
		streamerr errstruct = static_cast<streamerr>(pmalloco(x->p, sizeof(_streamerr)));
		char *errmsg = NULL;

		/* generate error message */
		xstream_parse_error(x->p, x, errstruct);
		xstream_format_error(s, errstruct);
		errmsg = spool_print(s);

		/* append error message to connect_results */
		if (c->connect_results != NULL && errmsg != NULL) {
		    spool_add(c->connect_results, " (");
		    spool_add(c->connect_results, pstrdup(c->connect_results->p, errmsg));
		    spool_add(c->connect_results, ")");
		}

		/* logging */
		switch (errstruct->severity) {
		    case normal:
			log_debug2(ZONE, LOGT_IO, "stream error on outgoing%s conn to %s (%s): %s", c->xmpp_version < 0 ? "" : c->xmpp_version == 0 ? " preXMPP" : " XMPP1.0", mio_ip(m), jid_full(c->key), errmsg);
			break;
		    case configuration:
		    case feature_lack:
		    case unknown:
			log_warn(c->d->i->id, "received stream error on outgoing%s conn to %s (%s): %s", c->xmpp_version < 0 ? "" : c->xmpp_version == 0 ? " preXMPP" : " XMPP1.0", mio_ip(m), jid_full(c->key), errmsg);
			break;
		    case error:
		    default:
			log_error(c->d->i->id, "received stream error on outgoing%s conn to %s (%s): %s", c->xmpp_version < 0 ? "" : c->xmpp_version == 0 ? " preXMPP" : " XMPP1.0", mio_ip(m), jid_full(c->key), errmsg);
		}
		mio_close(m);
		break;
	    }
	    /* watch for stream:features */
	    if (j_strcmp(xmlnode_get_localname(x), "features") == 0 && j_strcmp(xmlnode_get_namespace(x), NS_STREAM) == 0) {
		xmlnode mechanisms = NULL;

		/* the stream has just restarted after SASL? */
		if (c->connection_state == sasl_success) {
		    mio_reset(m, dialback_out_read_db, (void *)(c->d)); /* different handler now */
		    md = dialback_miod_new(c->d, m); /* set up the mio wrapper */
		    dialback_miod_hash(md, c->d->out_ok_db, c->key); /* this registers us to get stuff directly now */

		    /* send the db:verify packets */
		    dialback_out_send_verifies(m, c);

		    /* flush the queue of packets */
		    dialback_out_qflush(md, c->q);
		    c->q = NULL;

		    /* we are connected, and can trash this now */
		    dialback_out_connection_cleanup(c);

		    break;
		}

		c->connection_state = got_features;
		/* is starttls supported? */
		if (xmlnode_get_list_item(xmlnode_get_tags(x, "tls:starttls", c->d->std_ns_prefixes), 0) != NULL) {
		    /* don't start if forbidden by caller (configuration) */
		    if (j_strcmp(static_cast<char*>(xhash_get_by_domain(c->d->hosts_tls, c->key->server)), "no") == 0) {
			log_notice(c->d->i->id, "Server %s advertized starttls, but disabled by our configuration.", c->key->server);
		    } else if (mio_ssl_starttls_possible(m, c->key->resource)) {
			/* our side is prepared for starttls */
			xmlnode starttls = NULL;

			/* request to start tls on this connection */
			log_debug2(ZONE, LOGT_IO, "requesting starttls for an outgoing connection to %s", c->key->server);

			starttls = xmlnode_new_tag_ns("starttls", NULL, NS_XMPP_TLS);
			mio_write(m, starttls, NULL, 0);
			break;
		    }
		}

		/* is sasl-external supported? */
		mechanisms = xmlnode_get_list_item(xmlnode_get_tags(x, "sasl:mechanisms", c->d->std_ns_prefixes), 0);
		if (mechanisms != NULL) {
		    xmlnode mechanism = NULL;
		    xmlnode auth = NULL;
		    char *base64_source_domain = NULL;
		    size_t base64_source_domain_len = 0;
		    
		    /* check for mechanism EXTERNAL */
		    for (mechanism = xmlnode_get_firstchild(mechanisms); mechanism!=NULL; mechanism = xmlnode_get_nextsibling(mechanism)) {
			if (xmlnode_get_type(mechanism) != NTYPE_TAG)
			    continue;
			if (j_strcasecmp(xmlnode_get_data(mechanism), "EXTERNAL") != 0)
			    continue;

			/* SASL EXTERNAL is supported: use it */
			log_debug2(ZONE, LOGT_IO, "SASL EXTERNAL seems to be supported: %s", xmlnode_serialize_string(mechanisms, xmppd::ns_decl_list(), 0));
			auth = xmlnode_new_tag_ns("auth", NULL, NS_XMPP_SASL);
			xmlnode_put_attrib_ns(auth, "mechanism", NULL, NULL, xmlnode_get_data(mechanism));

			/* add our id as base64 encoded CDATA */
			base64_source_domain_len = (j_strlen(c->key->resource)+2)/3*4+1;
			base64_source_domain = static_cast<char*>(pmalloco(xmlnode_pool(x), base64_source_domain_len));
			base64_encode((unsigned char *)c->key->resource, j_strlen(c->key->resource), base64_source_domain, base64_source_domain_len);
			xmlnode_insert_cdata(auth, base64_source_domain, -1);

			/* send the initial exchange */
			log_debug2(ZONE, LOGT_IO, "trying authentication: %s", xmlnode_serialize_string(auth, xmppd::ns_decl_list(), 0));
			mio_write(m, auth, NULL, 0);

			c->db_state = sent_request;
			c->connection_state = sasl_started;
			break;
		    }

		    /* SASL EXTERNAL found and used */
		    if (mechanism != NULL)
			break;
		}

		/* no stream:feature we'd like to use, now check the settings */
		if (dialback_check_settings(c->d, m, c->key->server, 1, 0, c->xmpp_version) == 0) {
		    c->settings_failed = 1;
		    break;
		}

		/* new connection established, we can now send the outstanding db:result - or we could, if we did not want */
		log_debug2(ZONE, LOGT_IO, "XMPP-stream: we could now send <db:result/>s");
		if (c->db_state == want_request) {
		    /* send the dialback query */
		    cur = xmlnode_new_tag_ns("result", "db", NS_DIALBACK);
		    xmlnode_put_attrib_ns(cur, "to", NULL, NULL, c->key->server);
		    xmlnode_put_attrib_ns(cur, "from", NULL, NULL, c->key->resource);
		    xmlnode_insert_cdata(cur,  dialback_merlin(xmlnode_pool(cur), c->d->secret, c->key->server, c->key->resource, c->stream_id), -1);
		    mio_write(m,cur, NULL, 0);
		    c->db_state = sent_request;
		    c->connection_state = sent_db_request;
		    log_debug2(ZONE, LOGT_IO, "... and we wanted ... and we did sent a <db:result/>");
		} else if (c->db_state == not_requested) {
		    c->db_state = could_request;
		    log_debug2(ZONE, LOGT_IO, "... but we did not want to");
		}

		/* and we can send the verify requests */
		dialback_out_send_verifies(m, c);

		/* finished processing stream:features */
		break;
	    }

	    /* watch for positive starttls result */
	    if (j_strcmp(xmlnode_get_localname(x), "proceed") == 0 && j_strcmp(xmlnode_get_namespace(x), NS_XMPP_TLS) == 0) {
		/* start tls on our side */
		if (mio_xml_starttls(m, 1, c->key->resource)) {
		    /* starting tls failed */
		    log_warn(c->d->i->id, "Starting TLS on an outgoing s2s to %s failed on our side (%s).", c->key->server, c->key->resource);
		    mio_close(m);
		    break;
		}

		/* we forget about the headers we got now again */
		c->connection_state = connected;

		/* send stream header again */
		dialback_out_read(m, MIO_NEW, c, NULL, NULL, 0);

		break;
	    }

	    /* watch for negative starttls result */
	    if (j_strcmp(xmlnode_get_localname(x), "failure") == 0 && j_strcmp(xmlnode_get_namespace(x), NS_XMPP_TLS) == 0) {
		log_warn(c->d->i->id, "Starting TLS on an outgoing s2s to %s failed on the other side.", c->key->server);
		mio_close(m);
		break;
	    }

	    /* watch for SASL success */
	    if (j_strcmp(xmlnode_get_localname(x), "success") == 0 && j_strcmp(xmlnode_get_namespace(x), NS_XMPP_SASL) == 0) {
		log_debug2(ZONE, LOGT_IO, "SASL success response: %s", xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));

		c->connection_state = sasl_success;

		/* reset the stream */
		mio_xml_reset(m);

		/* send stream head again */
		dialback_out_read(m, MIO_NEW, c, NULL, NULL, 0);

		break;
	    }

	    /* watch for SASL failure */
	    if (j_strcmp(xmlnode_get_localname(x), "failure") == 0 && j_strcmp(xmlnode_get_namespace(x), NS_XMPP_SASL) == 0) {
		log_debug2(ZONE, LOGT_IO, "SASL failure response: %s", xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));
		
		/* something went wrong, we were invalid? */
		c->connection_state = sasl_fail;
		if (c->connect_results != NULL) {
		    spool_add(c->connect_results, " (SASL EXTERNAL auth failed: ");
		    spool_add(c->connect_results, xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));
		    spool_add(c->connect_results, ")");
		}
		log_alert(c->d->i->id, "SASL EXTERNAL authentication failed on authenticating ourselfs to %s (sending name: %s)", c->key->server, c->key->resource);
		/* close the stream (in former times we sent a stream error, but I think we shouldn't. There is stream fault by the other entity!) */ 
		mio_write(m, NULL, "</stream:stream>", -1);
		mio_close(m);
		break;
	    }

	    /* watch for a valid result, then we're set to rock! */
	    if(j_strcmp(xmlnode_get_localname(x),"result") == 0 && j_strcmp(xmlnode_get_namespace(x), NS_DIALBACK) == 0) {
		if(j_strcmp(xmlnode_get_attrib_ns(x, "from", NULL), c->key->server) != 0 || j_strcmp(xmlnode_get_attrib_ns(x, "to", NULL),c->key->resource) != 0) {
		    /* naughty... *click* */
		    log_warn(c->d->i->id,"Received illegal dialback validation remote %s != %s or to %s != %s", c->key->server, xmlnode_get_attrib_ns(x, "from", NULL),c->key->resource, xmlnode_get_attrib_ns(x, "to", NULL));
		    mio_write(m, NULL, "<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Invalid Dialback Result</text></stream:error>", -1);
		    mio_close(m);
		    break;
		}

		/* process the returned result */
		if(j_strcmp(xmlnode_get_attrib_ns(x, "type", NULL),"valid") == 0) {
		    c->connection_state = db_succeeded;

		    mio_reset(m, dialback_out_read_db, (void *)(c->d)); /* different handler now */
		    md = dialback_miod_new(c->d, m); /* set up the mio wrapper */
		    dialback_miod_hash(md, c->d->out_ok_db, c->key); /* this registers us to get stuff directly now */

		    /* flush the queue of packets */
		    dialback_out_qflush(md, c->q);
		    c->q = NULL;

		    /* we are connected, and can trash this now */
		    dialback_out_connection_cleanup(c);
		    break;
		}
		/* something went wrong, we were invalid? */
		c->connection_state = db_failed;
		if (c->connect_results != NULL) {
		    char *type_attribute = pstrdup(c->connect_results->p, xmlnode_get_attrib_ns(x, "type", NULL));
		    spool_add(c->connect_results, " (dialback result: ");
		    spool_add(c->connect_results, type_attribute ? type_attribute : "no type attribute");
		    spool_add(c->connect_results, ")");
		}
		log_alert(c->d->i->id,"We were told by %s that our sending name %s is invalid, either something went wrong on their end, we tried using that name improperly, or dns does not resolve to us",c->key->server,c->key->resource);
		/* close the stream (in former times we sent a stream error, but I think we shouldn't. There is stream fault by the other entity!) */ 
		mio_write(m, NULL, "</stream:stream>", -1);
		mio_close(m);
		break;
	    }

	    /* otherwise it's either a verify response, or bust! */
	    if (j_strcmp(xmlnode_get_localname(x), "verify") == 0 && j_strcmp(xmlnode_get_namespace(x), NS_DIALBACK) == 0) {
		dialback_in_verify(c->d, x);
		return;
	    }

	    log_warn(c->d->i->id,"Dropping connection due to illegal incoming packet on an unverified socket from %s to %s (%s): %s",c->key->resource,c->key->server, mio_ip(m), xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));
	    mio_write(m, NULL, "<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Not Allowed to send data on this socket!</text></stream:error>", -1);
	    mio_close(m);
	    break;

	case MIO_CLOSED:
	    /* add the connect error message to the list of messages for the tried hosts */
	    if (c->connect_results != NULL) {
		spool_add(c->connect_results, mio_connect_errmsg(m));
	    }
	    if(c->ip == NULL) {
		dialback_out_connection_cleanup(c); /* buh bye! */
	    } else {
		if (c->connect_results != NULL) {
		    spool_add(c->connect_results, " / ");
		}
		dialback_out_connect(c); /* this one failed, try another */
	    }
	    return;

	default:
	    return;
    }
    xmlnode_free(x);
}

/**
 * callback for walking the connecting hash tree: timing out connections that did not get
 * authorized in time (default is 30 seconds, can be configured with &lt;queuetimeout/&gt; in
 * the configuration file)
 *
 * @param h the hash containing all pending connections
 * @param key destination/source address
 * @param data the dboc
 * @param arg unused/ignored
 */
void _dialback_out_beat_packets(xht h, const char *key, void *data, void *arg) {
    dboc c = (dboc)data;
    dboq cur, next, last;
    int now = time(NULL);
    char *bounce_reason = NULL;

    /* time out individual queue'd packets */
    cur = c->q;
    while (cur != NULL) {
	const char* lang = xmlnode_get_lang(cur->x);

        if ((now - cur->stamp) <= c->d->timeout_packets) {
            last = cur;
            cur = cur->next;
            continue;
        }

        /* timed out sukkah! */
        next = cur->next;
        if(c->q == cur)
            c->q = next;
        else
            last->next = next;

	if (bounce_reason == NULL) {
	    spool errmsg = spool_new(c->p);
	    spool_add(errmsg, messages_get(lang, N_("Server connect timeout while ")));
	    spool_add(errmsg, messages_get(lang, dialback_out_connection_state_string(c->connection_state)));
	    if (c->connect_results != NULL) {
		spool_add(errmsg, ": ");
		spool_add(errmsg, spool_print(c->connect_results));
	    }
	    bounce_reason = spool_print(errmsg);
	}

        deliver_fail(dpacket_new(cur->x), bounce_reason ? bounce_reason : messages_get(lang, N_("Server Connect Timeout")));
        cur = next;
    }
}

/**
 * start walking the connection hash tree, to see if connections dig not get authorizsed in time
 *
 * @param arg the dialback instance
 * @return allways r_DONE
 */
result dialback_out_beat_packets(void *arg) {
    db d = (db)arg;
    xhash_walk(d->out_connecting,_dialback_out_beat_packets,NULL);
    return r_DONE;
}
