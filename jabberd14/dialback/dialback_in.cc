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
 * @file dialback_in.cc
 * @brief handle incoming server to server connections
 *
 * In this file there are the functions used to handle the incoming connections
 * on the server connection manager.
 *
 * After an other server has connected to us, we have to check its identity using
 * dialback. If the check succeeds, we trust the peer, that it is allowed to send
 * messages originating at the checked domain.
 *
 * How dialback works is documented in XMPP core (RFC 3920)
 */

#include "dialback.h"

/* 
On incoming connections, it's our job to validate any packets we receive on this server

We'll get:
    <db:result to=B from=A>...</db:result>
We verify w/ the dialback process, then we'll send back:
    <db:result type="valid" to=A from=B/>

*/

/**
 * remove a incoming connection from the hashtable of all incoming connections
 * waiting to be checked
 *
 * @param arg the connection that should be removed from the hash-table (type is dbic)
 */
void dialback_in_dbic_cleanup(void *arg) {
    dbic c = (dbic)arg;
    if(xhash_get(c->d->in_id,c->id) == c)
        xhash_zap(c->d->in_id,c->id);
}

/**
 * create a new instance of dbic, holding information about an incoming s2s stream
 *
 * @param d the dialback instance
 * @param m the connection of this stream
 * @param we_domain what the other end expects to be our main domain (for STARTTLS)
 * @param other_domain who the other end told to be in its stream root from attribute (if present)
 * @param xmpp_version version of the stream
 * @return the new instance of dbic
 */
static dbic dialback_in_dbic_new(db d, mio m, const char *we_domain, const char *other_domain, int xmpp_version) {
    dbic c;

    c = static_cast<dbic>(pmalloco(m->p, sizeof(_dbic)));
    c->m = m;
    c->id = static_cast<char*>(pstrdup(m->p,dialback_randstr())); /* generate a random id for this incoming stream */
    c->results = xmlnode_new_tag_pool_ns(m->p, "r", NULL, NS_JABBERD_WRAPPER); /* wrapper element, we add the db:result elements inside this one */
    c->d = d;
    c->we_domain = pstrdup(m->p, we_domain);
    c->other_domain = pstrdup(m->p, other_domain);
    c->xmpp_version = xmpp_version;
    time(&c->stamp);
    pool_cleanup(m->p,dialback_in_dbic_cleanup, (void *)c); /* remove us automatically if our memory pool is freed */
    xhash_put(d->in_id, c->id, (void *)c); /* insert ourself in the hash of not yet verified connections */
    log_debug2(ZONE, LOGT_IO, "created incoming connection %s from %s",c->id, mio_ip(m));
    return c;
}

/**
 * callback for mio for accepted sockets that are dialback
 *
 * - We check if the other host wants to switch to using TLS.
 * - We check if the other host wants to verify a dialback connection we made to them
 * - We accept db:result element, where the peer wants to authenticate to use a domain
 * - We accept stanzas send from a sender the peer has been authorized to use
 * - Else we generate a stream:error
 *
 * @param m the connection on which the stanza has been read
 * @param flags the mio action, should always be MIO_XML_NODE, other actions are ignored
 * @param arg the dbic instance of the stream on which the stanza has been read
 * @param x the stanza that has been read
 * @param unused1 unused/ignored
 * @param unused2 unused/ignored
 */
void dialback_in_read_db(mio m, int flags, void *arg, xmlnode x, char* unused1, int unused2) {
    dbic c = (dbic)arg;
    miod md;
    jid key, from;
    xmlnode x2;

    if(flags != MIO_XML_NODE) return;

    log_debug2(ZONE, LOGT_IO, "dbin read dialback: fd %d packet %s",m->fd, xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));

    /* incoming stream error? */
    if (j_strcmp(xmlnode_get_localname(x), "error") == 0 && j_strcmp(xmlnode_get_namespace(x), NS_STREAM) == 0) {
        spool s = spool_new(x->p);
        streamerr errstruct = static_cast<streamerr>(pmalloco(x->p, sizeof(_streamerr)));
        char *errmsg = NULL;

        xstream_parse_error(x->p, x, errstruct);
        xstream_format_error(s, errstruct);
        errmsg = spool_print(s);

        switch (errstruct->severity) {
            case normal:
                log_debug2(ZONE, LOGT_IO, "stream error on incoming db conn from %s: %s", mio_ip(m), errmsg);
                break;
            case configuration:
            case feature_lack:
            case unknown:
                log_warn(c->d->i->id, "received stream error on incoming db conn from %s: %s", mio_ip(m), errmsg);
                break;
            case error:
            default:
                log_error(c->d->i->id, "received stream error on incoming db conn from %s: %s", mio_ip(m), errmsg);
        }
	mio_close(m);
	return;
    }

    /* incoming starttls */
    if (j_strcmp(xmlnode_get_localname(x), "starttls") == 0 && j_strcmp(xmlnode_get_namespace(x), NS_XMPP_TLS) == 0) {
	/* starting TLS possible? */
	if (mio_ssl_starttls_possible(m, c->we_domain) && j_strcmp(static_cast<char*>(xhash_get_by_domain(c->d->hosts_tls, c->other_domain)), "no")!=0) {
	    /* ACK the start */
	    xmlnode proceed = xmlnode_new_tag_ns("proceed", NULL, NS_XMPP_TLS);
	    mio_write(m, proceed, NULL, 0);

	    /* start TLS on this connection */
	    if (mio_xml_starttls(m, 0, c->we_domain) != 0) {
		/* STARTTLS failed */
		mio_close(m);
		return;
	    }

	    /* we get a stream header again */
	    mio_reset(m, dialback_in_read, (void *)c->d);
	    
	    return;
	} else {
	    /* NACK */
	    mio_write(m, NULL, "<failure xmlns='" NS_XMPP_TLS "'/></stream:stream>", -1);
	    mio_close(m);
	    xmlnode_free(x);
	    return;
	}
    }
    
    /* incoming SASL */
    if (j_strcmp(xmlnode_get_localname(x), "auth") == 0 && j_strcmp(xmlnode_get_namespace(x), NS_XMPP_SASL) == 0) {
	const char *initial_exchange = xmlnode_get_data(x);
	char *decoded_initial_exchange = NULL;
	jid other_side_jid = NULL;

	log_debug2(ZONE, LOGT_IO, "incoming SASL: %s", xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));

	/* check that the peer is allowed to authenticate using SASL */
	if (j_strcmp(static_cast<char*>(xhash_get_by_domain(c->d->hosts_auth, c->other_domain)), "db") == 0) {
	    mio_write(m, NULL, "<failure xmlns='" NS_XMPP_SASL "'><invalid-mechanism/></failure><stream:error><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xml:lang='en' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>This server is configured to not accept SASL auth from your host!</text></stream:error></stream:stream>", -1);
	    mio_close(m);
	    xmlnode_free(x);
	    return;
	}

	/* check that the other end is requesting the EXTERNAL mechanism */
	if (j_strcasecmp(xmlnode_get_attrib_ns(x, "mechanism", NULL), "EXTERNAL") != 0) {
	    /* unsupported mechanism */
	    mio_write(m, NULL, "<failure xmlns='" NS_XMPP_SASL "'><invalid-mechanism/></failure></stream:stream>", -1);
	    mio_close(m);
	    xmlnode_free(x);
	    return;
	}

	/* XXX: empty initial exchange? send empty challenge */
	if (initial_exchange == NULL) {
	    /*
	    mio_write(m, NULL, "<challenge xmlns='" NS_XMPP_SASL "'>=</challenge>", -1);
	    */
	    mio_write(m, NULL, "<failure xmlns='" NS_XMPP_SASL "'><not-authorized/></failure></stream:stream>", -1);
	    mio_close(m);
	    xmlnode_free(x);
	    return;
	}

	/* decode initial exchange */
	decoded_initial_exchange = static_cast<char*>(pmalloco(x->p, (j_strlen(initial_exchange)+3)/4*3+1));
	base64_decode(initial_exchange, (unsigned char *)decoded_initial_exchange, (j_strlen(initial_exchange)+3)/4*3+1);
	other_side_jid = jid_new(x->p, decoded_initial_exchange);

	/* we only accept servers, no users */
	if (!other_side_jid || other_side_jid->user || other_side_jid->resource) {
	    mio_write(m, NULL, "<failure xmlns='" NS_XMPP_SASL "'><invalid-authzid/></failure></stream:stream>", -1);
	    mio_close(m);
	    xmlnode_free(x);
	    return;
	}

	/* check if the other host is who it supposes to be */
	if (!mio_ssl_verify(m, jid_full(other_side_jid))) {
	    mio_write(m, NULL, "<failure xmlns='" NS_XMPP_SASL "'><not-authorized/></failure></stream:stream>", -1);
	    mio_close(m);
	    xmlnode_free(x);
	    return;
	}

	/* check the security settings */
	if (!dialback_check_settings(c->d, c->m, other_side_jid->server, 0, 1, c->xmpp_version)) {
	    mio_write(m, NULL, "<failure xmlns='" NS_XMPP_SASL "'><mechanism-too-weak/></failure></stream:stream>", -1);
	    mio_close(m);
	    xmlnode_free(x);
	    return;
	}
	
	/* authorization was successfull! */
	mio_write(m, NULL, "<success xmlns='" NS_XMPP_SASL "'/>", -1);

	/* reset the stream */
	m->authed_other_side = pstrdup(m->p, jid_full(other_side_jid));
	mio_xml_reset(m);
	mio_reset(m, dialback_in_read, (void *)c->d);

	xmlnode_free(x);
	return;
    }

    /* incoming verification request, check and respond */
    if(j_strcmp(xmlnode_get_localname(x),"verify") == 0 && j_strcmp(xmlnode_get_namespace(x), NS_DIALBACK) == 0) {
	char *is = xmlnode_get_data(x);		/* what the peer tries to verify */
	char *should = dialback_merlin(xmlnode_pool(x), c->d->secret, xmlnode_get_attrib_ns(x, "from", NULL), xmlnode_get_attrib_ns(x, "to", NULL), xmlnode_get_attrib_ns(x, "id", NULL));

        if(j_strcmp(is, should) == 0) {
            xmlnode_put_attrib_ns(x, "type", NULL, NULL, "valid");
	} else {
            xmlnode_put_attrib_ns(x, "type", NULL, NULL, "invalid");
	    log_notice(c->d->i->id, "Is somebody faking us? %s tried to verify the invalid dialback key %s (should be %s)", xmlnode_get_attrib_ns(x, "from", NULL), is, should);
	}

        /* reformat the packet reply */
        jutil_tofrom(x);
        while((x2 = xmlnode_get_firstchild(x)) != NULL)
            xmlnode_hide(x2); /* hide the contents */
        mio_write(m, x, NULL, 0);
        return;
    }

    /* valid sender/recipient jids */
    if ((from = jid_new(xmlnode_pool(x), xmlnode_get_attrib_ns(x, "from", NULL))) == NULL || (key = jid_new(xmlnode_pool(x), xmlnode_get_attrib_ns(x, "to", NULL))) == NULL) {
        mio_write(m, NULL, "<stream:error><improper-addressing xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xml:lang='en' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>Invalid Packets Recieved!</text></stream:error>", -1);
        mio_close(m);
        xmlnode_free(x);
        return;
    }

    /* make our special key */
    jid_set(key,from->server,JID_RESOURCE);
    jid_set(key,c->id,JID_USER); /* special user of the id attrib makes this key unique */

    /* incoming result, track it and forward on */
    if(j_strcmp(xmlnode_get_localname(x),"result") == 0 && j_strcmp(xmlnode_get_namespace(x), NS_DIALBACK) == 0) {
        /* store the result in the connection, for later validation */
        xmlnode_put_attrib_ns(xmlnode_insert_tag_node(c->results, x), "key", NULL, NULL, jid_full(key));

        /* send the verify back to them, on another outgoing trusted socket, via deliver (so it is real and goes through dnsrv and anything else) */
        x2 = xmlnode_new_tag_pool_ns(xmlnode_pool(x), "verify", "db", NS_DIALBACK);
        xmlnode_put_attrib_ns(x2, "to", NULL, NULL, xmlnode_get_attrib_ns(x, "from", NULL));
        xmlnode_put_attrib_ns(x2, "ofrom", NULL, NULL, xmlnode_get_attrib_ns(x, "to", NULL));
        xmlnode_put_attrib_ns(x2, "from", NULL, NULL, c->d->i->id); /* so bounces come back to us to get tracked */
	xmlnode_put_attrib_ns(x2, "dnsqueryby", NULL, NULL, c->d->i->id); /* so this instance gets the DNS result back */
        xmlnode_put_attrib_ns(x2, "id", NULL, NULL, c->id);
        xmlnode_insert_node(x2, xmlnode_get_firstchild(x)); /* copy in any children */
        deliver(dpacket_new(x2), c->d->i);

        return;
    }

    /* hmm, incoming packet on dialback line, there better be a valid entry for it or else! */
    md = static_cast<miod>(xhash_get(c->d->in_ok_db, jid_full(key)));
    if(md == NULL || md->m != m)
    { /* dude, what's your problem!  *click* */
	log_notice(c->d->i->id, "Received unauthorized stanza for/from %s: %s", jid_full(key), xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));

        mio_write(m, NULL, "<stream:error><invalid-from xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xml:lang='en' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>Invalid Packets Recieved!</text></stream:error>", -1);
        mio_close(m);
        xmlnode_free(x);
        return;
    }

    dialback_miod_read(md, x);
}


/**
 * callback for mio for accepted sockets
 *
 * Our task is:
 * - Verify the stream root element
 * - Check the type of server-to-server stream (we support: dialback, xmpp+dialback)
 * - For xmpp+dialback: send stream:features (we support: starttls)
 * - Reset the mio callback. Stanzas are handled by dialback_in_read_db()
 *
 * @param m the connection on which the stream root element has been received
 * @param flags the mio action, everything but MIO_XML_ROOT is ignored
 * @param arg the db instance
 * @param x the stream root element
 * @param unused1 unused/ignored
 * @param unused2 unused/ignored
 */
void dialback_in_read(mio m, int flags, void *arg, xmlnode x, char* unused1, int unused2) {
    db d = (db)arg;
    xmlnode x2;
    miod md;
    char strid[10];
    dbic c = NULL;
    int version = 0;
    int dbns_defined = 0;
    int can_offer_starttls = 0;
    int can_do_sasl_external = 0;
    const char *we_domain = NULL;
    const char *other_domain = NULL;
    const char *loopcheck = NULL;

    log_debug2(ZONE, LOGT_IO, "dbin read: fd %d flag %d", m->fd, flags);

    if(flags != MIO_XML_ROOT)
        return;

    snprintf(strid, sizeof(strid), "%X", m); /* for hashes for later */

    /* check stream version and possible features */
    version = j_atoi(xmlnode_get_attrib_ns(x, "version", NULL), 0);
    try {
	m->in_root->get_nsprefix(NS_DIALBACK);
	dbns_defined = 1;
    } catch (std::invalid_argument) {
    }
    we_domain = xmlnode_get_attrib_ns(x, "to", NULL);
    other_domain = m->authed_other_side ? m->authed_other_side : xmlnode_get_attrib_ns(x, "from", NULL);
    can_offer_starttls = m->authed_other_side==NULL && mio_ssl_starttls_possible(m, we_domain) ? 1 : 0;
    can_do_sasl_external = m->authed_other_side==NULL && (mio_is_encrypted(m) > 0 && mio_ssl_verify(m, other_domain)) ? 1 : 0;

    /* disable by configuration */
    if (j_strcmp(static_cast<char*>(xhash_get_by_domain(d->hosts_tls, other_domain)), "no") == 0)
	can_offer_starttls = 0;
    if (j_strcmp(static_cast<char*>(xhash_get_by_domain(d->hosts_auth, other_domain)), "db") == 0)
	can_do_sasl_external = 0;
    if (j_strcmp(static_cast<char*>(xhash_get_by_domain(d->hosts_xmpp, other_domain)), "no") == 0)
	version = 0;
    else if (j_strcmp(static_cast<char*>(xhash_get_by_domain(d->hosts_xmpp, other_domain)), "force") == 0 && version == 0) {
	jid key = NULL;

        key = jid_new(xmlnode_pool(x), we_domain);
	mio_write_root(m, xstream_header(other_domain, jid_full(key)), 0);
        mio_write(m, NULL, "<stream:error><unsupported-version xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xml:lang='en' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>We are configured to not support pre-XMPP 1.0 connections.</text></stream:error>", -1);
        mio_close(m);
        xmlnode_free(x);
        return;
    }

    log_debug2(ZONE, LOGT_IO, "outgoing conn: can_offer_starttls=%i, can_do_sasl_external=%i", can_offer_starttls, can_do_sasl_external);

    /* validate namespace */
    /*
    if (xmlnode_list_get_nsprefix(m->in_last_ns_root, NS_SERVER) == NULL) {
	jid key = NULL;
        key = jid_new(xmlnode_pool(x), we_domain);
	mio_write_root(m, xstream_header(other_domain, jid_full(key)), 0);
	/ * XXX now that we have namespace handling - shouldn't we generate another error? do we need to check this at all? * /
        mio_write(m, NULL, "<stream:error><bad-namespace-prefix xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xml:lang='en' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>Sorry, but the namespace '" NS_SERVER "' has to be defined on the stream root.</text></stream:error>", -1);
        mio_close(m);
        xmlnode_free(x);
        return;
    }
    */

    /* deprecated non-dialback protocol, reject connection */
    if(version < 1 && !dbns_defined) {
	jid key = NULL;
        key = jid_new(xmlnode_pool(x), we_domain);
	mio_write_root(m, xstream_header(other_domain, jid_full(key)), 0);
        mio_write(m, NULL, "<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xml:lang='en' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>Legacy Access Denied!</text></stream:error>", -1);
        mio_close(m);
        xmlnode_free(x);
        return;
    }

    /* no support for dialback and we won't be able to offer SASL to this host? */
    if (!dbns_defined && !can_do_sasl_external && m->authed_other_side==NULL) {
	jid key = NULL;
        key = jid_new(xmlnode_pool(x), we_domain);
	mio_write_root(m, xstream_header(other_domain, jid_full(key)), 0);
	mio_write(m, NULL, "<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xml:lang='en' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>It seems you do not support dialback, and we cannot validate your TLS certificate. No authentication is possible. We are sorry.</text></stream:error>", -1);
	mio_close(m);
	xmlnode_free(x);
	return;
    }

    /* are we connecting to ourselves? */
    loopcheck = xmlnode_get_attrib_ns(x, "check", NS_JABBERD_LOOPCHECK);
    if (loopcheck != NULL && j_strcmp(loopcheck, dialback_get_loopcheck_token(d)) == 0) {
	jid key = NULL;
        key = jid_new(xmlnode_pool(x), we_domain);
	mio_write_root(m, xstream_header(other_domain, jid_full(key)), 0);
	mio_write(m, NULL, "<stream:error><remote-connection-failed xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xml:lang='en' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>Server connected to itself. Probably caused by a DNS misconfiguration, or a domain not used for Jabber/XMPP communications.</text></stream:error>", -1);
	mio_close(m);
	xmlnode_free(x);
	return;
    }

    /* dialback connection */
    c = dialback_in_dbic_new(d, m, we_domain, other_domain, version);

    /* restarted after SASL? authorize the connection */
    if (m->authed_other_side) {
	jid key = NULL;

	key = jid_new(xmlnode_pool(x),c->we_domain);
	jid_set(key, m->authed_other_side, JID_RESOURCE);
	jid_set(key, c->id, JID_USER); /* special user of the id attrib makes this key unique */
	dialback_miod_hash(dialback_miod_new(c->d, c->m), c->d->in_ok_db, key);
    }

    /* write our header */
    x2 = xstream_header(c->other_domain, c->we_domain);
    if (j_strcmp(static_cast<char*>(xhash_get_by_domain(c->d->hosts_auth, c->other_domain)), "sasl") != 0)
	xmlnode_put_attrib_ns(x2, "db", "xmlns", NS_XMLNS, NS_DIALBACK); /* flag ourselves as dialback capable */
    if (c->xmpp_version >= 1) {
	xmlnode_put_attrib_ns(x2, "version", NULL, NULL, "1.0");	/* flag us as XMPP capable */
    }
    xmlnode_put_attrib_ns(x2, "id", NULL, NULL, c->id); /* send random id as a challenge */
    mio_write_root(m, x2, 0);
    xmlnode_free(x);

    /* reset to a dialback packet reader */
    mio_reset(m, dialback_in_read_db, (void *)c);

    /* write stream features */
    if (c->xmpp_version >= 1) {
	xmlnode features = xmlnode_new_tag_ns("features", "stream", NS_STREAM);
	if (can_offer_starttls) {
	    xmlnode starttls = NULL;

	    starttls = xmlnode_insert_tag_ns(features, "starttls", NULL, NS_XMPP_TLS);
	}
	if (can_do_sasl_external) {
	    xmlnode mechanisms = NULL;
	    xmlnode mechanism = NULL;

	    mechanisms = xmlnode_insert_tag_ns(features, "mechanisms", NULL, NS_XMPP_SASL);
	    mechanism = xmlnode_insert_tag_ns(mechanisms, "mechanism", NULL, NS_XMPP_SASL);
	    xmlnode_insert_cdata(mechanism, "EXTERNAL", -1);
	}
	log_debug2(ZONE, LOGT_IO, "sending stream features: %s", xmlnode_serialize_string(features, xmppd::ns_decl_list(), 0));
	mio_write(m, features, NULL, 0);
    }
}

/**
 * Handle db:verify packets, that we got as a result to our dialback to the authoritive server.
 *
 * We expect the to attribute to be our name and the from attribute to be the remote name.
 *
 * We have to do:
 * - Check if there is (still) a connection for this dialback result
 * - If the we got type='valid' we have to authorize the peer to use the verified sender address
 * - Inform the peer about the result
 *
 * @note dialback_out_connection_cleanup() calls this function as well to trash pending verifies.
 * In that case we don't get the db:verify result, but the db:verify query (no type attribute set).
 *
 * @param d the db instance
 * @param x the db:verify answer packet
 */
void dialback_in_verify(db d, xmlnode x) {
    dbic c;
    xmlnode x2;
    jid key;
    const char *type = NULL;

    log_debug2(ZONE, LOGT_AUTH, "dbin validate: %s",xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));

    /* check for the stored incoming connection first */
    if ((c = static_cast<dbic>(xhash_get(d->in_id, xmlnode_get_attrib_ns(x, "id", NULL)))) == NULL) {
	log_warn(d->i->id, "Dropping a db:verify answer, we don't have a waiting incoming connection (anymore?) for this id: %s", xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));
        xmlnode_free(x);
        return;
    }

    /* make a key of the sender/recipient addresses on the packet */
    key = jid_new(xmlnode_pool(x),xmlnode_get_attrib_ns(x, "to", NULL));
    jid_set(key, xmlnode_get_attrib_ns(x, "from", NULL),JID_RESOURCE);
    jid_set(key, c->id, JID_USER); /* special user of the id attrib makes this key unique */

    x2 = xmlnode_get_list_item(xmlnode_get_tags(c->results, spools(xmlnode_pool(x), "*[@key='", jid_full(key), "']", xmlnode_pool(x)), d->std_ns_prefixes), 0);
    if (x2 == NULL) {
	log_warn(d->i->id, "Dropping a db:verify answer, we don't have a waiting incoming <db:result/> query (anymore?) for this to/from pair: %s", xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));
        xmlnode_free(x);
        return;
    }

    /* hide the waiting db:result, it has been processed now */
    xmlnode_hide(x2);

    /* get type of db:verify result */
    type = xmlnode_get_attrib_ns(x, "type", NULL);

    /* rewrite the result */
    x2 = xmlnode_new_tag_pool_ns(xmlnode_pool(x),"result", "db", NS_DIALBACK);
    xmlnode_put_attrib_ns(x2, "to", NULL, NULL, xmlnode_get_attrib_ns(x, "from", NULL));
    xmlnode_put_attrib_ns(x2, "from", NULL, NULL, xmlnode_get_attrib_ns(x, "to", NULL));
    xmlnode_put_attrib_ns(x2, "type", NULL, NULL, type != NULL ? type : "invalid");

    /* valid requests get the honour of being miod */
    type = xmlnode_get_attrib_ns(x, "type", NULL);
    if (j_strcmp(type, "valid") == 0) {
	/* check the security settings for this connection */
	if (!dialback_check_settings(c->d, c->m, xmlnode_get_attrib_ns(x, "from", NULL), 0, 0, c->xmpp_version)) {
	    return;
	}

	/* accept incoming stanzas on this connection */
        dialback_miod_hash(dialback_miod_new(c->d, c->m), c->d->in_ok_db, key);
    } else
	log_warn(d->i->id, "Denying peer to use the domain %s. Dialback failed (%s): %s", key->resource, type ? type : "timeout", xmlnode_serialize_string(x2, xmppd::ns_decl_list(), 0));

    /* rewrite and send on to the socket */
    mio_write(c->m, x2, NULL, -1);
}
