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

/**
 * @file dialback_in.c
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
 * incoming dialback streams
 */
typedef struct dbic_struct
{
    mio m;		/**< the connection of the incoming stream */
    char *id;		/**< random id we assigned to this stream */
    xmlnode results;	/**< db:result elements that we received and
			  that are not yet fully processed (just doing
			  dialback on them). We add an additional
			  attribute "key" to the element:
			  "streamid@ourdomain/peersdomain" */
    db d;		/**< the dialback instance */
    char *we_domain;	/**< who the other end expects us to be
			  (to attribute of stream head) for selecting
			  a certificate at STARTTLS */
} *dbic, _dbic;

/**
 * remove a incoming connection from the hashtable of all incoming connections
 * waiting to be checked
 *
 * @param arg the connection that should be removed from the hash-table (type is dbic)
 */
void dialback_in_dbic_cleanup(void *arg)
{
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
 * @return the new instance of dbic
 */
dbic dialback_in_dbic_new(db d, mio m, const char *we_domain)
{
    dbic c;

    c = pmalloco(m->p, sizeof(_dbic));
    c->m = m;
    c->id = pstrdup(m->p,dialback_randstr()); /* generate a random id for this incoming stream */
    c->results = xmlnode_new_tag_pool(m->p,"r"); /* wrapper element, we add the db:result elements inside this one */
    c->d = d;
    c->we_domain = pstrdup(m->p, we_domain);
    pool_cleanup(m->p,dialback_in_dbic_cleanup, (void *)c); /* remove us automatically if our memory pool is freed */
    xhash_put(d->in_id, c->id, (void *)c); /* insert ourself in the hash of not yet verified connections */
    log_debug2(ZONE, LOGT_IO, "created incoming connection %s from %s",c->id,m->ip);
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
 */
void dialback_in_read_db(mio m, int flags, void *arg, xmlnode x)
{
    dbic c = (dbic)arg;
    miod md;
    jid key, from;
    xmlnode x2;

    if(flags != MIO_XML_NODE) return;

    log_debug2(ZONE, LOGT_IO, "dbin read dialback: fd %d packet %s",m->fd, xmlnode2str(x));

    /* incoming starttls */
    if (j_strcmp(xmlnode_get_name(x), "starttls") == 0 && j_strcmp(xmlnode_get_attrib(x, "xmlns"), NS_XMPP_TLS) == 0) {
	/* starting TLS possible? */
	if (mio_ssl_starttls_possible(m, c->we_domain)) {
	    /* ACK the start */
	    xmlnode proceed = xmlnode_new_tag("proceed");
	    xmlnode_put_attrib(proceed, "xmlns", NS_XMPP_TLS);
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

    /* incoming verification request, check and respond */
    if(j_strcmp(xmlnode_get_name(x),"db:verify") == 0)
    {
	char *is = xmlnode_get_data(x);		/* what the peer tries to verify */
	char *should = dialback_merlin(xmlnode_pool(x), c->d->secret, xmlnode_get_attrib(x,"from"), xmlnode_get_attrib(x,"id"));

        if(j_strcmp(is, should) == 0) {
            xmlnode_put_attrib(x,"type","valid");
	} else {
            xmlnode_put_attrib(x,"type","invalid");
	    log_notice(c->d->i->id, "Is somebody faking us? %s tried to verify the invalid dialback key %s (should be %s)", xmlnode_get_attrib(x, "from"), is, should);
	}

        /* reformat the packet reply */
        jutil_tofrom(x);
        while((x2 = xmlnode_get_firstchild(x)) != NULL)
            xmlnode_hide(x2); /* hide the contents */
        mio_write(m, x, NULL, 0);
        return;
    }

    /* valid sender/recipient jids */
    if((from = jid_new(xmlnode_pool(x),xmlnode_get_attrib(x,"from"))) == NULL || (key = jid_new(xmlnode_pool(x),xmlnode_get_attrib(x,"to"))) == NULL)
    {
        mio_write(m, NULL, "<stream:error><improper-addressing xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xml:lang='en' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>Invalid Packets Recieved!</text></stream:error>", -1);
        mio_close(m);
        xmlnode_free(x);
        return;
    }

    /* make our special key */
    jid_set(key,from->server,JID_RESOURCE);
    jid_set(key,c->id,JID_USER); /* special user of the id attrib makes this key unique */

    /* incoming result, track it and forward on */
    if(j_strcmp(xmlnode_get_name(x),"db:result") == 0)
    {
        /* store the result in the connection, for later validation */
        xmlnode_put_attrib(xmlnode_insert_tag_node(c->results, x),"key",jid_full(key));

        /* send the verify back to them, on another outgoing trusted socket, via deliver (so it is real and goes through dnsrv and anything else) */
        x2 = xmlnode_new_tag_pool(xmlnode_pool(x),"db:verify");
        xmlnode_put_attrib(x2,"to",xmlnode_get_attrib(x,"from"));
        xmlnode_put_attrib(x2,"ofrom",xmlnode_get_attrib(x,"to"));
        xmlnode_put_attrib(x2,"from",c->d->i->id); /* so bounces come back to us to get tracked */
	xmlnode_put_attrib(x2,"dnsqueryby",c->d->i->id); /* so this instance gets the DNS result back */
        xmlnode_put_attrib(x2,"id",c->id);
        xmlnode_insert_node(x2,xmlnode_get_firstchild(x)); /* copy in any children */
        deliver(dpacket_new(x2),c->d->i);

        return;
    }

    /* hmm, incoming packet on dialback line, there better be a valid entry for it or else! */
    md = xhash_get(c->d->in_ok_db, jid_full(key));
    if(md == NULL || md->m != m)
    { /* dude, what's your problem!  *click* */
	log_notice(c->d->i->id, "Received unauthorized stanza for/from %s: %s", jid_full(key), xmlnode2str(x));

        mio_write(m, NULL, "<stream:error><invalid-from xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xml:lang='en' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>Invalid Packets Recieved!</text></stream:error>", -1);
        mio_close(m);
        xmlnode_free(x);
        return;
    }

    dialback_miod_read(md, x);
}


/**
 * callback for mio for accepted sockets that are legacy
 *
 * We just accept all stanzas for legacy connections. :-(
 * Hopefully the administrator did not enable this connection type.
 *
 * @param m the connection
 * @param flags mio action, we ignore anything but MIO_XML_NODE
 * @param arg the miod structure
 * @param x the received stanza
 */
void dialback_in_read_legacy(mio s, int flags, void *arg, xmlnode x)
{
    miod md = (miod)arg;

    if(flags != MIO_XML_NODE) return;

    dialback_miod_read(md, x);
}

/**
 * callback for mio for accepted sockets
 *
 * Our task is:
 * - Verify the stream root element
 * - Check the type of server-to-server stream (we support: legacy, dialback, xmpp+dialback)
 * - For legacy streams: Check if we want to allow them
 * - For xmpp+dialback: send stream:features (we support: starttls)
 * - Reset the mio callback. Stanzas are handled by dialback_in_read_legacy() or dialback_in_read_db()
 *
 * @param m the connection on which the stream root element has been received
 * @param the mio action, everything but MIO_XML_ROOT is ignored
 * @param arg the db instance
 * @param x the stream root element
 */
void dialback_in_read(mio m, int flags, void *arg, xmlnode x)
{
    db d = (db)arg;
    xmlnode x2;
    miod md;
    jid key;
    char strid[10];
    dbic c;
    int version = 0;
    const char *dbns = NULL;

    log_debug2(ZONE, LOGT_IO, "dbin read: fd %d flag %d",m->fd, flags);

    if(flags != MIO_XML_ROOT)
        return;

    /* validate namespace */
    if(j_strcmp(xmlnode_get_attrib(x,"xmlns"),"jabber:server") != 0)
    {
        mio_write(m, NULL, "<stream:stream><stream:error><bad-namespace-prefix xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xml:lang='en' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>Invalid Stream Header!</text></stream:error>", -1);
        mio_close(m);
        xmlnode_free(x);
        return;
    }

    snprintf(strid, 9, "%X", m); /* for hashes for later */

    /* check stream version */
    version = j_atoi(xmlnode_get_attrib(x, "version"), 0);
    dbns = xmlnode_get_attrib(x, "xmlns:db");

    /* legacy, icky */
    if(version < 1 && dbns == NULL)
    {
        key = jid_new(xmlnode_pool(x), xmlnode_get_attrib(x, "to"));
        mio_write(m,NULL, xstream_header_char(xstream_header("jabber:server", NULL, jid_full(key))), -1);
        if(d->legacy && key != NULL)
        {
            log_notice(d->i->id,"legacy server incoming connection to %s established from %s",key->server, m->ip);
            md = dialback_miod_new(d, m);
            jid_set(key,strid,JID_USER);
            dialback_miod_hash(md, d->in_ok_legacy, jid_user(key)); /* register 5A55BD@toname for tracking in the hash */
            mio_reset(m, dialback_in_read_legacy, (void *)md); /* set up legacy handler for all further packets */
            xmlnode_free(x);
            return;
        }
        mio_write(m, NULL, "<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xml:lang='en' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>Legacy Access Denied!</text></stream:error>", -1);
        mio_close(m);
        xmlnode_free(x);
        return;
    }

    /* peer is XMPP server but does not support dialback (probably it implements only SASL) */
    if (dbns == NULL) {
	mio_write(m, NULL, "<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xml:lang='en' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>Sorry, we only support dialback to 'authenticate' our peers. SASL is not supported by us. You need to support dialback to communicate with this host.</text></stream:error>", -1);
	mio_close(m);
	xmlnode_free(x);
	return;
    }

    /* check namespaces */
    if (j_strcmp(dbns, NS_DIALBACK) != 0) {
	mio_write(m, NULL, "<stream:error><invalid-namespace xmlns='urn:ietf:params:xml:ns:xmpp-streams'><text xml:lang='en' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>Sorry, but don't you think, that xmlns:db should declare the namespace jabber:server:dialback?</text></stream:error>", -1);
	mio_close(m);
	xmlnode_free(x);
	return;
    }

    /* dialback connection */
    c = dialback_in_dbic_new(d, m, xmlnode_get_attrib(x, "to"));

    /* write our header */
    x2 = xstream_header(NS_SERVER, NULL, c->we_domain);
    xmlnode_put_attrib(x2, "xmlns:db", NS_DIALBACK); /* flag ourselves as dialback capable */
    if (version >= 1) {
	xmlnode_put_attrib(x2, "version", "1.0");	/* flag us as XMPP capable */
    }
    xmlnode_put_attrib(x2,"id",c->id); /* send random id as a challenge */
    mio_write(m,NULL, xstream_header_char(x2), -1);
    xmlnode_free(x2);
    xmlnode_free(x);

    /* reset to a dialback packet reader */
    mio_reset(m, dialback_in_read_db, (void *)c);

    /* write stream features */
    if (version >= 1) {
	xmlnode features = xmlnode_new_tag("stream:features");
	if (mio_ssl_starttls_possible(m, c->we_domain)) {
	    xmlnode starttls = NULL;

	    starttls = xmlnode_insert_tag(features, "starttls");
	    xmlnode_put_attrib(starttls, "xmlns", NS_XMPP_TLS);
	}
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
void dialback_in_verify(db d, xmlnode x)
{
    dbic c;
    xmlnode x2;
    jid key;
    const char *type = NULL;

    log_debug2(ZONE, LOGT_AUTH, "dbin validate: %s",xmlnode2str(x));

    /* check for the stored incoming connection first */
    if((c = xhash_get(d->in_id, xmlnode_get_attrib(x,"id"))) == NULL)
    {
	log_warn(d->i->id, "Dropping a db:verify answer, we don't have a waiting incoming connection (anymore?) for this id: %s", xmlnode2str(x));
        xmlnode_free(x);
        return;
    }

    /* make a key of the sender/recipient addresses on the packet */
    key = jid_new(xmlnode_pool(x),xmlnode_get_attrib(x,"to"));
    jid_set(key,xmlnode_get_attrib(x,"from"),JID_RESOURCE);
    jid_set(key,c->id,JID_USER); /* special user of the id attrib makes this key unique */

    if((x2 = xmlnode_get_tag(c->results, spools(xmlnode_pool(x),"?key=",jid_full(key),xmlnode_pool(x)))) == NULL)
    {
	log_warn(d->i->id, "Dropping a db:verify answer, we don't have a waiting incoming <db:result/> query (anymore?) for this to/from pair: %s", xmlnode2str(x));
        xmlnode_free(x);
        return;
    }

    /* hide the waiting db:result, it has been processed now */
    xmlnode_hide(x2);

    /* get type of db:verify result */
    type = xmlnode_get_attrib(x, "type");

    /* rewrite the result */
    x2 = xmlnode_new_tag_pool(xmlnode_pool(x),"db:result");
    xmlnode_put_attrib(x2,"to",xmlnode_get_attrib(x,"from"));
    xmlnode_put_attrib(x2,"from",xmlnode_get_attrib(x,"to"));
    xmlnode_put_attrib(x2,"type", type != NULL ? type : "invalid");

    /* valid requests get the honour of being miod */
    type = xmlnode_get_attrib(x, "type");
    if(j_strcmp(type,"valid") == 0)
        dialback_miod_hash(dialback_miod_new(c->d, c->m), c->d->in_ok_db, key);
    else
	log_warn(d->i->id, "Denying peer to use the domain %s. Dialback failed (%s): %s", key->resource, type ? type : "timeout", xmlnode2str(x2));

    /* rewrite and send on to the socket */
    mio_write(c->m, x2, NULL, -1);
}
