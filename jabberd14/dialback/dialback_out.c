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

#include "dialback.h"

/* 
On outgoing connections, we need to send a result and any verifies, and watch for their responses 

We'll send:
    <db:result to=B from=A>...</db:result>
We'll get back:
    <db:result type="valid" to=A from=B/>

We'll send:
    <db:verify to=B from=A id=asdf>...</db:verify>
We'll get back:
    <db:verify type="valid" to=A from=B id=asdf/>

*/

/* simple queue for out_queue */
typedef struct dboq_struct
{
    int stamp;
    xmlnode x;
    struct dboq_struct *next;
} *dboq, _dboq;

/* for connecting db sockets */
typedef struct
{
    char *ip;
    int stamp;
    db d;
    jid key;
    xmlnode verifies;
    pool p;
    dboq q;
    mio m; /* for that short time when we're connected and open, but haven't auth'd ourselves yet */
    int xmpp_version;
    int xmpp_no_tls;
    xmlnode outstanding_db;
} *dboc, _dboc;

void dialback_out_read(mio m, int flags, void *arg, xmlnode x);

/* try to start a connection based upon this connect object */
void dialback_out_connect(dboc c)
{
    char *ip, *col;
    int port = 5269;

    if(c->ip == NULL)
        return;

    ip = c->ip;
    c->ip = strchr(ip,',');
    if(c->ip != NULL)
    { /* chop off this ip if there is another, track the other */
        *c->ip = '\0';
        c->ip++;
    }

    log_debug2(ZONE, LOGT_IO, "Attempting to connect to %s at %s",jid_full(c->key),ip);

    /* get the ip/port for io_select */
#ifdef WITH_IPV6
    if(ip[0] == '[')
    { /* format "[ipaddr]:port" or "[ipaddr]" */
	ip++;
	col=strchr(ip,']');
	if(col != NULL)
	{
	    *col = '\0';
	    if(col[1]==':')
	    {
		col++;
	    }
	}
    }
    else
    { /* format "ipaddr" or "ipaddr:port" */
	col = strchr(ip, ':');
	/* if it has at least two colons it is an IPv6 address */
	if(col!=NULL && strchr(col+1,':'))
	{
	    col = NULL;
	}
    }
#else
    col = strchr(ip,':');
#endif
    if(col != NULL) 
    {
        *col = '\0';
        col++;
        port = atoi(col);
    }
    mio_connect(ip, port, dialback_out_read, (void *)c, 20, MIO_CONNECT_XML);
}

/* new connection object */
dboc dialback_out_connection(db d, jid key, char *ip)
{
    dboc c;
    pool p;

    if((c = xhash_get(d->out_connecting, jid_full(key))) != NULL)
        return c;

    if(ip == NULL)
        return NULL;

    /* none, make a new one */
    p = pool_heap(2*1024);
    c = pmalloco(p, sizeof(_dboc));
    c->p = p;
    c->d = d;
    c->key = jid_new(p,jid_full(key));
    c->stamp = time(NULL);
    c->verifies = xmlnode_new_tag_pool(p,"v");
    c->ip = pstrdup(p,ip);
    /* XXX add config option, to disable XMPP for configured hosts */
    c->xmpp_version = 1;

    /* insert in the hash */
    xhash_put(d->out_connecting, jid_full(c->key), (void *)c);

    /* start the conneciton process */
    dialback_out_connect(c);

    return c;
}

/* either we're connected, or failed, or something like that, but the connection process is kaput */
void dialback_out_connection_cleanup(dboc c)
{
    dboq cur, next;
    xmlnode x;

    xhash_zap(c->d->out_connecting,jid_full(c->key));

    /* if there was never any ->m set but there's a queue yet, then we probably never got connected, just make a note of it */
    if(c->m == NULL && c->q != NULL)
        log_notice(c->key->server,"failed to establish connection");

    /* if there's any packets in the queue, flush them! */
    cur = c->q;
    while(cur != NULL)
    {
        next = cur->next;
        deliver_fail(dpacket_new(cur->x),"Server Connect Failed");
        cur = next;
    }

    /* also kill any validations still waiting */
    for(x = xmlnode_get_firstchild(c->verifies); x != NULL; x = xmlnode_get_nextsibling(x))
    {
        jutil_tofrom(x);
        dialback_in_verify(c->d, xmlnode_dup(x)); /* it'll take these verifies and trash them */
    }

    pool_free(c->p);
}


void dialback_out_packet(db d, xmlnode x, char *ip)
{
    jid to, from, key;
    miod md;
    int verify = 0;
    dboq q;
    dboc c;

    to = jid_new(xmlnode_pool(x),xmlnode_get_attrib(x,"to"));
    from = jid_new(xmlnode_pool(x),xmlnode_get_attrib(x,"from"));
    if(to == NULL || from == NULL)
    {
        log_warn(d->i->id, "dropping packet, invalid to or from: %s", xmlnode2str(x));
        xmlnode_free(x);
        return;
    }

    log_debug2(ZONE, LOGT_IO, "dbout packet[%s]: %s",ip,xmlnode2str(x));

    /* db:verify packets come in with us as the sender */
    if(j_strcmp(from->server,d->i->id) == 0)
    {
        verify = 1;
        /* fix the headers, restore the real from */
        xmlnode_put_attrib(x,"from",xmlnode_get_attrib(x,"ofrom"));
        xmlnode_hide_attrib(x,"ofrom");
	xmlnode_hide_attrib(x,"dnsqueryby");
        from = jid_new(xmlnode_pool(x),xmlnode_get_attrib(x,"from"));
    }

    /* build the standard key */
    key = jid_new(xmlnode_pool(x),to->server);
    jid_set(key, from->server, JID_RESOURCE);

    /* try to get an active connection */
    if((md = xhash_get(d->out_ok_db, jid_full(key))) == NULL && verify == 0)
        md = xhash_get(d->out_ok_legacy, jid_full(key));

    log_debug2(ZONE, LOGT_IO, "outgoing packet with key %s and located existing %X",jid_full(key),md);

    /* yay! that was easy, just send the packet :) */
    if(md != NULL)
    {
        /* if we've got an ip sent, and a connected host, we should be registered! */
        if(ip != NULL)
            register_instance(md->d->i, key->server);
        dialback_miod_write(md, x);
        return;
    }

    /* get a connection to the other server */
    c = dialback_out_connection(d, key, dialback_ip_get(d, key, ip));

    /* verify requests can't be queued, they need to be sent outright */
    if(verify)
    {
        if(c == NULL)
        {
            jutil_tofrom(x); /* pretend it bounced */
            dialback_in_verify(d, x); /* no connection to send db:verify to, bounce back to in to send failure */
            return;
        }

        /* if the server is already connected, just write it */
        if(c->m != NULL)
        {
            mio_write(c->m, x, NULL, -1);
        }else{  /* queue it so that it's written after we're connected */
            xmlnode_insert_tag_node(c->verifies,x);
            xmlnode_free(x);
        }

        return;
    }

    if(c == NULL)
    {
        log_warn(d->i->id,"dropping a packet that was missing an ip to connect to: %s",xmlnode2str(x));
        xmlnode_free(x);
        return;
    }

    /* insert into the queue */
    q = pmalloco(xmlnode_pool(x), sizeof(_dboq));
    q->stamp = time(NULL);
    q->x = x;
    q->next = c->q;
    c->q = q;

}


/* handle the events on an outgoing dialback socket, which isn't much of a job */
void dialback_out_read_db(mio m, int flags, void *arg, xmlnode x)
{
    db d = (db)arg;

    if(flags != MIO_XML_NODE) return;

    /* it's either a valid verify response, or bust! */
    if(j_strcmp(xmlnode_get_name(x),"db:verify") == 0)
    {
        dialback_in_verify(d, x);
        return;
    }

    if(j_strcmp(xmlnode_get_name(x),"stream:error") == 0)
    {
        log_debug2(ZONE, LOGT_IO, "reveived stream error: %s",xmlnode_get_data(x));
    }else{
        mio_write(m, NULL, "<stream:error><undefined-condition xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Received data on a send-only socket. You are not Allowed to send data on this socket!</text></stream:error>", -1);
    }
    
    mio_close(m);
    xmlnode_free(x);
}

/* handle the events on an outgoing legacy socket, in other words, nothing */
void dialback_out_read_legacy(mio m, int flags, void *arg, xmlnode x)
{
    if(flags != MIO_XML_NODE) return;

    /* other data on the stream? naughty you! */
    if(j_strcmp(xmlnode_get_name(x),"stream:error") == 0)
    {
        log_debug2(ZONE, LOGT_IO, "reveived stream error: %s",xmlnode_get_data(x));
    }else{
        mio_write(m, NULL, "<stream:error><undefined-condition xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Received data on a send-only socket. You are not Allowed to send data on this socket!</text></stream:error>", -1);
    }
    
    mio_close(m);
    xmlnode_free(x);
}

/* util to flush queue to mio */
void dialback_out_qflush(miod md, dboq q)
{
    dboq cur, next;

    cur = q;
    while(cur != NULL)
    {
        next = cur->next;
        dialback_miod_write(md, cur->x);
        cur = next;
    }
}

/* handle the early connection process */
void dialback_out_read(mio m, int flags, void *arg, xmlnode x)
{
    dboc c = (dboc)arg;
    xmlnode cur;
    miod md;
    int version = 0;
    char *dbns = NULL;

    log_debug2(ZONE, LOGT_IO, "dbout read: fd %d flag %d key %s",m->fd, flags, jid_full(c->key));

    switch(flags)
    {
    case MIO_NEW:
        log_debug2(ZONE, LOGT_IO, "NEW outgoing server socket connected at %d",m->fd);

        /* outgoing conneciton, write the header */
        cur = xstream_header("jabber:server", c->key->server, NULL);
        xmlnode_put_attrib(cur,"xmlns:db","jabber:server:dialback");	/* flag ourselves as dialback capable */
	if (c->xmpp_version == 1) {					/* should we flag XMPP support? */
	    xmlnode_put_attrib(cur, "version", "1.0");
	}
        mio_write(m, NULL, xstream_header_char(cur), -1);
        xmlnode_free(cur);
        return;

    case MIO_XML_ROOT:
        log_debug2(ZONE, LOGT_IO, "Incoming root %s",xmlnode2str(x));
        /* validate namespace */
        if(j_strcmp(xmlnode_get_attrib(x,"xmlns"),"jabber:server") != 0)
        {
            mio_write(m, NULL, "<stream:error><invalid-namespace xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Invalid Stream Header!</text></stream:error>", -1);
            mio_close(m);
            break;
        }

        /* make sure we're not connecting to ourselves */
        if(xhash_get(c->d->in_id,xmlnode_get_attrib(x,"id")) != NULL)
        {
            log_alert(c->key->server,"hostname maps back to ourselves!- No service defined for this hostname, can not handle request. Check jabberd configuration.");
            mio_write(m, NULL, "<stream:error><internal-server-error xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Mirror Mirror on the wall (we connected to ourself)</text></stream:error>", -1);
            mio_close(m);
            break;
        }

	/* check version */
	version = j_atoi(xmlnode_get_attrib(x, "version"), 0);
	dbns = xmlnode_get_attrib(x, "xmlns:db");

        /* check for old servers */
	if (version < 1 && dbns == NULL) {
            if(!c->d->legacy)
            { /* Muahahaha!  you suck! *click* */
                log_notice(c->key->server,"Legacy server access denied due to configuration");
		mio_write(m, NULL, "<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Legacy Access Denied!</text></stream:error>", -1);
                mio_close(m);
                break;
            }

            mio_reset(m, dialback_out_read_legacy, (void *)c->d); /* different handler now */
            md = dialback_miod_new(c->d, m); /* set up the mio wrapper */
            dialback_miod_hash(md, c->d->out_ok_legacy, c->key); /* this registers us to get stuff now */
            dialback_out_qflush(md, c->q); /* flush the queue of packets */
            c->q = NULL;
            dialback_out_connection_cleanup(c); /* we're connected already, trash this */
            break;
        }

	/* peer is XMPP server, but does not support dialback */
	if (dbns == NULL) {
	    log_notice(c->d->i->id, "We cannot send to %s. This XMPP server does not support dialback.", c->key->server);
	    mio_write(m, NULL, "<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xml:lang='en' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>Sorry, we only support dialback to 'authenticate' our peers. SASL is not supported by us. It seems we cannot communicate to you :-(</text></stream:error>", -1);
	    mio_close(m);
	    break;
	}

        /* create and send our result request to initiate dialback */
        cur = xmlnode_new_tag("db:result");
        xmlnode_put_attrib(cur, "to", c->key->server);
        xmlnode_put_attrib(cur, "from", c->key->resource);
        xmlnode_insert_cdata(cur,  dialback_merlin(xmlnode_pool(cur), c->d->secret, c->key->server, xmlnode_get_attrib(x,"id")), -1);
	if (version && c->outstanding_db == NULL) {
	    c->outstanding_db = cur;
	} else {
	    mio_write(m,cur, NULL, 0);
	}

        /* well, we're connected to a dialback server, we can at least send verify requests now */
        c->m = m;
	if (version < 1) {
	    for(cur = xmlnode_get_firstchild(c->verifies); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
		mio_write(m, xmlnode_dup(cur), NULL, -1);
		xmlnode_hide(cur);
	    }
	}

        break;
    case MIO_XML_NODE:
	/* watch for stream:features */
	if (j_strcmp(xmlnode_get_name(x), "stream:features") == 0) {
#ifdef HAVE_SSL
	    /* is starttls supported? */
	    if (xmlnode_get_tag(x, "starttls?xmlns=" NS_XMPP_TLS) != NULL) {
		/* don't start if forbidden by caller (configuration) */
		if (c->xmpp_no_tls) {
		    log_notice(c->d->i->id, "Server %s advertized starttls, but disabled by our configuration.", c->key->server);
		    break;
		}

		/* check if our side is prepared for starttls */
		if (mio_ssl_starttls_possible(m, c->key->resource)) {
		    xmlnode starttls = NULL;

		    /* request to start tls on this connection */
		    log_debug2(ZONE, LOGT_IO, "requesting starttls for an outgoing connection to %s", c->key->server);

		    starttls = xmlnode_new_tag("starttls");
		    xmlnode_put_attrib(starttls, "xmlns", NS_XMPP_TLS);
		    mio_write(m, starttls, NULL, 0);
		    break;
		}
	    }
#endif /* HAVE_SSL */

	    /* no stream:feature we'd like to use, we can now send the outstanding db:result */
	    if (c->outstanding_db) {
		mio_write(m, c->outstanding_db, NULL, 0);
		c->outstanding_db = NULL;
	    }

	    /* and we can send the verify requests */
	    for(cur = xmlnode_get_firstchild(c->verifies); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
		mio_write(m, xmlnode_dup(cur), NULL, -1);
		xmlnode_hide(cur);
	    }

	    /* finished processing stream:features */
	    break;
	}

#ifdef HAVE_SSL
	/* watch for positive starttls result */
	if (j_strcmp(xmlnode_get_name(x), "proceed") == 0 && j_strcmp(xmlnode_get_attrib(x, "xmlns"), NS_XMPP_TLS) == 0) {
	    /* start tls on our side */
	    if (mio_xml_starttls(m, 1, c->key->resource)) {
		/* starting tls failed */
		log_warn(c->d->i->id, "Starting TLS on an outgoing s2s to %s failed on our side (%s).", c->key->server, c->key->resource);
		mio_close(m);
	    }

	    /* forget outstanding <db:result/>, stream state is reset */
	    if (c->outstanding_db != NULL) {
		xmlnode_free(c->outstanding_db);
		c->outstanding_db = NULL;
	    }

	    /* send stream header again */
	    dialback_out_read(m, MIO_NEW, c, NULL);

	    break;
	}

	/* watch for negative starttls result */
	if (j_strcmp(xmlnode_get_name(x), "failure") == 0 && j_strcmp(xmlnode_get_attrib(x, "xmlns"), NS_XMPP_TLS) == 0) {
	    log_warn(c->d->i->id, "Starting TLS on an outgoing s2s to %s failed on the other side.", c->key->server);
	    mio_close(m);
	    break;
	}
#endif /* HAVE_SSL */

        /* watch for a valid result, then we're set to rock! */
        if(j_strcmp(xmlnode_get_name(x),"db:result") == 0)
        {
            if(j_strcmp(xmlnode_get_attrib(x,"from"),c->key->server) != 0 || j_strcmp(xmlnode_get_attrib(x,"to"),c->key->resource) != 0)
            { /* naughty... *click* */
                log_warn(c->d->i->id,"Received illegal dialback validation remote %s != %s or to %s != %s",c->key->server,xmlnode_get_attrib(x,"from"),c->key->resource,xmlnode_get_attrib(x,"to"));
                mio_write(m, NULL, "<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Invalid Dialback Result</text></stream:error>", -1);
                mio_close(m);
                break;
            }

            /* process the returned result */
            if(j_strcmp(xmlnode_get_attrib(x,"type"),"valid") == 0)
            {
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
            log_alert(c->d->i->id,"We were told by %s that our sending name %s is invalid, either something went wrong on their end, we tried using that name improperly, or dns does not resolve to us",c->key->server,c->key->resource);
            mio_write(m, NULL, "<stream:error><remote-connection-failed xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>I guess we're trying to use the wrong name, sorry</text></stream:error>", -1);
            mio_close(m);
            break;
        }

        /* otherwise it's either a verify response, or bust! */
        if(j_strcmp(xmlnode_get_name(x),"db:verify") == 0)
        {
            dialback_in_verify(c->d, x);
            return;
        }

        log_warn(c->d->i->id,"Dropping connection due to illegal incoming packet on an unverified socket from %s to %s (%s): %s",c->key->resource,c->key->server,m->ip,xmlnode2str(x));
        mio_write(m, NULL, "<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Not Allowed to send data on this socket!</text></stream:error>", -1);
        mio_close(m);
        break;

    case MIO_CLOSED:
        if(c->ip == NULL)
            dialback_out_connection_cleanup(c); /* buh bye! */
        else
            dialback_out_connect(c); /* this one failed, try another */
        return;

    default:
        return;
    }
    xmlnode_free(x);
}

/* callback for walking the connecting hash tree */
void _dialback_out_beat_packets(xht h, const char *key, void *data, void *arg)
{
    dboc c = (dboc)data;
    dboq cur, next, last;
    int now = time(NULL);

    /* time out individual queue'd packets */
    cur = c->q;
    while(cur != NULL)
    {
        if((now - cur->stamp) <= c->d->timeout_packets)
        {
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
        deliver_fail(dpacket_new(cur->x),"Server Connect Timeout");
        cur = next;
    }
}

result dialback_out_beat_packets(void *arg)
{
    db d = (db)arg;
    xhash_walk(d->out_connecting,_dialback_out_beat_packets,NULL);
    return r_DONE;
}
