/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "License").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the License.  You
 * may obtain a copy of the License at http://www.jabber.com/license/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2000 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * --------------------------------------------------------------------------*/

#include <jabberd.h>
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
    db d;
    jid key;
    xmlnode verifies;
    pool p;
    dboq q;
    mio m; /* for that short time when we're connected and open, but haven't auth'd ourselves yet */
} *dboc, _dboc;

/* actually start up the connection */
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

    log_debug(ZONE, "Attempting to connect to %s at %s",jid_full(c->key),ip);

    /* get the ip/port for io_select */
    col = strchr(ip,':');
    if(col != NULL) 
    {
        *col = '\0';
        col++;
        port = atoi(colon);
    }
    mio_connect(ip, port, dialback_out_read, (void *)c, 20, MIO_CONNECT_XML);
}

dboc dialback_out_connection(db d, jid key, char *ip)
{
    dboc c;
    pool p;
    char *col;
    int port;

    if((c = ghash_get(d->out_connecting, jid_full(key))) != NULL)
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

    /* insert in the hash */
    ghash_put(d->out_connecting, jid_full(c->key), (void *)c);

    /* start the conneciton process */
    dialback_out_connect(c);
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

    /* db:verify packets come in with us as the sender */
    if(j_strcmp(from->server,d->i->id) == 0)
    {
        verify = 1;
        /* fix the headers, restore the real from */
        xmlnode_put_attrib(x,"from",xmlnode_get_attrib(x,"ofrom"));
        xmlnode_hide_attrib(x,"ofrom");
        from = jid_new(xmlnode_pool(x),xmlnode_get_attrib(x,"from"));
    }

    /* build the standard key */
    key = jid_new(xmlnode_pool(x),to->server);
    jid_set(key, from->server, JID_RESOURCE);

    /* try to get an active connection */
    if((md = ghash_get(d->out_ok_db, jid_full(key))) == NULL && verify == 0)
        md = ghash_get(d->out_ok_legacy, jid_full(key));

    log_debug(ZONE,"outgoing packet with key %s and located existing %X",jid_full(key),md);

    /* yay! that was easy, just send the packet :) */
    if(md != NULL)
    {
        dialback_miod_write(md, x);
        return;
    }

    /* get a connection to the other server */
    c = dialback_out_connection(d, key, ip);

    /* verify requests can't be queued, they need to be sent outright */
    if(verify)
    {
        if(c == NULL)
        {
            dialback_in_packet(d, x); /* no connection to send db:verify to, bounce back to in to send failure */
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
void dialback_out_read_db(mio s, int flags, void *arg, xmlnode x)
{
    db d = (db)arg;

    if(flags != MIO_XML_NODE) return;

    /* it's either a valid verify response, or bust! */
    if(j_strcmp(xmlnode_get_name(x),"db:verify") == 0 && dialback_in_verify(d, x) != 0)
        mio_write(m, NULL, "<stream:error>Invalid Dialback Verify!</stream:error>", -1);
    else
        mio_write(m, NULL, "<stream:error>Not Allowed to send data on this socket!</stream:error>", -1);

    mio_close(m);
    xmlnode_free(x);
}

/* handle the events on an outgoing legacy socket, in other words, nothing */
void dialback_out_read_legacy(mio s, int flags, void *arg, xmlnode x)
{
    db d = (db)arg;

    if(flags != MIO_XML_NODE) return;

    /* other data on the stream? naughty you! */
    mio_write(m, NULL, "<stream:error>Not Allowed to send data on this socket!</stream:error>", -1);
    mio_close(m);
    xmlnode_free(x);
}

/* util to flush queue to mio */
void _dialback_out_qflush(miod md, dboq q)
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

    switch(flags)
    {
    case MIO_NEW:
        log_debug(ZONE,"NEW outgoing server socket connected at %d",m->fd);

        /* outgoing conneciton, write the header */
        cur = xstream_header("jabber:server", c->key->server, NULL);
        xmlnode_put_attrib(cur,"xmlns:db","jabber:server:dialback"); /* flag ourselves as dialback capable */
        mio_write(m, NULL, xstream_header_char(cur), -1);
        xmlnode_free(cur);
        break;

    case MIO_XML_ROOT:
        /* validate namespace */
        if(j_strcmp(xmlnode_get_attrib(x,"xmlns"),"jabber:server") != 0)
        {
            mio_write(m, NULL, "<stream:error>Invalid Stream Header!</stream:error>", -1);
            mio_close(m);
            break;
        }

        /* check for old servers */
        if(xmlnode_get_attrib(x,"xmlns:db") == NULL)
        {
            if(!c->d->legacy)
            { /* Muahahaha!  you suck! *click* */
                log_notice(c->key->server,"Legacy server access denied due to configuration");
                mio_write(m, NULL, "<stream:error>Legacy Access Denied!</stream:error>", -1);
                mio_close(m);
                break;
            }

            mio_reset(m, dialback_out_read_legacy, (void *)d); /* different handler now */
            md = dialback_miod_new(c->d, m); /* set up the mio wrapper */
            dialback_miod_hash(md, c->d->out_ok_legacy, c->key); /* this registers us to get stuff now */
            _dialback_out_qflush(md, c->q); /* flush the queue of packets */
            dialback_out_connection_kill(c); /* buh bye! */
            break;
        }

        /* XXX generate and send our result */

        /* well, we're connected to a dialback server, we can at least send verify requests now */
        c->m = m;
        for(cur = xmlnode_get_firstchild(c->verifies); cur != NULL; cur = xmlnode_get_nextsibling(cur))
        {
            mio_write(m, xmlnode_dup(cur), NULL, -1);
            xmlnode_hide(cur);
        }

        break;
    case MIO_XML_NODE:
        /* watch for a valid result, then we're set to rock! */
        if(j_strcmp(xmlnode_get_name(x),"db:result") == 0)
        {
            if(j_strcmp(xmlnode_get_attrib(x,"from"),c->key->server) != 0 || j_strcmp(xmlnode_get_attrib(x,"to"),c->key->resource) != 0)
            { /* naughty... *click* */
                log_warn(c->d->i->id,"Received illegal dialback validation remote %s != %s or to %s != %s",c->key->server,xmlnode_get_attrib(x,"from"),c->key->resource,xmlnode_get_attrib(x,"to"));
                mio_write(c->s, NULL, "<stream:error>Invalid Dialback Result</stream:error>", -1);
                mio_close(c->s);
                break;
            }

            /* process the returned result */
            if(j_strcmp(xmlnode_get_attrib(x,"type"),"valid") == 0)
            {
                mio_reset(m, dialback_out_read_db, (void *)d); /* different handler now */
                md = dialback_miod_new(c->d, m); /* set up the mio wrapper */
                dialback_miod_hash(md, c->d->out_ok_db, c->key); /* this registers us to get stuff now */
                _dialback_out_qflush(md, c->q); /* flush the queue of packets */
            }
            dialback_out_connection_kill(c);
            break;
        }

        /* otherwise it's either a valid verify response, or bust! */
        if(j_strcmp(xmlnode_get_name(x),"db:verify") == 0 && dialback_in_verify(d, x) != 0)
            mio_write(m, NULL, "<stream:error>Invalid Dialback Verify!</stream:error>", -1);
        else
            mio_write(m, NULL, "<stream:error>Not Allowed to send data on this socket!</stream:error>", -1);
        mio_close(m);
        break;

    case MIO_CLOSED:
        if(c->ip == NULL)
            dialback_out_connection_kill(c); /* buh bye! */
        else
            dialback_out_connect(c); /* this one failed, try another */
        return;
    }
    xmlnode_free(x);
}

/* kill the connection stuff */
void dialback_out_connection_kill(dboc c)
{
    dboq cur, next;
    xmlnode x;

    log_notice(c->key->server,"failed to connect");
    ghash_remove(c->d->out_connecting,jid_full(c->key));

    /* bounce all queue'd packets */
    cur = c->q;
    while(cur != NULL)
    {
        next = cur->next;
        deliver_fail(dpacket_new(cur->x),"Server Connect Timeout");
        cur = next;
    }

    /* kill any validations waiting */
    for(x = xmlnode_get_firstchild(c->verifies); x != NULL; x = xmlnode_get_nextsibling(x))
        dialback_in_packets(c->d, xmlnode_dup(x)); /* it'll take these verifies and trash them */

    pool_free(c->p);
}

/* callback for walking the connecting hash tree */
int _dialback_out_beat_packets(void *arg, const void *key, void *data)
{
    dboc c = (dboc)data;
    dboq cur, next, last;
    int now = time(NULL);

    /* time out individual queue'd packets */
    cur = c->q;
    while(cur != NULL)
    {
        if((now - cur->stamp) <= c->d->timeout_packet)
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

    return 1;
}

void dialback_out_beat_packets(d)
{
    ghash_walk(d->out_connecting,_dialback_out_beat_packets,NULL);
    return r_DONE;
}
