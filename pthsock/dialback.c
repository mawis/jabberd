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
 
/*
    <!-- For use without an external DNS component -->
  <service id="127.0.0.1 s2s">
    <host/>
    <load main="pthsock_server">
      <pthsock_server>../load/pthsock_server.so</pthsock_server>
    </load>
  </service>

  <!-- for use with an external DNS component -->
  <service id="127.0.0.1 s2s">
    <host>pthsock-s2s.127.0.0.1</host> <!-- add this host to DNS config section -->
    <load main="pthsock_server">
      <pthsock_server>../load/pthsock_server.so</pthsock_server>
    </load>
  </service>

DIALBACK: 

A->B
    A: <db:result to=B from=A>...</db:result>

    B->A
        B: <db:verify to=A from=B id=asdf>...</db:verify>
        A: <db:verify type="valid" to=B from=A id=asdf/>

A->B
    B: <db:result type="valid" to=A from=B/>


*/

#include "io.h"


/************************ OBJECTS ****************************/

/* s2s instance */
typedef struct ssi_struct
{
    instance i;
    HASHTABLE ips; /* hash table of all dialback capable outgoing sockets to ip:port addresses */
    HASHTABLE hosts; /* hash table of all host structures, in and out, key@to/from format */
    HASHTABLE nscache; /* hash table of all resolved hostname->ip mappings, since we skip dnsrv */
    char *secret; /* our dialback secret */
    int legacy; /* flag to allow old servers */
} *ssi, _ssi;

typedef struct conn_struct
{
    /* used for in and out connections */
    ssi si;
    sock s;         /* socket once it's connected */
    xstream xs;     /* xml stream */
    int legacy;     /* flag that we're in legacy mode */
    char *id;       /* the id="" attrib from the other side or the one we sent */

    /* outgoing connections only */
    int connected;  /* flag for connecting process */
    char *ips;      /* the ip:port */
    char *ipn;      /* the next ip:port */
    pool p;         /* pool for this struct */
    pool pre;       /* pool for queing activity that happens as soon as the socket is spiffy */
    char *legacy_to;/* the to="" hostname for legacy servers */

} *conn, _conn;

typedef enum { htype_IN, htype_OUT } htype;

typedef struct host_struct
{
    /* used for in and out connections */
    htype type;     /* type of host, in or out */
    jid id;         /* the funky id for the hashes, to/from */
    int valid;      /* flag if we've been validated */
    ssi si;         /* instance tracker */
    int created;    /* when the host entry was created */

    /* outgoing connections only */
    conn c;         /* the ip we're connected on */
    pth_msgport_t mp; /* pre-validated write queue */

    /* incoming connections */
    sock s;         /* the incoming connection that we're associated with */

} *host, _host;

/* msgport wrapper struct to deliver dpackets to a queue */
typedef struct
{
    pth_message_t head; /* the standard pth message header */
    xmlnode x;
} _dpq, *dpq;


/************************ UTILITIES ****************************/

/* we need a decently random string in a few places */
char *_pthsock_server_randstr(void)
{
    static char ret[41];

    sprintf(ret,"%d",rand());
    shahash_r(ret,ret);
    return ret;
}

/* flag an outgoing host as valid and dequeue the msgport, can be called to cleanup the host entry as failure */
void _pthsock_server_host_validated(int valid, host h)
{
    dpq q;

    log_debug(ZONE,"host valid check %d for %s",valid,jid_full(h->id));
    if(valid)
    {
        h->valid = 1;
        if(h->mp != NULL)
        {
            /* dequeue and send the waiting packets */
            while((q = (dpq)pth_msgport_get(h->mp)) != NULL)
                io_write(h->c->s,q->x);
            pth_msgport_destroy(h->mp);
            h->mp = NULL;
        }
        return;
    }

    /* invalid host, clean up and dissappear! */
    unregister_instance(h->si->i, h->id->server);

    if(h->mp != NULL)
    {
        /* dequeue and bounce the waiting packets */
        while((q = (dpq)pth_msgport_get(h->mp)) != NULL)
            deliver_fail(dpacket_new(q->x),NULL);
        pth_msgport_destroy(h->mp);
        h->mp = NULL;
    }

    /* remove from hash */
    ghash_remove(h->si->hosts,jid_full(h->id));
}

/* called when the host goes bye bye */
void _pthsock_server_host_cleanup(void *arg)
{
    host h = (host)arg;

    /* this function cleans up for us as if it were invalid */
    _pthsock_server_host_validated(0,h);
}

/* convenience */
char *_pthsock_server_merlin(pool p, char *secret, char *to, char *challenge)
{
    static char res[41];

    shahash_r(secret,                       res);
    shahash_r(spools(p, res, to, p),        res);
    shahash_r(spools(p, res, challenge, p), res);

    return res;
}

/* send the db:result to the other side, can be called as a failure (from pool_cleanup) or directly to queue the result, reacts intelligently */
void _pthsock_server_host_result(void *arg)
{
    host h = (host)arg;
    xmlnode x;

    log_debug(ZONE,"host result check for %s",jid_full(h->id));

    /* if this is a legacy connect, just validate the host */
    if(h->c->legacy)
    {
        _pthsock_server_host_validated(1,h);
        return;
    }

    /* if we're CTS, generate and send result */
    if(h->c->connected)
    {
        x = xmlnode_new_tag("db:result");
        xmlnode_put_attrib(x, "to", h->id->server);
        xmlnode_put_attrib(x, "from", h->id->resource);
        xmlnode_insert_cdata(x,  _pthsock_server_merlin(xmlnode_pool(x), h->si->secret, h->id->server, h->c->id), -1);
        log_debug(ZONE,"host result generated %s",xmlnode2str(x));
        io_write_str(h->c->s,xmlnode2str(x));
        xmlnode_free(x);
        return;
    }

    /* no socket yet, queue the packet */
    if(h->c->s == NULL)
    {
        pool_cleanup(h->c->pre, _pthsock_server_host_result, arg);
        return;
    }

    /* we're only here if something went wrong, couldn't connect, legacy connect, etc, just quit */
}

/* send the db:verify to the other side, can be called as a pool_cleanup or directly, reacts intelligently */
void _pthsock_server_host_verify(void *arg)
{
    xmlnode x = (xmlnode)arg;
    conn c = xmlnode_get_vattrib(x,"c"); /* hidden c on the xmlnode */
    host h;

    log_debug(ZONE,"host verify QR %s",xmlnode2str(x));

    /* send it */
    if(!c->legacy && c->connected)
    {
        xmlnode_hide_attrib(x,"c"); /* hide it again */
        io_write_str(c->s,xmlnode2str(x));
        xmlnode_free(x);
        return;
    }

    /* queue it */
    if(c->s == NULL)
    {
        pool_cleanup(c->pre, _pthsock_server_host_verify, arg);
        return;
    }

    /* hmm... something went wrong, bounce it */
    jutil_tofrom(x);
    xmlnode_put_attrib(x,"type","invalid");
    h = ghash_get(c->si->hosts,spools(xmlnode_pool(x),xmlnode_get_attrib(x,"id"),"@",xmlnode_get_attrib(x,"from"),"/",xmlnode_get_attrib(x,"to"),xmlnode_pool(x))); /* should be getting the incon host */
    if(h != NULL)
        io_write_str(h->c->s, xmlnode2str(x));
    xmlnode_free(x);
}


/************************ OUTGOING CONNECTIONS ****************************/

/* process xml from a socket we made */
void pthsock_server_outx(int type, xmlnode x, void *arg)
{
    conn c = (conn)arg;
    host h;
    xmlnode x2;

    log_debug(ZONE,"outgoing conn %s XML[%d]: %s",c->ips,type,xmlnode2str(x));

    switch(type)
    {
    case XSTREAM_ROOT:
        /* validate namespace */
        if(j_strcmp(xmlnode_get_attrib(x,"xmlns"),"jabber:server") != 0)
        {
            io_write_str(c->s,"<stream:error>Invalid Stream Header!</stream:error>");
            io_close(c->s);
            break;
        }
        /* check for old servers */
        if(xmlnode_get_attrib(x,"xmlns:db") == NULL)
        {
            if(!c->si->legacy)
            { /* Muahahaha!  you suck! *click* */
                log_notice(c->legacy_to,"Legacy server access denied to do configuration");
                io_write_str(c->s,"<stream:error>Legacy Access Denied!</stream:error>");
                io_close(c->s);
                break;
            }
            c->legacy = 1;
            log_notice(c->legacy_to,"legacy server outgoing connection established");
        }else{
            /* db capable, register in main hash of connected ip's */
            ghash_put(c->si->ips, c->ips, c);
        }
        c->connected = 1;
        c->id = pstrdup(c->p,xmlnode_get_attrib(x,"id")); /* store this for the result generation */
        pool_free(c->pre); /* flag that we're clear-to-send */
        c->pre = NULL;
        break;
    case XSTREAM_NODE:
        /* we only get db:* packets incoming! */
        if(j_strcmp(xmlnode_get_name(x),"db:result") == 0)
        {
            h = ghash_get(c->si->hosts,spools(xmlnode_pool(x),xmlnode_get_attrib(x,"from"),"/",xmlnode_get_attrib(x,"to"),xmlnode_pool(x)));
            if(h == NULL || h->c != c)
            { /* naughty... *click* */
                log_warn(c->legacy_to,"Received illegal dialback validation from %s to %s",xmlnode_get_attrib(x,"from"),xmlnode_get_attrib(x,"to"));
                io_write_str(c->s,"<stream:error>Invalid Dialback Result!</stream:error>");
                io_close(c->s);
                break;
            }

            /* process the returned result */
            if(j_strcmp(xmlnode_get_attrib(x,"type"),"valid") == 0)
                _pthsock_server_host_validated(1,h);
            else
                _pthsock_server_host_validated(0,h);

            break;
        }
        if(j_strcmp(xmlnode_get_name(x),"db:verify") == 0)
        {
            /* first validate that we actually sent it */
            h = ghash_get(c->si->hosts,spools(xmlnode_pool(x),xmlnode_get_attrib(x,"from"),"/",xmlnode_get_attrib(x,"to"),xmlnode_pool(x)));
            if(h == NULL || h->c != c)
            { /* naughty... *click* */
                log_warn(c->legacy_to,"Received illegal dialback verification from %s to %s",xmlnode_get_attrib(x,"from"),xmlnode_get_attrib(x,"to"));
                io_write_str(c->s,"<stream:error>Invalid Dialback Verify!</stream:error>");
                io_close(c->s);
                break;
            }

            /* get the incoming host */
            h = ghash_get(c->si->hosts,spools(xmlnode_pool(x),xmlnode_get_attrib(x,"id"),"@",xmlnode_get_attrib(x,"to"),"/",xmlnode_get_attrib(x,"from"),xmlnode_pool(x)));
            if(h == NULL)
                break; /* musta distapeared */

            /* if they're cool in your book, we'll agree, enable them to send packets */
            if(j_strcmp(xmlnode_get_attrib(x,"type"),"valid") == 0)
                h->valid = 1;

            /* rewrite and forward the result on so they can send packets */
            x2 = xmlnode_new_tag_pool(xmlnode_pool(x),"db:result");
            xmlnode_put_attrib(x2,"to",xmlnode_get_attrib(x,"from"));
            xmlnode_put_attrib(x2,"from",xmlnode_get_attrib(x,"to"));
            xmlnode_put_attrib(x2,"type",xmlnode_get_attrib(x,"type"));
            io_write_str(h->c->s,xmlnode2str(x2));
            break;
        }
        /* other data on the stream? */
    case XSTREAM_ERR:
    case XSTREAM_CLOSE:
        /* IO cleanup will take care of everything else */
        io_close(c->s);
        break;
    }
    xmlnode_free(x);
}

/* callback for io_select for connections we've made */
void pthsock_server_outread(sock s, char *buffer, int bufsz, int flags, void *arg)
{
    conn c = (conn)arg;
    xmlnode x;
    char *ip, *colon;
    int port = 5269;

    log_debug(ZONE,"outgoing conn %s IO[%d]",c->ips,flags);

    switch(flags)
    {
    case IO_INIT:
        break; /* umm.. who cares? */
    case IO_NEW: /* new socket from io_select */
        log_debug(ZONE,"NEW outgoing server socket connected at %d",s->fd);
        c->xs = xstream_new(c->p, pthsock_server_outx, (void *)c);
        c->s = s;

        /* outgoing conneciton, write the header */
        x = xstream_header("jabber:server", c->legacy_to, NULL);
        xmlnode_put_attrib(x,"xmlns:db","jabber:server:dialback"); /* flag ourselves as dialback capable */
        log_debug(ZONE,"writing header to server: %s",xmlnode2str(x));
        io_write_str(c->s,xstream_header_char(x));
        xmlnode_free(x);

        break;
    case IO_NORMAL:
        /* yum yum */
        xstream_eat(c->xs,buffer,bufsz);
        break;
    case IO_CLOSED:

        /* remove us if we were advertised */
        ghash_remove(c->si->ips, c->ips);

        /* if we weren't connected and there's more IP's to try, try them */
        if(c->s == NULL && c->ipn != NULL)
        {
            ip = c->ipn;
            c->ipn = strchr(ip,',');
            if(c->ipn != NULL)
            { /* chop off this ip if there is another, track the other */
                *c->ipn = '\0';
                c->ipn++;
            }
            /* get the ip/port for io_select */
            colon = strchr(ip,':');
            if(colon != NULL) 
            {
                colon[0]='\0';
                colon++;
                port=atoi(colon);
            }
            io_select_connect(ip, port, NULL, pthsock_server_outread, (void *)c);
            return;
        }

        /* hrm, we're here, so this means we're giving up on connecting */
        pool_free(c->pre);
        pool_free(c->p);
        break;
    case IO_ERROR:
        /* XXX bounce the write queue? */
    }
}

/* phandler callback, send packets to another server */
result pthsock_server_packets(instance i, dpacket dp, void *arg)
{
    ssi si = (ssi) arg;
    pool p;
    xmlnode x = dp->x;
    jid to, from, id;
    host h;
    conn c;
    char *ip = NULL, *colon;
    int port = 5269;
    dpq q;

    /* if it's a route, x is the child and get the ip, and make sure we have all that we need to continue */
    if((dp->type == p_ROUTE && ((x = xmlnode_get_firstchild(dp->x)) == NULL || (ip = xmlnode_get_attrib(dp->x,"ip")) == NULL)) || (to = jid_new(dp->p,xmlnode_get_attrib(x,"to"))) == NULL || (from = jid_new(dp->p,xmlnode_get_attrib(x,"from"))) == NULL)
    {
        log_notice(dp->host,"Dropping invalid outbound packet: %s",xmlnode2str(dp->x));
        xmlnode_free(dp->x);
        return r_DONE;
    }

    log_debug(ZONE,"Dr. Pepper Says: %s",xmlnode2str(dp->x));

    /* make this special id for the hash */
    id = jid_new(dp->p,to->server);
    jid_set(id,from->server,JID_RESOURCE);

    /* get the host if there's already one */
    if((h = (host)ghash_get(si->hosts,jid_full(id))) == NULL)
    {
        /* if we don't have an IP, we're misconfigured or something went awry! */
        if(ip == NULL && (ip = (char*)ghash_get(si->nscache,to->server)) == NULL)
        {
            log_error(dp->host,"s2s received invalid, unresolved, outbound packet: %s",xmlnode2str(dp->x));
            deliver_fail(dp, "Unresolved");
            return r_DONE;
        }
        /* if there's already a connection to this ip, reuse it */
        if((c = (conn)ghash_get(si->ips,ip)) == NULL)
        {
            /* new conn struct */
            p = pool_new();
            c = pmalloco(p, sizeof(_conn));
            c->legacy_to = pstrdup(p, to->server); /* legacy crap, conn tied to recipient host */
            c->ips = pstrdup(p,ip);
            c->ipn = strchr(ip,',');
            if(c->ipn != NULL)
            { /* chop off this ip if there is another, track the other */
                *c->ipn = '\0';
                c->ipn++;
                c->ipn = pstrdup(p,c->ipn); /* for future reference to the succeding ip's */
            }
            c->p = p;
            c->si = si;
            c->pre = pool_new();
            /* get the ip/port for io_select */
            colon = strchr(ip,':');
            if(colon != NULL) 
            {
                colon[0]='\0';
                colon++;
                port=atoi(colon);
            }
            io_select_connect(ip, port, NULL, pthsock_server_outread, (void *)c);
        }

        /* make a new host */
        h = pmalloco(c->p, sizeof(_host));
        h->type = htype_OUT;
        h->si = si;
        h->c = c;
        h->created = time(NULL);
        h->id = jid_new(c->p,jid_full(id));
        ghash_put(si->hosts,jid_full(h->id),h); /* register us */
        pool_cleanup(c->p,_pthsock_server_host_cleanup,(void *)h); /* make sure things get put back to normal afterwards */
        _pthsock_server_host_result((void *)h); /* try to send result to the other side */

        /* cache the name/ip since we'll get unresolved packets directly now (below) */
        if(j_strcmp(ghash_get(si->nscache,to->server),ip) != 0)
            ghash_put(si->nscache,pstrdup(si->i->p,to->server),pstrdup(si->i->p,ip)); /* XXX yes, I know this leaks everytime the IP changes and there's a new sender, should be infrequent enough for now :) */

        /* register us with this host, for efficiency */
        register_instance(si->i, id->server);

    }

    /* write the packet to the socket, it's safe */
    if(h->valid)
    {
        io_write(h->c->s, x);
        return r_DONE;
    }

    if(j_strcmp(xmlnode_get_name(x),"db:verify") != 0)
    {
        if(h->mp == NULL)
            h->mp = pth_msgport_create(jid_full(id));

        q = pmalloco(dp->p, sizeof(_dpq));
        q->x = x;
        pth_msgport_put(h->mp,(pth_message_t *)q);
        return r_DONE;
    }

    /* all we have left is db:verify packets */
    xmlnode_put_vattrib(x,"c",(void *)(h->c)); /* ugly, but hide the c on the xmlnode */
    _pthsock_server_host_verify((void *)(x));

    return r_DONE;
}


/************************ INCOMING CONNECTIONS ****************************/

/* process xml from an accept'd socket */
void pthsock_server_inx(int type, xmlnode x, void *arg)
{
    conn c = (conn)arg;
    xmlnode x2;
    host h = NULL;
    jid to, from;

    log_debug(ZONE,"incoming conn %X XML[%d]: %s",c,type,xmlnode2str(x));

    switch(type)
    {
    case XSTREAM_ROOT:
        /* new incoming connection sent a header, write our header */
        x2 = xstream_header("jabber:server", NULL, xmlnode_get_attrib(x,"to"));
        xmlnode_put_attrib(x2,"xmlns:db","jabber:server:dialback"); /* flag ourselves as dialback capable */
        c->id = pstrdup(c->p,_pthsock_server_randstr());
        xmlnode_put_attrib(x2,"id",c->id); /* send random id as a challenge */
        io_write_str(c->s,xstream_header_char(x2));
        xmlnode_free(x2);

        /* validate namespace */
        if(j_strcmp(xmlnode_get_attrib(x,"xmlns"),"jabber:server") != 0)
        {
            io_write_str(c->s,"<stream:error>Invalid Stream Header!</stream:error>");
            io_close(c->s);
            break;
        }

        if(xmlnode_get_attrib(x,"xmlns:db") == NULL)
        {
            if(c->si->legacy)
            {
                c->legacy = 1;
                log_notice(xmlnode_get_attrib(x,"to"),"legacy server incoming connection established from %s",c->s->ip);
            }else{
                io_write_str(c->s,"<stream:error>Legacy Access Denied!</stream:error>");
                io_close(c->s);
                break;
            }
        }

        break;
    case XSTREAM_NODE:
        /* check for a legacy socket */
        if(c->legacy)
        {
            deliver(dpacket_new(x),c->si->i);
            return;
        }

        /* incoming verification request, check and respond */
        if(j_strcmp(xmlnode_get_name(x),"db:verify") == 0)
        {
            if(j_strcmp( xmlnode_get_data(x), _pthsock_server_merlin(xmlnode_pool(x), c->si->secret, xmlnode_get_attrib(x,"from"), xmlnode_get_attrib(x,"id"))) == 0)
                xmlnode_put_attrib(x,"type","valid");
            else
                xmlnode_put_attrib(x,"type","invalid");
            jutil_tofrom(x);
            io_write_str(c->s,xmlnode2str(x));
            break;
        }

        /* incoming result, make a host and forward on */
        if(j_strcmp(xmlnode_get_name(x),"db:result") == 0)
        {
            /* make a new host */
            h = pmalloco(c->p, sizeof(_host));
            h->type = htype_IN;
            h->si = c->si;
            h->c = c;
            h->id = jid_new(c->p,xmlnode_get_attrib(x,"to"));
            jid_set(h->id,xmlnode_get_attrib(x,"from"),JID_RESOURCE);
            jid_set(h->id,c->id,JID_USER); /* special user of the id attrib makes this key unique */
            ghash_put(c->si->hosts,jid_full(h->id),h); /* register us */
            pool_cleanup(c->p,_pthsock_server_host_cleanup,(void *)h); /* make sure things get put back to normal afterwards */

            /* send the verify back to them, on another outgoing trusted socket, via deliver (so it is real and goes through dnsrv and anything else) */
            x2 = xmlnode_new_tag_pool(xmlnode_pool(x),"db:verify");
            xmlnode_put_attrib(x2,"to",xmlnode_get_attrib(x,"from"));
            xmlnode_put_attrib(x2,"from",xmlnode_get_attrib(x,"to"));
            xmlnode_put_attrib(x2,"id",c->id);
            xmlnode_insert_node(x2,xmlnode_get_firstchild(x)); /* copy in any children */
            deliver(dpacket_new(x2),c->si->i);

            return;
        }

        /* hmm, incoming packet on dialback line, there better be a host for it or else! */
        to = jid_new(xmlnode_pool(x),xmlnode_get_attrib(x,"to"));
        from = jid_new(xmlnode_pool(x),xmlnode_get_attrib(x,"from"));
        if(to != NULL && from != NULL)
            h = ghash_get(c->si->hosts, spools(xmlnode_pool(x),c->id,"@",to->server,"/",from->server,xmlnode_pool(x)));
        if(h == NULL || !h->valid || h->c != c)
        { /* dude, what's your problem!  *click* */
            io_write_str(c->s,"<stream:error>Invalid Packets Recieved!</stream:error>");
            io_close(c->s);
            break;
        }

        /* all cool */
        deliver(dpacket_new(x),c->si->i);
        return;
    case XSTREAM_ERR:
    case XSTREAM_CLOSE:
        /* things clean up for themselves */
        io_close(c->s);
        break;
    }
    xmlnode_free(x);
}

/* callback for io_select for accepted sockets */
void pthsock_server_inread(sock s, char *buffer, int bufsz, int flags, void *arg)
{
    conn c = (conn)arg;

    log_debug(ZONE,"incoming conn %X IO[%d]",c,flags);

    switch(flags)
    {
    case IO_INIT:
        break; /* umm.. who cares? */
    case IO_NEW: /* new socket from io_select */
        log_debug(ZONE,"NEW incoming server socket connected at %d",s->fd);
        c = pmalloco(s->p, sizeof(_conn)); /* we get free'd with the socket */
        c->s = s;
        c->p = s->p;
        c->si = (ssi)arg; /* old arg is si */
        c->xs = xstream_new(c->p, pthsock_server_inx, (void *)c);
        s->cb_arg = (void *)c; /* the new arg is c */
        break;
    case IO_NORMAL:
        /* yum yum */
        xstream_eat(c->xs,buffer,bufsz);
        break;
    case IO_CLOSED:
        /* conn is on the sock pool, will get cleaned up */
        break;
    case IO_ERROR:
        /* we don't care, we don't ever write real packets to an incoming connection! */
        break;
    }
}

/* cleanup function */
void pthsock_server_shutdown(void *arg)
{
    ssi si = (ssi)arg;
    ghash_destroy(si->ips);
    ghash_destroy(si->hosts);
    ghash_destroy(si->nscache);
}

/* callback for walking the host hash tree */
int _pthsock_server_beat(void *arg, const void *key, void *data)
{
    host h = (host)data;

    /* any invalid hosts older than 120 seconds, timed out */
    if(h->type == htype_OUT && !h->valid && (time(NULL) - h->created) > 120)
    {
        log_notice(h->id->server,"server connection timed out");
        _pthsock_server_host_validated(0,h);
    }

    return 1;
}

/* heartbeat checker for timed out hosts */
result pthsock_server_beat(void *arg)
{
    ssi si = (ssi)arg;
    ghash_walk(si->hosts,_pthsock_server_beat,NULL);    
    return r_DONE;
}

/*** everything starts here ***/
void pthsock_server(instance i, xmlnode x)
{
    ssi si;
    xmlnode cfg, cur;
    struct karma k;

    log_debug(ZONE,"pthsock_server loading");
    srand(time(NULL));

    /* get the config */
    cfg = xdb_get(xdb_cache(i),NULL,jid_new(xmlnode_pool(x),"config@-internal"),"jabber:config:pth-ssock");

    si = pmalloco(i->p,sizeof(_ssi));
    si->ips = ghash_create(j_atoi(xmlnode_get_tag_data(cfg,"maxhosts"),67),(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp); /* keys are "ip:port" */
    si->hosts = ghash_create(j_atoi(xmlnode_get_tag_data(cfg,"maxhosts"),67),(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp); /* keys are jids: "id@to/from" */
    si->nscache = ghash_create(j_atoi(xmlnode_get_tag_data(cfg,"maxhosts"),67),(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);
    si->i = i;
    si->secret = xmlnode_get_attrib(cfg,"secret");
    if(si->secret == NULL) /* if there's no configured secret, make one on the fly */
        si->secret = pstrdup(i->p,_pthsock_server_randstr());
    if(xmlnode_get_tag(cfg,"legacy") != NULL)
        si->legacy = 1;


    k.val=KARMA_INIT;
    k.bytes=0;
    cur = xmlnode_get_tag(cfg,"karma");
    k.max=j_atoi(xmlnode_get_tag_data(cur,"max"),KARMA_MAX);
    k.inc=j_atoi(xmlnode_get_tag_data(cur,"inc"),KARMA_INC);
    k.dec=j_atoi(xmlnode_get_tag_data(cur,"dec"),KARMA_DEC);
    k.restore=j_atoi(xmlnode_get_tag_data(cur,"restore"),KARMA_RESTORE);
    k.penalty=j_atoi(xmlnode_get_data(cur),KARMA_PENALTY);

    if((cur = xmlnode_get_tag(cfg,"ip")) != NULL)
        for(;cur != NULL; xmlnode_hide(cur), cur = xmlnode_get_tag(cfg,"ip"))
            io_select_listen_ex(j_atoi(xmlnode_get_attrib(cur,"port"),5269),xmlnode_get_data(cur),pthsock_server_inread,(void*)si,j_atoi(xmlnode_get_attrib(xmlnode_get_tag(cfg,"rate"),"time"),5),j_atoi(xmlnode_get_attrib(xmlnode_get_tag(cfg,"rate"),"points"),25),&k);
    else /* no special config, use defaults */
        io_select_listen_ex(5269,NULL,pthsock_server_inread,(void*)si,j_atoi(xmlnode_get_attrib(xmlnode_get_tag(cfg,"rate"),"time"),5),j_atoi(xmlnode_get_attrib(xmlnode_get_tag(cfg,"rate"),"points"),25),&k);

    register_phandler(i,o_DELIVER,pthsock_server_packets,(void*)si);
    register_shutdown(pthsock_server_shutdown, (void*)si);
    register_beat(15, pthsock_server_beat, (void *)si);

    xmlnode_free(cfg);
}
