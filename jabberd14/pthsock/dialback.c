

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *  Jabber
 *  Copyright (C) 1998-2000 The Jabber Team http://jabber.org/
 */

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

/* server 2 server instance */
typedef struct ssi_struct
{
    instance i;
    HASHTABLE ips; /* hash table of all dialback capable outgoing sockets to ip:port addresses */
    HASHTABLE hosts; /* hash table of all host structures, in and out, key@to/from format */
} *ssi, _ssi;

typedef enum { cstate_START, cstate_OK } cstate;

typedef struct conn_struct
{
    /* used for in and out connections */
    ssi si;
    sock s;         /* socket once it's connected */
    xstream xs;     /* xml stream */

    /* outgoing connections only */
    int connected;  /* flag for connecting process */
    char *ipp;      /* the ip:port */
    pool p;         /* pool for this struct */
    char *inid      /* the id="" attrib from the other side */
    pool pre;       /* pool for queing activity that happens as soon as the socket is spiffy */

} *conn, _conn;

typedef enum { htype_IN, htype_OUT } htype;

typedef struct host_struct
{
    /* used for in and out connections */
    htype type;     /* type of host, in or out */
    jid id;         /* the funky id for the hashes, to/from */
    int valid;      /* flag if we've been validated */
    ssi si;         /* instance tracker */

    /* outgoing connections only */
    conn c;         /* the ip we're connected on */
    pth_msgport_t queue; /* pre-validated write queue */

    /* incoming connections */
    sock s;         /* the incoming connection that we're associated with */

} *host, _host;

/* msgport wrapper struct to deliver dpackets to a queue */
typedef struct
{
    pth_message_t head; /* the standard pth message header */
    dpacket p;
} _dpq, *dpq;


/* process xml from a socket we made */
void pthsock_server_outx(int type, xmlnode x, void *arg)
{
    sock c=(sock)arg;

    switch(type)
    {
    case XSTREAM_ROOT:
        /* XXX write stream header */
        c->connected = 1;
        pool_free(c->pre); /* flag that we're clear-to-send */
        break;
    case XSTREAM_NODE:
        if( /* db:result */)
        { /*
            host = ghash_get(si->hashout)
            if(host->outconn != us)
                log_notice and drop?
            host->valid = 1
            empty host->queue onto the wire */
            break;
        }
        if(/* db:verify */)
        { /*
            if(ghash_get(si->hashout) && that->outconn == us)
                were getting a verify with invalid to/from, drop conn
            host = ghash_get(si->hashin)
            if(host == NULL)
                log_notice
            host->valid = 1;
            write(host->sock */
            break;
        }
        /* other data on the stream? */
    case XSTREAM_ERR:
        break;
    case XSTREAM_CLOSE:
        break;
    }
    xmlnode_free(x);
}

/* callback for io_select for connections we've made */
void pthsock_server_outread(sock s, char *buffer, int bufsz, int flags, void *arg)
{
    conn c = (conn)arg;

    switch(flags)
    {
    case IO_INIT:
        break; /* umm.. who cares? */
    case IO_NEW: /* new socket from io_select */
        log_debug(ZONE,"NEW outgoing server socket connected at %d",s->fd);
        c->xs = xstream_new(c->p, pthsock_server_outx, (void *)c);
        c->s = s;
        break;
    case IO_NORMAL:
        /* yum yum */
        xstream_eat(c->xs,buffer,bufsz);
        break;
    case IO_CLOSED:
        /* if we were connected, just free ourselves and be done */
        if(c->connected)
        {
            pool_free(c->p);
            return;
        }
        if(!c->connected && /* XXX ip's left */)
        { /* if we've never connected yet, then try another ip:port in the list (if any) */
            /* XXX do */
            return;
        }
        /* hrm, we're here, so this means we're giving up on connecting */
        /* XXX give up! */
        break;
    case IO_ERROR:
        /* bounce the write queue */
    }
}

/* process xml from an accept'd socket */
void pthsock_server_inx(int type, xmlnode x, void *arg)
{
    sock c=(sock)arg;

    switch(type)
    {
    case XSTREAM_ROOT:
        /* send stream header w/ random id="challenge" */
        break;
    case XSTREAM_NODE:
        if( /* db:result */)
        { /*
            new host, valid=0, cleanup on inconn pool to take out of ghash
            ghash_put si->hashin
            forward verify into deliver, going back to sender on outconn */
            return;
        }
        if( /* db:verify */)
        {
            /* send response */
            return
        }
        host = ghash_get(si->hashin);
        if(host->valid && host->s == us)
        {
            send
        }else{
            drop connection
        }
        break;
    case XSTREAM_ERR:
        break;
    case XSTREAM_CLOSE:
        break;
    }
    xmlnode_free(x);
}

/* callback for io_select for accepted sockets */
void pthsock_server_inread(sock s, char *buffer, int bufsz, int flags, void *arg)
{
    conn c = (conn)arg;

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
        /* we don't care, pools will clean themselves up */
        break;
    case IO_ERROR:
        /* we don't care, we don't ever write real packets to an incoming connection! */
        break;
    }
}

/* send the db:result to the other side, can be called as a pool_cleanup or directly, reacts intelligently */
void _pthsock_server_host_result(void *arg)
{
    host h = (host)arg;

    /* XXX need to check and make sure the socket quitting */

    if(!h->c->connected)
    {
        pool_cleanup(h->c->pre, _pthsock_server_host_result, arg);
        return;
    }

    /* XXX generate the result */
    /* write to the socket */
}

/* send the db:verify to the other side, can be called as a pool_cleanup or directly, reacts intelligently */
void _pthsock_server_host_verify(void *arg)
{
    dpacket p = (dpacket)arg;
    conn c = xmlnode_get_vattrib(p->x,"c"); /* hidden c on the xmlnode */

    /* XXX need to check and make sure the socket quitting */

    if(!c->connected)
    {
        pool_cleanup(c->pre, _pthsock_server_host_verify, arg);
        return;
    }

    xmlnode_hide_attrib(p->x,"c"); /* hide it again */
    /* XXX write to the socket */
}

/* phandler callback, send packets to another server */
result pthsock_server_packets(instance id, dpacket dp, void *arg)
{
    ssi si = (ssi) arg;
    pool p;
    xmlnode x;
    jid to, from, id;
    host h;
    conn c;
    char *ip, *colon;
    int port = 5269;
    dpq q;

    if(dp->type != p_ROUTE || (x = xmlnode_get_firstchild(dp->x)) == NULL || (to = jid_new(dp->p,xmlnode_get_attrib(x,"to"))) == NULL || (from = jid_new(dp->p,xmlnode_get_attrib(x,"from"))) == NULL || (ip = xmlnode_get_attrib(dp->x,"ip")) == NULL)
    {
        log_notice(dp->host,"Dropping invalid outbound packet: %s",xmlnode2str(dp->x));
        xmlnode_free(dp->x);
        return r_DONE;
    }

    /* make this special id for the hash */
    id = jid_new(dp->p,to->server);
    jid_set(id,from->server,JID_RESOURCE);

    /* get the host if there's already one */
    if((h = (host)ghash_get(si->hosts,jid_full(id))) == NULL)
    {
        /* if there's already a connection to this ip, reuse it */
        if((c = (conn)ghash_get(si->ips,ip)) == NULL)
        {
            /* new conn struct */
            p = pool_new();
            c = pmalloco(p, sizeof(_conn));
            c->ips = pstrdup(p,ip);
            c->p = p;
            c->si = si;
            c->pre_ok = pool_new();
            /* get the ip/port for io_select */
            char *colon=strchr(ip,':');
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
        h->id = jid_new(c->p,jid_full(id));

        /* send result */
        _pthsock_server_host_result((void *)h);
    }

    if(h->valid)
    {
        /* XXX write the packet to the socket, it's safe */
        return r_DONE;
    }

    if( /* XXX it's not a db:verify */ )
    {
        if(h->mp == NULL)
            h->mp = pth_msgport_create(jid_full(id));

        q = pmalloco(dp->p, sizeof(_dpq));
        q->dp = dp;
        pth_msgport_put(h->mp,dp);
        return r_DONE;
    }

    /* all we have left is db:verify packets */
    xmlnode_put_vattrib(p->x,"c",(void *)c); /* ugly, but hide the c on the xmlnode */
    _pthsock_server_host_verify((void *)p);

    return r_DONE;
}


/* everything starts here */
void pthsock_server(instance i, xmlnode x)
{
    ssi si;

    log_debug(ZONE,"pthsock_server loading");

    /* XXX make the hash sizes configurable */
    si = pmalloco(i->p,sizeof(_ssi));
    si->ips = ghash_create(67,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp); /* keys are "ip:port" */
    si->hosts = ghash_create(67,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp); /* keys are jids: "id@to/from" */
    si->i=i;

    /* XXX make configurable rate limits */
    io_select_listen(5269,NULL,pthsock_server_inread,(void*)si,5,25);
    register_phandler(i,o_DELIVER,pthsock_server_packets,(void*)si);
}
