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


/************************ OBJECTS ****************************/

/* s2s instance */
typedef struct ssi_struct
{
    instance i;
    HASHTABLE ips; /* hash table of all dialback capable outgoing sockets to ip:port addresses */
    HASHTABLE hosts; /* hash table of all host structures, in and out, key@to/from format */
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
    dpacket p;
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

    if(valid)
    {
        h->valid = 1;
        if(h->mp != NULL)
        {
            /* dequeue and send the waiting packets */
            while((q = (dpq)pth_msgport_get(h->mp)) != NULL)
                io_write(h->c->s,q->p->x);
            pth_msgport_destroy(h->mp);
            h->mp = NULL;
        }
        return;
    }

    /* invalid host, clean up and dissappear! */

    if(h->mp != NULL)
    {
        /* dequeue and bounce the waiting packets */
        while((q = (dpq)pth_msgport_get(h->mp)) != NULL)
            deliver_fail(q->p,NULL);
        pth_msgport_destroy(h->mp);
        h->mp = NULL;
    }

    /* remove from hash */
    ghash_remove(h->si->hosts,h->id);
}

/* called when the host goes bye bye */
void _pthsock_server_host_cleanup(void *arg)
{
    host h = (host)arg;
    /* this function cleans up for us as if it were invalid */
    _pthsock_server_host_validated(0,h);
}

/* send the db:result to the other side, can be called as a failure (from pool_cleanup) or directly to queue the result, reacts intelligently */
void _pthsock_server_host_result(void *arg)
{
    host h = (host)arg;
    xmlnode x;

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
        xmlnode_insert_cdata(x,  shahash( spools(xmlnode_pool(x),shahash( spools(xmlnode_pool(x),shahash(h->si->secret),h->id->server,xmlnode_pool(x)) ),h->c->id,xmlnode_pool(x)) ), -1);
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

    switch(type)
    {
    case XSTREAM_ROOT:
        /* check for old servers */
        if(xmlnode_get_attrib(x,"xmlns:db") == NULL)
        {
            if(!c->si->legacy)
            { /* Muahahaha!  you suck! *click* */
                io_write_str(c->s,"<stream:error>Legacy Access Denied!</stream:error>");
                io_close(c->s);
                break;
            }
            c->legacy = 1;
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
                log_notice(c->legacy_to,"Received illegal dialback validation from %s to %s",xmlnode_get_attrib(x,"from"),xmlnode_get_attrib(x,"to"));
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
                log_notice(c->legacy_to,"Received illegal dialback verification from %s to %s",xmlnode_get_attrib(x,"from"),xmlnode_get_attrib(x,"to"));
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

    switch(flags)
    {
    case IO_INIT:
        break; /* umm.. who cares? */
    case IO_NEW: /* new socket from io_select */
        log_debug(ZONE,"NEW outgoing server socket connected at %d",s->fd);
        c->xs = xstream_new(c->p, pthsock_server_outx, (void *)c);
        c->s = s;

        /* outgoing conneciton, write the header */
        x = xstream_header("jabber:server", NULL, c->legacy_to);
        xmlnode_put_attrib(x,"xmlns:db","jabber:server:dialback"); /* flag ourselves as dialback capable */
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
            c->ips = pstrdup(c->p,c->ipn);
            c->ipn = strchr(c->ips,',');
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
            c->ipn = strchr(c->ips,',');
            if(c->ipn != NULL)
            { /* chop off this ip if there is another, track the other */
                *c->ipn = '\0';
                c->ipn++;
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
        h->id = jid_new(c->p,jid_full(id));
        ghash_put(si->hosts,h->id,h); /* register us */
        pool_cleanup(c->p,_pthsock_server_host_cleanup,(void *)h); /* make sure things get put back to normal afterwards */
        _pthsock_server_host_result((void *)h); /* try to send result to the other side */
    }

    /* write the packet to the socket, it's safe */
    if(h->valid)
    {
        io_write(h->c->s, dp->x);
        return r_DONE;
    }

    if(j_strcmp(xmlnode_get_name(dp->x),"db:verify") != 0)
    {
        if(h->mp == NULL)
            h->mp = pth_msgport_create(jid_full(id));

        q = pmalloco(dp->p, sizeof(_dpq));
        q->p = dp;
        pth_msgport_put(h->mp,(pth_message_t *)q);
        return r_DONE;
    }

    /* all we have left is db:verify packets */
    xmlnode_put_vattrib(dp->x,"c",(void *)c); /* ugly, but hide the c on the xmlnode */
    _pthsock_server_host_verify((void *)(dp->x));

    return r_DONE;
}


/************************ INCOMING CONNECTIONS ****************************/

/* process xml from an accept'd socket */
void pthsock_server_inx(int type, xmlnode x, void *arg)
{
    conn c = (conn)arg;
    xmlnode x2;
    host h;

    switch(type)
    {
    case XSTREAM_ROOT:
        /* new incoming connection sent a header, write our header */
        x2 = xstream_header("jabber:server", xmlnode_get_attrib(x,"to"), NULL);
        xmlnode_put_attrib(x2,"xmlns:db","jabber:server:dialback"); /* flag ourselves as dialback capable */
        c->id = pstrdup(c->p,_pthsock_server_randstr());
        xmlnode_put_attrib(x2,"id",c->id); /* send random id as a challenge */
        io_write_str(c->s,xstream_header_char(x2));
        xmlnode_free(x2);

        if(xmlnode_get_attrib(x,"xmlns:db") == NULL)
        {
            if(c->si->legacy)
            {
                c->legacy = 1;
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
            jutil_tofrom(x);
            if(j_strcmp( xmlnode_get_data(x), shahash( spools(xmlnode_pool(x), shahash( spools(xmlnode_pool(x),shahash(c->si->secret),xmlnode_get_attrib(x,"from"),xmlnode_pool(x))), c->id,xmlnode_pool(x)))) == 0)
                xmlnode_put_attrib(x,"type","valid");
            else
                xmlnode_put_attrib(x,"type","invalid");
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
            xmlnode_insert_node(x2,xmlnode_get_firstchild(x)); /* copy in any children */
            deliver(dpacket_new(x2),c->si->i);

            return;
        }

        /* hmm, incoming packet on dialback line, there better be a host for it or else! */
        h = ghash_get(c->si->hosts, spools(xmlnode_pool(x),c->id,"@",xmlnode_get_attrib(x,"to"),"/",xmlnode_get_attrib(x,"from"),xmlnode_pool(x)));
        if(h == NULL || !h->valid || h->c != c)
        { /* dude, what's your problem!  *click* */
            io_write_str(c->s,"<stream:error>Invalided Packets Recieved!</stream:error>");
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


/*** everything starts here ***/

void pthsock_server(instance i, xmlnode x)
{
    ssi si;
    xmlnode cfg;

    log_debug(ZONE,"pthsock_server loading");
    srand(time(NULL));

    /* get the config */
    cfg = xdb_get(xdb_cache(i),NULL,jid_new(xmlnode_pool(x),"config@-internal"),"jabber:config:pth-csock");

    si = pmalloco(i->p,sizeof(_ssi));
    si->ips = ghash_create(j_atoi(xmlnode_get_attrib(cfg,"prime"),67),(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp); /* keys are "ip:port" */
    si->hosts = ghash_create(j_atoi(xmlnode_get_attrib(cfg,"prime"),67),(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp); /* keys are jids: "id@to/from" */
    si->i = i;
    si->secret = xmlnode_get_attrib(cfg,"secret");
    if(si->secret == NULL) /* if there's no configured secret, make one on the fly */
        si->secret = pstrdup(i->p,_pthsock_server_randstr());
    if(xmlnode_get_attrib(cfg,"legacy") != NULL)
        si->legacy = 1;

    /* XXX make configurable rate limits */
    io_select_listen(j_atoi(xmlnode_get_attrib(cfg,"port"),5269),NULL,pthsock_server_inread,(void*)si,5,25);
    register_phandler(i,o_DELIVER,pthsock_server_packets,(void*)si);

    xmlnode_free(cfg);
}
