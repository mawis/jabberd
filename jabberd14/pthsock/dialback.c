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
    char *secret; /* our dialback secret */
    int legacy; /* flag to allow old servers */
} *ssi, _ssi;

typedef enum { cstate_START, cstate_OK } cstate;

typedef struct conn_struct
{
    /* used for in and out connections */
    ssi si;
    sock s;         /* socket once it's connected */
    xstream xs;     /* xml stream */
    int legacy;     /* flag that we're in legacy mode */
    char *id        /* the id="" attrib from the other side or the one we sent */

    /* outgoing connections only */
    int connected;  /* flag for connecting process */
    char *ipp;      /* the ip:port */
    pool p;         /* pool for this struct */
    pool pre;       /* pool for queing activity that happens as soon as the socket is spiffy */
    char *legacy_to /* the to="" hostname for legacy servers */

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
    conn c = (conn)arg;
    host h;
    xmlnode x, x2;
    jid id;

    switch(type)
    {
    case XSTREAM_ROOT:
        /* check for old servers */
        if(xmlnode_get_attrib(x,"xmlns:db") == NULL)
        {
            if(!c->si->legacy)
            { /* Muahahaha!  you suck! *click* */
                io_write_str(c,"<stream:error>Legacy Access Denied!</stream:error>");
                io_close(c);
                break;
            }
            c->legacy = 1;
        }else{
            /* db capable, register in main hash of connected ip's */
            ghash_put(c->si->ips, c->ipp, c);
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
            h = ghash_get(si->hosts,spools(xmlnode_pool(x),xmlnode_get_attrib(x,"from"),"/",xmlnode_get_attrib(x,"to"),xmlnode_pool(x));
            if(h == NULL || h->c != c)
            { /* naughty... *click* */
                log_notice(c->legacy_to,"Received illegal dialback validation from %s to %s",xmlnode_get_attrib(x,"from"),xmlnode_get_attrib(x,"to"));
                io_write_str(c,"<stream:error>Invalid Dialback Result!</stream:error>");
                io_close(c);
                break;
            }

            /* process the returned result */
            if(j_strmcp(xmlnode_get_attrib(x,"type"),"valid") == 0)
                _pthsock_server_host_validated(1,h);
            else
                _pthsock_server_host_validated(0,h);

            break;
        }
        if(j_strcmp(xmlnode_get_name(x),"db:verify") == 0)
        {
            /* first validate that we actually sent it */
            h = ghash_get(si->hosts,spools(xmlnode_pool(x),xmlnode_get_attrib(x,"from"),"/",xmlnode_get_attrib(x,"to"),xmlnode_pool(x));
            if(h == NULL !! h->c != c)
            { /* naughty... *click* */
                log_notice(c->legacy_to,"Received illegal dialback verification from %s to %s",xmlnode_get_attrib(x,"from"),xmlnode_get_attrib(x,"to"));
                io_write_str(c,"<stream:error>Invalid Dialback Verify!</stream:error>");
                io_close(c);
                break;
            }

            /* get the incoming host */
            h = ghash_get(si->hosts,spools(xmlnode_pool(x),xmlnode_get_attrib(x,"id"),"@",xmlnode_get_attrib(x,"to"),"/",xmlnode_get_attrib(x,"from"),xmlnode_pool(x));
            if(h == NULL)
                break; /* musta distapeared */

            /* if they're cool in your book, we'll agree, enable them to send packets */
            if(j_strmcp(xmlnode_get_attrib(x,"type"),"valid") == 0)
                h->valid = 1;

            /* rewrite and forward the result on so they can send packets */
            x2 = xmlnode_new_tag_pool(xmlnode_pool(x),"db:result");
            xmlnode_put_attrib(x2,"to",xmlnode_get_attrib(x,"from"));
            xmlnode_put_attrib(x2,"from",xmlnode_get_attrib(x,"to"));
            xmlnode_put_attrib(x2,"type",xmlnode_get_attrib(x,"type"));
            io_write_str(h->c,xmlnode2str(x2));
            break;
        }
        /* other data on the stream? */
    case XSTREAM_ERR:
    case XSTREAM_CLOSE:
        /* IO cleanup will take care of everything else */
        io_close(c);
        break;
    }
    xmlnode_free(x);
}

/* callback for io_select for connections we've made */
void pthsock_server_outread(sock s, char *buffer, int bufsz, int flags, void *arg)
{
    conn c = (conn)arg;
    xmlnode x;

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
        block = xstream_header_char(x);
        io_write_str(c->s,block);
        xmlnode_free(x);

        break;
    case IO_NORMAL:
        /* yum yum */
        xstream_eat(c->xs,buffer,bufsz);
        break;
    case IO_CLOSED:

        /* remove us if we were advertised */
        ghash_remove(c->si->ips, c->ipp);

        /* if we weren't connected and there's more IP's to try, try them */
        if(c->s == NULL && /* XXX ip's left on the list */)
        {
            /* XXX call connect again w/ the next IP */
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

/* process xml from an accept'd socket */
void pthsock_server_inx(int type, xmlnode x, void *arg)
{
    sock c=(sock)arg;
    xmlnode x2;

    switch(type)
    {
    case XSTREAM_ROOT:
        /* new incoming connection sent a header, write our header */
        x2 = xstream_header("jabber:server", xmlnode_get_attrib(x,"to"), NULL);
        xmlnode_put_attrib(x2,"xmlns:db","jabber:server:dialback"); /* flag ourselves as dialback capable */
        xmlnode_put_attrib(x2,"id",_pthsock_server_randstr()); /* send random id as a challenge */
        block = xstream_header_char(x2);
        io_write_str(c->s,block);
        xmlnode_free(x2);

        if(xmlnode_get_attrib(x,"xmlns:db") == NULL)
            c->legacy_to = pstrdup(c->p,xmlnode_get_attrib(x,"to"));

        break;
    case XSTREAM_NODE:
        if(c->legacy_to != NULL)
        {
            /* XXX legacy mode, just send it on */
            return;
        }

        if(j_strcmp(xmlnode_get_name(x),"db:verify") == 0)
        {
            /* XXX generate new result and verify, send response */
            break;
        }

        if(j_strcmp(xmlnode_get_name(x),"db:result") == 0)
        { /*
            new host, valid=0, cleanup on inconn pool to take out of ghash
            ghash_put si->hashin
            forward verify into deliver, going back to sender on outconn */
            return;
        }
        h = ghash_get(si->hashin);
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

/* flag an outgoing host as valid and dequeue the msgport, can be called to cleanup the host entry as failure */
void _pthsock_server_host_validated(int valid, host h)
{
    if(valid)
    {
        h->valid = 1;
        if(h->mp != NULL)
        {
            /* XXX dequeue and send the waiting packets */
            /* XXX free the mp */
            h->mp = NULL;
        }
        return;
    }

    /* invalid host, clean up and dissappear! */

    if(h->mp != NULL)
    {
        /* dequeue and bounce the waiting packets */
        /* XXX free the mp */
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
    _pthsock_server_host_validate(0,h);
}

/* send the db:result to the other side, can be called as a failure (from pool_cleanup) or directly to queue the result, reacts intelligently */
void _pthsock_server_host_result(void *arg)
{
    host h = (host)arg;

    /* if this is a legacy connect, just validate the host */
    if(h->c->legacy)
    {
        _pthsock_server_host_validate(1,h);
        return;
    }

    /* if we're CTS */
    if(h->c->connected)
    {
        /* XXX generate the result, include the id="" header sent from h->c->id */
        /* write to the socket */
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

    /* send it */
    if(!c->legacy && c->connected)
    {
        xmlnode_hide_attrib(x,"c"); /* hide it again */
        /* XXX write to the socket */
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
    /* XXX send to the incoming conn that generated this */
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
        ghash_put(si->hosts,h->id,h); /* register us */
        pool_cleanup(c->p,_pthsock_server_host_cleanup,(void *)h); /* make sure things get put back to normal afterwards */
        _pthsock_server_host_result((void *)h); /* try to send result to the other side */
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
    _pthsock_server_host_verify((void *)(p->x));

    return r_DONE;
}

/* we need a decently random string in a few places */
char *_pthsock_server_randstr(void)
{
    static char ret[41];

    sprintf(ret,"%d",rand());
    shahash_r(ret,ret);
    return ret;
}

/* everything starts here */
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
