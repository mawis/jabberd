
/* cleans up the host (removes from hashes) */
void dbhost_cleanup(void *arg); 

/* is called when the dbip gets connected, to send a result or verify packet */
void dbhost_sendspecial(void *arg);

/* sends packet out (or bounces or drops) */
result pthsock_server_packets(instance i, dpacket dp, void *arg)
{
    ssi si = (ssi) arg;
    dbhost h;
    dbip ip;
    jid to, from;
    xmlnode x;

    /* unwrap the route packet */
    x = xmlnode_get_firstchild(dp->x);

    to = jid_new(dp->p,xmlnode_get_attrib(x,"to"));
    from = jid_new(dp->p,xmlnode_get_attrib(x,"from"));
    jid_set(id,NULL,JID_USER);

    get the id
    host = ghash_get(si->hashout,id)
    if(host == NULL)
        ip = ghash_get(si->haship,ip);
        if(ip == NULL)
            new ip
            connect(ip)
        new host
        cleanup when ip dies
        ghash_put
        if ip->state != state_OK
            cleanup when ip->pre_ok to generate and send a db:result
        else
            send db:result

    if(host->valid)
        send to host->ip->sock
        return;

    if packet is a db:verify
        if(host->ip->state != state_OK)
            cleanup when ip->pre_ok to generate and send the packet
        else
            send db:verify on
    else
        queue

}

outconn_read
    if(db:result)
        host = ghash_get(si->hashout)
        if(host->outconn != us)
            log_notice and drop?
        host->valid = 1
        empty host->queue onto the wire
    if(db:verify)
        if(ghash_get(si->hashout) && that->outconn == us)
            were getting a verify with invalid to/from, drop conn
        host = ghash_get(si->hashin)
        if(host == NULL)
            log_notice
        host->valid = 1;
        write(host->sock

inconn_read
    if(db:result)
        new host, valid=0, cleanup on inconn pool to take out of ghash
        ghash_put si->hashin
        forward verify into deliver, going back to sender on outconn
        return
    if(db:verify)
        send response
        return
    host = ghash_get(si->hashin)
    if host->valid && host->s == us
        send
    else
        drop connection

hashtable keys: id@to/from

UGH, handle multiple inconns from the same to/from, other side is multiple nodes on a farm

A->B
    A: <db:result to=B from=A>...</db:result>
B->A
    B: <db:verify to=A from=B id=asdf>...</db:verify>
    A: <db:verify type="valid" to=B from=A id=asdf/>
A->B
    B: <db:result type="valid" to=A from=B/>


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
    cstate state;
    char *ipp;      /* the ip:port */
    sock s;         /* socket once it's connected */
    pool p;         /* pool for this struct */
    pool pre_ok;    /* pool for queing activity that happens as soon as the socket is spiffy */
} *conn, _conn;

typedef enum { htype_IN, htype_OUT } htype;

typedef struct host_struct
{
    /* used for in and out connections */
    ssi i;
    htype type;     /* type of host, in or out */
    jid id;         /* the funky id for the hashes, to/from */
    char *to;       /* who we're connected to (out), or who we are (in) */
    char *from;     /* reverse of to :) */
    int valid;      /* flag if we've been validated */
    ssi si;         /* instance tracker */

    /* outgoing connections only */
    dbip ip;        /* the ip we're connected on */
    pth_msgport_t queue; /* pre-validated write queue */

    /* incoming connections */
    sock s;         /* the incoming connection that we're associated with */

} *host, _host;


/* process xml from an accept'd socket */
void pthsock_server_inx(int type, xmlnode x, void *arg)
{
    sock c=(sock)arg;

    switch(type)
    {
    case XSTREAM_ROOT:
        break;
    case XSTREAM_NODE:
        break;
    case XSTREAM_ERR:
        break;
    case XSTREAM_CLOSE:
        break;
    }
    xmlnode_free(x);
}

/* process xml from a socket we made */
void pthsock_server_outx(int type, xmlnode x, void *arg)
{
    sock c=(sock)arg;
    sdata sd = (sdata)c->arg;
    xmlnode h;
    jid j;
    char *block, *to;

    switch(type)
    {
    case XSTREAM_ROOT:
        if(sd->type==conn_OUT) /* if this is an outgoing conn */
        {
            wbq q;
            /* that means we got the other stream header,
             * dump the queue, and continue like normal */
            while((q=(wbq)pth_msgport_get(sd->queue))!=NULL)
                io_write(c,q->x);
            pth_msgport_destroy(sd->queue); /* no longer used after this */
            sd->queue=NULL;
            xmlnode_free(x);
            break;
        }
        if(j_strcmp(xmlnode_get_attrib(x,"xmlns"),"jabber:server")!=0)
        { /* if they sent something other than jabber:client */
            io_write_str(c,"<stream:error>Invalid Namespace</stream:error>");
            io_close((sock)sd->arg);
            sd->type = conn_CLOSED;   /* why you tawkin' gibberish?  */
            xmlnode_free(x);
            break;
        }

        if(xmlnode_get_attrib(x,"xmlns:etherx")==NULL&& /* verify header */
           xmlnode_get_attrib(x,"etherx:secret")==NULL)
        {
            to=xmlnode_get_attrib(x,"to");
            if(sd->to==NULL)
                sd->to=pstrdup(c->p,to);
            if(to==NULL)
            {
                io_write_str(c,"<stream:error>You didn't send your to='host' attribute.</stream:error>");
                io_close(c);
                sd->type = conn_CLOSED;
            }
            else
            { /* header is okay, send our header */
                h=xstream_header("jabber:server",NULL,to);
                block = xstream_header_char(h);
                io_write_str(c,block);
                xmlnode_free(h);
            }
        }
        else
        { /* don't allow stupid 1.0 transports */
            io_write_str(c,"<stream:error>Transport Access is Denied</stream:error>");
            io_close((sock)sd->arg);
            sd->type = conn_CLOSED;   /* it wants to be a transport, to bad */
        }
        xmlnode_free(x);
        break;
    case XSTREAM_NODE:
        if(sd->type==conn_OUT)
        { /* don't allow incoming data on an outgoing conn */
            log_debug(ZONE,"Outgoing connection tried to receive data!");
            io_write_str(c,"<stream:error>This connection does not accept incoming data</stream:error>");
            xmlnode_free(x);
            break;
        }

        /* kill the annoying bits */
        xmlnode_hide_attrib(x,"etherx:from");
        xmlnode_hide_attrib(x,"etherx:to");
        xmlnode_hide_attrib(x,"sto");
        xmlnode_hide_attrib(x,"sfrom");
        xmlnode_hide_attrib(x,"ip");

        /* make sure we don't get packets on an incoming connection */
        /* that are destined for a connection we have established */
        /* as outgoing.. this is to fix a looping issue */
        j=jid_new(xmlnode_pool(x),xmlnode_get_attrib(x,"to"));
        if(j!=NULL)c=ghash_get(sd->i->out_tab,j->server);
        if(c==NULL)
        {
            deliver(dpacket_new(x),sd->i->i);
        }
        else
        { /* wierd DNS issue.. we connected to ourselves! */
            deliver_fail(dpacket_new(x),"External Server Error");
        }
        break;
    case XSTREAM_ERR:
        log_debug(ZONE,"Bad XML: %s",xmlnode2str(x));
        io_write_str(c,"<stream:error>You sent malformed XML</stream:error>");
    case XSTREAM_CLOSE:
        /* they closed there connections to us */
        log_debug(ZONE,"closing XML stream to %d",sd->to);
        io_close(c);
        xmlnode_free(x);
    }
}

/* callback for io_select for connections we've made */
void pthsock_server_outread(sock c,char *buffer,int bufsz,int flags,void *arg)
{
    ssi si=(ssi)arg;
    sdata sd;
    wbq q;
    int ret;

    switch(flags)
    {
    case IO_INIT:
        break; /* umm.. who cares? */
    case IO_NEW: /* new socket from io_select */
        log_debug(ZONE,"NEW server socket connected at %d",c->fd);
        sd=(sdata)c->arg;
        if(sd==NULL)
        { /* if this is an incoming connection, there is no sdata */
            sd = pmalloco(c->p, sizeof(_sdata));
            sd->type=conn_IN;
            sd->arg=(void*)c;
            c->arg=(void*)sd;
            sd->i = si;
        }
        else 
        {   /* we already have an sdata for outgoing conns  */
            /* once we made the connection, send the header */
            xmlnode x=xstream_header("jabber:server",sd->to,NULL);
            /* notify jabberd's deliver to send us */
            /* packets to this host                */
            log_debug(ZONE,"Created outgoing socket type: %d",c->type);
            register_instance(si->i,sd->to);
            sd->arg=(void*)c;
            io_write_str(c,xstream_header_char(x));
            xmlnode_free(x);
            sd->type=conn_OUT;
        }
        /* create the xstream for the socket */
        c->xs = xstream_new(c->p,(void*)pthsock_server_in,(void*)c);
        break;
    case IO_NORMAL:
        /* yum yum */
        ret=xstream_eat(c->xs,buffer,bufsz);
        break;
    case IO_CLOSED:
        /* called JUST BEFORE the socket pool is freed 
         * after this, the sdata is invalid so clean up! */
        sd=(sdata)c->arg;
        if (sd->type == conn_OUT)
        { /* we no longer have an outgoing conn to this server */
            ghash_remove(si->out_tab,sd->to);
            unregister_instance(si->i,sd->to);
        }
        sd->type=conn_CLOSED;
        /* if this is outgoing connection, we will have a pool to free */
        if(sd->p!=NULL)pool_free(sd->p);
        break;
    case IO_ERROR:
        /* bounce the write queue */
        /* check the sock queue */
        sd=(sdata)c->arg;
        log_debug(ZONE,"Socket Error to host %s, bouncing queue",sd->to);
        if(c->xbuffer!=NULL)
        { /* if there is an xbuffer, there is one or more waiting packet to write */
            if(((int)c->xbuffer)!=-1)
                deliver_fail(dpacket_new(c->xbuffer),"External Server Error");
            else pool_free(c->pbuffer);
            c->xbuffer=NULL;
            c->wbuffer=c->cbuffer=NULL;
            c->pbuffer=NULL;
            /* xbuffer is just the first one, the rest are on the mp */
            while((q=(wbq)pth_msgport_get(c->queue))!=NULL)
            {
                if(q->type==queue_XMLNODE)
                {
                    deliver_fail(dpacket_new(q->x),"External Server Error");
                } else pool_free(q->p);
            }
        }
        /* as well as our pre connected queue */
        if(sd->queue!=NULL)
            while((q=(wbq)pth_msgport_get(sd->queue))!=NULL)
                deliver_fail(dpacket_new(q->x),"External Server Error");
    }
}

/* callback for io_select for accepted sockets */
void pthsock_server_inread(sock c,char *buffer,int bufsz,int flags,void *arg)
{
    ssi si=(ssi)arg;
    sdata sd;
    wbq q;
    int ret;

    switch(flags)
    {
    case IO_INIT:
        break; /* umm.. who cares? */
    case IO_NEW: /* new socket from io_select */
        log_debug(ZONE,"NEW server socket connected at %d",c->fd);
        sd=(sdata)c->arg;
        if(sd==NULL)
        { /* if this is an incoming connection, there is no sdata */
            sd = pmalloco(c->p, sizeof(_sdata));
            sd->type=conn_IN;
            sd->arg=(void*)c;
            c->arg=(void*)sd;
            sd->i = si;
        }
        else 
        {   /* we already have an sdata for outgoing conns  */
            /* once we made the connection, send the header */
            xmlnode x=xstream_header("jabber:server",sd->to,NULL);
            /* notify jabberd's deliver to send us */
            /* packets to this host                */
            log_debug(ZONE,"Created outgoing socket type: %d",c->type);
            register_instance(si->i,sd->to);
            sd->arg=(void*)c;
            io_write_str(c,xstream_header_char(x));
            xmlnode_free(x);
            sd->type=conn_OUT;
        }
        /* create the xstream for the socket */
        c->xs = xstream_new(c->p,(void*)pthsock_server_in,(void*)c);
        break;
    case IO_NORMAL:
        /* yum yum */
        ret=xstream_eat(c->xs,buffer,bufsz);
        break;
    case IO_CLOSED:
        /* called JUST BEFORE the socket pool is freed 
         * after this, the sdata is invalid so clean up! */
        sd=(sdata)c->arg;
        if (sd->type == conn_OUT)
        { /* we no longer have an outgoing conn to this server */
            ghash_remove(si->out_tab,sd->to);
            unregister_instance(si->i,sd->to);
        }
        sd->type=conn_CLOSED;
        /* if this is outgoing connection, we will have a pool to free */
        if(sd->p!=NULL)pool_free(sd->p);
        break;
    case IO_ERROR:
        /* bounce the write queue */
        /* check the sock queue */
        sd=(sdata)c->arg;
        log_debug(ZONE,"Socket Error to host %s, bouncing queue",sd->to);
        if(c->xbuffer!=NULL)
        { /* if there is an xbuffer, there is one or more waiting packet to write */
            if(((int)c->xbuffer)!=-1)
                deliver_fail(dpacket_new(c->xbuffer),"External Server Error");
            else pool_free(c->pbuffer);
            c->xbuffer=NULL;
            c->wbuffer=c->cbuffer=NULL;
            c->pbuffer=NULL;
            /* xbuffer is just the first one, the rest are on the mp */
            while((q=(wbq)pth_msgport_get(c->queue))!=NULL)
            {
                if(q->type==queue_XMLNODE)
                {
                    deliver_fail(dpacket_new(q->x),"External Server Error");
                } else pool_free(q->p);
            }
        }
        /* as well as our pre connected queue */
        if(sd->queue!=NULL)
            while((q=(wbq)pth_msgport_get(sd->queue))!=NULL)
                deliver_fail(dpacket_new(q->x),"External Server Error");
    }
}

/* phandler callback, send packets to another server */
result pthsock_server_packets(instance id, dpacket dp, void *arg)
{
    ssi si = (ssi) arg;
    pool p;
    sdata sd;
    char *ip;
    wbq q;
    jid from,to;

    ip=xmlnode_get_attrib(dp->x,"ip"); /* look for ip="12.34.56.78:5269" header */ 

    /* we don't care about the route header, just the meat */
    if(dp->type==p_ROUTE && (dp->xmlnode_get_firstchild(dp->x)!=NULL)
        dp->x=xmlnode_get_firstchild(dp->x);
    else if(dp->type==p_ROUTE) /* ie has no child */
    { /* bad route packet */
        log_notice(si->i->id,"Dropping Invalid Incoming packet: %s",xmlnode2str(dp->x));
        xmlnode_free(dp->x);
        return r_DONE;
    }

    /* maybe the ip is on the internal packet? */
    if(ip==NULL) ip=xmlnode_get_attrib(dp->x,"ip"); /* look for ip="12.34.56.78:5269" header */ 

    /* get real to and from */
    to=jid_new(xmlnode_pool(dp->x),xmlnode_get_attrib(dp->x,"to"));
    from=jid_new(xmlnode_pool(dp->x),xmlnode_get_attrib(dp->x,"from"));

    if(to==NULL)
    { /* uh oh! no to.. this cored the server once */
        log_notice(si->i->id,"Dropping Invalid Incoming packet: %s",xmlnode2str(dp->x->parent));
        xmlnode_free(dp->x);
        return r_DONE;
    }

    if(ip!=NULL)
    { /*grab the IP and port */
        char *colon=strchr(ip,':');
        if(colon==NULL) 
            port=5269;
        else
        {
            colon[0]='\0';
            colon++;
            port=atoi(colon);
        }
    }
    else
    { /*else, we lookup ourselves*/
        ip=to->server;
        port=5269;
    }

    log_debug(ZONE,"pthsock_server connecting to %s",ip);

    /* etherx header crap for 1.0 compatibily */
    if (from)
        xmlnode_put_attrib(dp->x,"etherx:from",from->server);
    xmlnode_put_attrib(dp->x,"etherx:to",to->server);

    /* find our outgoing conn to this server */
    sd = ghash_get(si->out_tab,to->server);

    if (sd != NULL) /* make sure we found a valid outgoing socket */
        if ((sd->type!=conn_OUT&&sd->type!=conn_CONNECTING)||sd->arg==NULL||((sock)sd->arg)->state!=state_ACTIVE)
            sd = NULL; /* nope it's not really valid */

    q=pmalloco(dp->p,sizeof(_wbq));
    q->x=dp->x;
    /* hide the header crap */
    xmlnode_hide_attrib(q->x,"sto");   /* XXX can we kill these yet? */
    xmlnode_hide_attrib(q->x,"sfrom"); /* XXX can we kill these yet? */
    xmlnode_hide_attrib(q->x,"ip");
    xmlnode_hide_attrib(q->x,"iperror");

    /* no current socket found for this host */
    if (sd == NULL)
    {
        log_debug(ZONE,"Creating new connection to %s",to->server);

        /* create the sdata to attach to the new socket */
        p = pool_new();
        sd = pmalloco(p,sizeof(_sdata));
        sd->p=p;
        sd->type = conn_CONNECTING;
        sd->to = pstrdup(p,to->server);
        sd->i = si;
        sd->queue = pth_msgport_create("queue");
        /* add this to our outgoing list, so no more sockets get opened */
        ghash_put(si->out_tab,sd->to,sd);

        /* pop on the queue, and spawn a connection thread */
        pth_msgport_put(sd->queue,(void*)q);
        io_select_connect(ip,port,(void*)sd,pthsock_server_read,(void*)si);
        return r_DONE;
    }

    /* if we haven't connected fully, write to the temp queue */
    if(sd->type==conn_CONNECTING)
        pth_msgport_put(sd->queue,(void*)q);
    else if(sd->type==conn_OUT) /* otherwise,just write the sucker */
        io_write((sock)sd->arg,dp->x);

    return r_DONE;
}


/* everything starts here */
void pthsock_server(instance i, xmlnode x)
{
    ssi si;

    log_debug(ZONE,"pthsock_server loading");


    si = pmalloco(i->p,sizeof(_ssi));
    si->out_tab = ghash_create(20,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);
    si->i=i;

    /* XXX make configurable rate limits */
    io_select_listen(5269,NULL,pthsock_server_inread,(void*)si,5,25);
    register_phandler(i,o_DELIVER,pthsock_server_packets,(void*)si);
}
