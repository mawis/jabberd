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
 *  Copyright (C) 1998-1999 The Jabber Team http://jabber.org/
 */

/*
  <service id="127.0.0.1 s2s">
    <host/>
    <load main="pthsock_server">
      <pthsock_server>../load/pthsock_server.so</pthsock_server>
    </load>
  </service>
*/

#include "io.h"

typedef enum { conn_CONNECTING, conn_IN, conn_OUT, conn_CLOSED } conn_type;
struct sdata_st;
iosi io__instance=NULL;

/* server 2 server instance */
typedef struct ssi_st
{
    instance i;
    HASHTABLE out_tab;
} *ssi, _ssi;

typedef struct sdata_st
{
    ssi i;
    pool p;
    conn_type type;
    pth_msgport_t queue;
    char *to;
    void *arg;
} *sdata, _sdata;

/* recieve data from io_select */
void pthsock_server_in(int type, xmlnode x, void *arg)
{
    sock c=(sock)arg;
    sdata sd = (sdata)c->arg;
    xmlnode h;
    char *block, *to;

    switch(type)
    {
    case XSTREAM_ROOT:
        if(sd->type==conn_IN)
        {
            if(xmlnode_get_attrib(x,"xmlns:etherx")==NULL&&
               xmlnode_get_attrib(x,"etherx:secret")==NULL)
            {
                to=xmlnode_get_attrib(x,"to");
                if(sd->to==NULL)
                    sd->to=pstrdup(c->p,to);
                if(to==NULL)
                {
                    io_write_str(c,"<stream::error>You didn't send your to='host' attribute.</stream:error>");
                    io_close(c);
                    sd->type = conn_CLOSED;
                }
                else
                {
                    h=xstream_header("jabber:server",NULL,to);
                    block = xstream_header_char(h);
                    io_write_str(c,block);
                    xmlnode_free(h);
                }
            }
            else
            {
                io_write_str(c,"<stream::error>Transport Access is Denied</stream:error>");
                io_close((sock)sd->arg);
                sd->type = conn_CLOSED;   /* it wants to be a transport, to bad */
            }
        }
        else
        { /* we finnally connected, dump the queue */
            drop d;
            while((d=(drop)pth_msgport_get(sd->queue))!=NULL)
                io_write(c,d->x);
        }

        xmlnode_free(x);
        break;
    case XSTREAM_NODE:
        if(sd->type==conn_OUT)
        {
            xmlnode h=xmlnode_new_tag("stream:error");
            log_debug(ZONE,"Outgoing connection tried to receive data!");
            xmlnode_insert_cdata(h,"This connection does not accept incoming data",-1);
            io_write(c,h);
            xmlnode_free(x);
            break;
        }
        log_debug(ZONE,"node received for %d",c->fd);

        xmlnode_hide_attrib(x,"etherx:from");
        xmlnode_hide_attrib(x,"etherx:to");

        /* make sure we don't get packets on an incoming connection */
        /* that are destined for a connection we have established */
        /* as outgoing.. this is to fix a looping issue */
        c=ghash_get(sd->i->out_tab,(jid_new(xmlnode_pool(x),xmlnode_get_attrib(x,"to")))->server);
        if(c==NULL)
        {
            deliver(dpacket_new(x),sd->i->i);
        }
        else
        {
            jutil_error(x,TERROR_EXTERNAL);
            deliver(dpacket_new(x),sd->i->i);
        }
        break;
    case XSTREAM_ERR:
        log_debug(ZONE,"failed to parse XML for %d",c->fd);
        io_write_str(c,"<stream::error>You sent malformed XML</stream:error>");
    case XSTREAM_CLOSE:
        /* they closed there connections to us */
        log_debug(ZONE,"closing XML stream for %d",c->fd);
        io_close(c);
        xmlnode_free(x);
    }
}


void pthsock_server_read(sock c,char *buffer,int bufsz,int flags,void *arg)
{
    ssi si=(ssi)arg;
    sdata sd;
    drop d;
    wbq q;
    int ret;

    switch(flags)
    {
    case IO_INIT:
        log_debug(ZONE,"io_select INIT event");
        break;
    case IO_NEW:
        log_debug(ZONE,"io_select NEW socket connected at %d",c->fd);
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
        { /* we already have an sdata for outgoing conns */
            /* once we made the connection, send the header */
            xmlnode x=xstream_header("jabber:server",sd->to,NULL);
            sd->arg=(void*)c;
            io_write_str(c,xstream_header_char(x));
            xmlnode_free(x);
            sd->type=conn_OUT;
        }
        c->xs = xstream_new(c->p,(void*)pthsock_server_in,(void*)c);
        break;
    case IO_NORMAL:
        log_debug(ZONE,"io_select NORMAL data");
        ret=xstream_eat(c->xs,buffer,bufsz);
        break;
    case IO_CLOSED:
        sd=(sdata)c->arg;
        if (sd->type == conn_OUT)
            ghash_remove(si->out_tab,sd->to);
        /* if this is outgoing connection, we will have a pool to free */
        if(sd->p!=NULL)pool_free(sd->p);
        break;
    case IO_ERROR:
        /* bounce the write queue */
        /* check the sock queue */
        sd=(sdata)c->arg;
        log_debug(ZONE,"Socket Error to host %s, bouncing queue",sd->to);
        if(c->xbuffer!=NULL)
        {
            jutil_error(c->xbuffer,TERROR_EXTERNAL);
            deliver(dpacket_new(c->xbuffer),si->i);
            c->xbuffer=NULL;
            c->wbuffer=c->cbuffer=NULL;
            while((q=(wbq)pth_msgport_get(c->queue))!=NULL)
            {
                jutil_error(q->x,TERROR_EXTERNAL);
                deliver(dpacket_new(q->x),si->i);
            }
        }
        /* as well as our queue */
        while((d=(drop)pth_msgport_get(sd->queue))!=NULL)
        {
            jutil_error(d->x,TERROR_EXTERNAL);
            deliver(dpacket_new(d->x),si->i);
        }
    }
}

result pthsock_server_packets(instance id, dpacket dp, void *arg)
{
    ssi si = (ssi) arg;
    pool p;
    sdata sd;
    char *to;
    drop d;
    jid from;

    to = dp->id->server;
    from = jid_new(xmlnode_pool(dp->x),xmlnode_get_attrib(dp->x,"from"));

    log_debug(ZONE,"pthsock_server looking up %s",to);

    if (from)
        xmlnode_put_attrib(dp->x,"etherx:from",from->server);
    xmlnode_put_attrib(dp->x,"etherx:to",to);

    sd = ghash_get(si->out_tab,to);

    if (sd != NULL)
        if (sd->type == conn_CLOSED)
            sd = NULL;

    d=pmalloco(dp->p,sizeof(_drop));
    d->x=dp->x;

    if (sd == NULL)
    {
        log_debug(ZONE,"Creating new connection to %s",to);

        p = pool_new();
        sd = pmalloco(p,sizeof(_sdata));
        sd->p=p;
        sd->type = conn_CONNECTING;
        sd->to = pstrdup(p,to);
        sd->i = si;
        sd->queue = pth_msgport_create("queue");
        ghash_put(si->out_tab,sd->to,sd);

        io_select_connect(io__instance,to,5269,(void*)sd);
        pth_msgport_put(sd->queue,(void*)d);
        return r_DONE;
    }

    if(sd->type==conn_CONNECTING)
        pth_msgport_put(sd->queue,(void*)d);
    else
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

    io__instance=io_select(5269,pthsock_server_read,(void*)si);
    register_phandler(i,o_DELIVER,pthsock_server_packets,(void*)si);
}
