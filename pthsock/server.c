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
    struct sdata_st *conns;
    HASHTABLE out_tab;
    int asock;
} *ssi, _ssi;

typedef struct sdata_st
{
    ssi i;
    pool p;
    conn_type type;
    pth_msgport_t queue;
    char *to;
    struct sdata_st *prev,*next;
    void *arg;
} *sdata, _sdata;

void pthsock_server_close(ssi si, sdata s)
{
    log_debug(ZONE,"closing socket '%d'",((sock)s->arg)->fd);

    if (s->type == conn_OUT)
        ghash_remove(si->out_tab,s->to);

    io_close((sock)s->arg);
    s->type = conn_CLOSED;
}

/* recieve data from io_select */
void pthsock_server_in(int type, xmlnode x, void *arg)
{
    sock c=(sock)arg;
    sdata sd = (sdata)c->arg;
    xmlnode h;
    char *block, *to;

    log_debug(ZONE,"pthsock_server_stream handling packet type %d",type);

    switch(type)
    {
    case XSTREAM_ROOT:
        log_debug(ZONE,"root received for %d",c->fd);
        if(sd->type==conn_IN)
        {
            if(xmlnode_get_attrib(x, "xmlns:etherx") == NULL && xmlnode_get_attrib(x,"etherx:secret") == NULL)
            {
                to=xmlnode_get_attrib(x,"to");
                if(sd->to==NULL)
                {
                    sd->to=pstrdup(c->p,to);
                    ghash_put(sd->i->out_tab,sd->to,sd);
                }
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
                pthsock_server_close(sd->i,sd);
                sd->type = conn_CLOSED;   /* it wants to be a transport, to bad */
            }
        }

        xmlnode_free(x);
        break;
    case XSTREAM_NODE:
        log_debug(ZONE,"node received for %d",c->fd);

        xmlnode_hide_attrib(x,"etherx:from");
        xmlnode_hide_attrib(x,"etherx:to");

        deliver(dpacket_new(x),sd->i->i);
        break;

    case XSTREAM_ERR:
        log_debug(ZONE,"failed to parse XML for %d",c->fd);
        io_write_str(c,"<stream::error>You sent malformed XML</stream:error>");
    case XSTREAM_CLOSE:
        /* they closed there connections to us */
        log_debug(ZONE,"closing XML stream for %d",c->fd);
        pthsock_server_close(sd->i,sd);
    }
}


void pthsock_server_read(sock c,char *buffer,int bufsz,int flags,void *arg)
{
    ssi si=(ssi)arg;
    sdata sd;
    int ret;

    if(c!=NULL){
     log_debug(ZONE,"io_select read event on %d:%d:%d,[%s]",c->fd,flags,bufsz,buffer);}
    else{
     log_debug(ZONE,"io_select read event with flag: %d",flags);}

    switch(flags)
    {
    case IO_INIT:
        log_debug(ZONE,"io_select INIT event");
        break;
    case IO_NEW:
        log_debug(ZONE,"io_select NEW socket connected at %d",c->fd);
        sd=(sdata)c->arg;
        if(sd==NULL)
        {
            sd = pmalloco(c->p, sizeof(_sdata));
            sd->type=conn_IN;
            sd->arg=(void*)c;
            c->arg=(void*)sd;
            sd->i = si;
            if(si->conns!=NULL) si->conns->prev=sd;
            sd->next = si->conns;
            si->conns = sd;
        }
        else 
        {
            drop d;
            sd->type=conn_OUT;
            while((d=(drop)pth_msgport_get(sd->queue))!=NULL)
                io_write(c,d->x);
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
        if(sd==si->conns) si->conns=si->conns->next;
        if(sd->next!=NULL) sd->next->prev=sd->prev;
        if(sd->prev!=NULL) sd->prev->next=sd->next;
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
