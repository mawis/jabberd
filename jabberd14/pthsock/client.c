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
    <service id="pthsock client">
      <host>pth-csock.127.0.0.1</host> <!-- Can be anything -->
      <load>
	    <pthsock_client>../load/pthsock_client.so</pthsock_client>
      </load>
      <pthcsock xmlns='jabberd:pth-csock:config'>
	    <host>pth-csock.127.0.0.1</host> <!-- our host, from above -->
        <listen>5222</listen>            <!-- Port to listen on -->
      </pthcsock>
    </service>
*/

#include "io.h"
iosi io__instance=NULL;

/* socket manager instance */
typedef struct smi_st
{
    instance i;
    xmlnode cfg;
    pth_msgport_t wmp;
    char *host;
} *smi, _smi;

typedef struct cdata_st
{
    smi* i;
    int state;
    char *id, *host, *sid, *res, *auth_id;
    void *arg;
    struct cdata_st *next;
} _cdata,*cdata;

void pthsock_client_close(sock c)
{
    xmlnode x;
    cdata cd=(cdata)c->arg;
    if(cd->state==state_AUTHD)
    {
        x = xmlnode_new_tag("message");
        jutil_error(x,TERROR_DISCONNECTED);
        xmlnode_put_attrib(x,"sto",cd->host);
        xmlnode_put_attrib(x,"sfrom",cd->id);
        deliver(dpacket_new(x),((smi)cd->i)->i);
    }
    log_debug(ZONE,"asking socket to close");
    io_close(c);
}

result pthsock_client_packets(instance id, dpacket p, void *arg)
{
    smi si=(smi)arg;
    cdata cdcur;
    sock cur;
    char *type;
    int fd;

    log_debug(ZONE,"Got a packet from Deliver: %s",xmlnode2str(p->x));

    if (p->id->user == NULL)
    {
        log_debug(ZONE,"NO USER, FREEING PACKET, NOT SENDING");
        xmlnode_free(p->x);
        return r_DONE;
    }

    fd = atoi(p->id->user); 
    if (fd == 0)
    {
        log_debug(ZONE,"INVALID SOCK, FREEING PACKET, NOT SENDING");
        xmlnode_free(p->x);
        return r_DONE;
    }

    for (cur=io_select_get_list(io__instance);cur!=NULL;cur=cur->next)
    {
        cdcur=((cdata)cur->arg);
        if (fd == cur->fd)
            if (j_strcmp(p->id->resource,cdcur->res) == 0)
                break;
    }
    if(cur!=NULL)
    { /* check to see if the session manager killed the session */
        log_debug(ZONE,"Found the sock for this user");
        if (xmlnode_get_tag(p->x,"error?code=510")!=NULL)
        {
            xmlnode x=xmlnode_new_tag("stream:error");
            xmlnode_insert_cdata(x,"Disconnected",-1);
            log_debug(ZONE,"received disconnect message from session manager");
            io_write(cur,x);
            pthsock_client_close(cur);
            xmlnode_free(p->x);
            return r_DONE;
        }
        else if(cdcur->state==state_UNKNOWN)
        {
            char *type=xmlnode_get_attrib(p->x,"type");
            char *id=xmlnode_get_attrib(p->x,"id");
            if((j_strcmp(type,"result")==0)&&j_strcmp(cdcur->auth_id,id)==0)
            { /* update the cdata status if it's a successfull auth */
                log_debug(ZONE,"auth for user successful");
                /* change the host id */
                cdcur->host = pstrdup(cur->p,xmlnode_get_attrib(p->x,"sfrom"));
                cdcur->state = state_AUTHD;
            } else log_debug(ZONE,"Auth not successfull");
        }
        xmlnode_hide_attrib(p->x,"sto");
        xmlnode_hide_attrib(p->x,"sfrom");
        log_debug(ZONE,"Writing packet to socket");
        io_write(cur,p->x);
        return r_DONE;
    }

    if (xmlnode_get_tag(p->x,"error?code=510")!=NULL)
    { /* we got a 510, but no session to end */
        log_debug(ZONE,"510 ERROR, BUT NO SESSION"); 
        xmlnode_free(p->x);
        return r_DONE;
    }

    log_debug(ZONE,"pthsock_client connection not found");

    xmlnode_put_attrib(p->x,"sto",xmlnode_get_attrib(p->x,"sfrom"));
    xmlnode_put_attrib(p->x,"sfrom",jid_full(p->id));
    type = xmlnode_get_attrib(p->x,"type");

    jutil_error(p->x,TERROR_DISCONNECTED);

    if (type != NULL)
        xmlnode_put_attrib(xmlnode_get_tag(p->x,"error?code=510"),"type",type);

    jutil_tofrom(p->x);
    deliver(dpacket_new(p->x),si->i);

    return r_DONE;
}

/* callback for xstream */
void pthsock_client_stream(int type, xmlnode x, void *arg)
{
    sock c = (sock)arg;
    cdata cd=(cdata)c->arg;
    xmlnode h;

    switch(type)
    {
    case XSTREAM_ROOT:
        log_debug(ZONE,"root received for %d",c->fd);

        /* write are stream header */
        cd->host = pstrdup(c->p,xmlnode_get_attrib(x,"to"));
        h = xstream_header("jabber:client",NULL,cd->host);
        cd->sid = pstrdup(c->p,xmlnode_get_attrib(h,"id"));
        io_write_str(c,xstream_header_char(h));
        xmlnode_free(h);
        xmlnode_free(x);
        break;
    case XSTREAM_NODE:
        if (cd->state == state_UNKNOWN)
        { /* only allow auth and registration queries at this point */
            xmlnode q = xmlnode_get_tag(x,"query");
            if (!NSCHECK(q,NS_AUTH)&&!NSCHECK(q,NS_REGISTER))
            {
                log_debug(ZONE,"user tried to send packet in unknown state");
                xmlnode_free(x);
                pthsock_client_close(c);
                return;
            }
            else if (NSCHECK(q,NS_AUTH))
            {
                xmlnode_put_attrib(xmlnode_get_tag(q,"digest"),"sid",cd->sid);
                cd->auth_id = pstrdup(c->p,xmlnode_get_attrib(x,"id"));
                if(cd->auth_id==NULL) 
                {
                    cd->auth_id = pstrdup(c->p,"pthsock_client_auth_ID");
                    xmlnode_put_attrib(x,"id","pthsock_client_auth_ID");
                }
            }
        }

        xmlnode_put_attrib(x,"sfrom",cd->id);
        xmlnode_put_attrib(x,"sto",cd->host);
        deliver(dpacket_new(x),((smi)cd->i)->i);
        break;
    case XSTREAM_ERR:
        h=xmlnode_new_tag("stream:error");
        xmlnode_insert_cdata(h,"You sent malformed XML",-1);
        io_write(c,h);
    case XSTREAM_CLOSE:
        log_debug(ZONE,"closing XSTREAM");
        pthsock_client_close(c);
        xmlnode_free(x);
    }
}


cdata pthsock_client_cdata(smi si,sock c)
{
    cdata cd;
    char *buf;

    cd = pmalloco(c->p, sizeof(_cdata));
    cd->i = (void*)si;
    c->xs = xstream_new(c->p,pthsock_client_stream,(void*)c);
    cd->state = state_UNKNOWN;
    cd->arg=(void*)c;

    buf=pmalloco(c->p,100);

    /* HACK to fix race conditon */
    snprintf(buf,99,"%X",c);
    cd->res = pstrdup(c->p,buf);

    /* we use <fd>@host to identify connetions */
    snprintf(buf,99,"%d@%s/%s",c->fd,si->host,cd->res);
    cd->id = pstrdup(c->p,buf);

    return cd;
}

void pthsock_client_read(sock c,char *buffer,int bufsz,int flags,void *arg)
{
    smi si=(smi)arg;
    cdata cd;
    wbq q;
    xmlnode x;
    int ret;

    switch(flags)
    {
    case IO_INIT:
        log_debug(ZONE,"io_select INIT event");
        break;
    case IO_NEW:
        log_debug(ZONE,"io_select NEW socket connected at %d",c->fd);
        cd=pthsock_client_cdata(si,c);
        c->arg=(void*)cd;
        break;
    case IO_NORMAL:
        log_debug(ZONE,"io_select NORMAL data");
        ret=xstream_eat(c->xs,buffer,bufsz);
        break;
    case IO_CLOSED:
        cd=(cdata)c->arg;
        log_debug(ZONE,"io_select Socket %d close notification",c->fd);
        if(cd->state==state_AUTHD)
        {
            x = xmlnode_new_tag("message");
            jutil_error(x,TERROR_DISCONNECTED);
            xmlnode_put_attrib(x,"sto",cd->host);
            xmlnode_put_attrib(x,"sfrom",cd->id);
            deliver(dpacket_new(x),((smi)cd->i)->i);
        }
        break;
    case IO_ERROR:
        if(c->xbuffer!=NULL)
        {
            log_debug(ZONE,"error on socket %d, bouncing queue",c->fd);
            jutil_error(c->xbuffer,TERROR_EXTERNAL);
            deliver(dpacket_new(c->xbuffer),si->i);
            c->xbuffer=NULL;
            c->wbuffer=NULL;
            c->cbuffer=NULL;
            while((q=(wbq)pth_msgport_get(c->queue))!=NULL)
            {
                jutil_error(q->x,TERROR_EXTERNAL);
                deliver(dpacket_new(q->x),si->i);
            }
        }
        
    }
}

/* everything starts here */
void pthsock_client(instance i, xmlnode x)
{
    smi si;
    xdbcache xc;
    char *host, *port;

    log_debug(ZONE,"pthsock_client loading");

    si = pmalloco(i->p,sizeof(_smi));

    /* write mp */
    si->wmp = pth_msgport_create("pthsock_client_wmp");

    /* get the config */
    xc = xdb_cache(i);
    si->cfg = xdb_get(xc,NULL,jid_new(xmlnode_pool(x),"config@-internal"),"jabberd:pth-csock:config");

    si->host = host = xmlnode_get_tag_data(si->cfg,"host");
    port = xmlnode_get_tag_data(si->cfg,"listen");


    if (host == NULL || port == NULL)
    {
        log_error(ZONE,"pthsock_client invaild config");
        return;
    }

    /* register data callbacks */
    io__instance=io_select(atoi(port),pthsock_client_read,(void*)si);
    if(io_instance==NULL)
    {
        log_debug(ZONE,"Server to Server Failed to listen on 5222");
        log_warn("Server 2 Server Component","Failed to listen on 5222");
        exit(1);
    }
    register_phandler(i,o_DELIVER,pthsock_client_packets,(void*)si);
}
