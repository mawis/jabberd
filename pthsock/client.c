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

typedef enum { state_UNKNOWN, state_AUTHD } user_state;
typedef struct cdata_st
{
    smi* i;
    user_state state;
    char *id, *host, *sid, *res, *auth_id;
    void *arg;
    pth_msgport_t pre_auth_mp;
    struct cdata_st *next;
} _cdata,*cdata;

void pthsock_client_close(sock c)
{
    xmlnode x;
    cdata cd=(cdata)c->arg;
    if(cd->state==state_AUTHD)
    {
        x = xmlnode_new_tag("route");
        xmlnode_put_attrib(x,"type","error");
        xmlnode_put_attrib(x,"to",cd->host);
        xmlnode_put_attrib(x,"from",cd->id);
        log_debug(ZONE,"Closing client socket, sending notification to SM: %s",xmlnode2str(x));
        deliver(dpacket_new(x),((smi)cd->i)->i);
    }
    else
    {
        wbq q;
        if(cd->pre_auth_mp!=NULL)
        {
            while((q=(wbq)pth_msgport_get(cd->pre_auth_mp))!=NULL)
            {
                xmlnode_free(q->x);
            }
            pth_msgport_destroy(cd->pre_auth_mp);
        } 
    }
    log_debug(ZONE,"asking socket to close");
    io_close(c);
}

result pthsock_client_packets(instance id, dpacket p, void *arg)
{
    smi si=(smi)arg;
    cdata cdcur;
    sock cur;
    int fd=0;

    log_debug(ZONE,"Got a packet from Deliver[%s]: %s",p->id->user,xmlnode2str(p->x));

    if(p->id->user!=NULL)fd = atoi(p->id->user); 
    if(p->type!=p_ROUTE||fd==0)
    {
        log_debug(ZONE,"Dropping loser packet[%d]: %s",p->type,xmlnode2str(p->x));
        xmlnode_free(p->x);
        return r_DONE;
    }

    for (cur=io_select_get_list();cur!=NULL;cur=cur->next)
    {
        cdcur=((cdata)cur->arg);
        if (fd == cur->fd)
            if (j_strcmp(p->id->resource,cdcur->res) == 0)
                break;
    }

    if(cur!=NULL)
    { /* check to see if the session manager killed the session */
        log_debug(ZONE,"Found the sock for this user");
        if (j_strcmp(xmlnode_get_attrib(p->x,"type"),"error")==0)
        { /* <route type="error" means we were disconnected */
            xmlnode x=xmlnode_new_tag("stream:error");
            xmlnode_insert_cdata(x,"Disconnected",-1);
            log_debug(ZONE,"received disconnect message from session manager");
            io_write(cur,x);
            pthsock_client_close(cur);
            xmlnode_free(p->x);
            return r_DONE;
        }
        else if(cdcur->state==state_UNKNOWN&&j_strcmp(xmlnode_get_attrib(p->x,"type"),"auth")==0)
        { /* look for our auth packet back */
            char *type=xmlnode_get_attrib(xmlnode_get_firstchild(p->x),"type");
            char *id=xmlnode_get_attrib(xmlnode_get_tag(p->x,"iq"),"id");
            if((j_strcmp(type,"result")==0)&&j_strcmp(cdcur->auth_id,id)==0)
            { /* update the cdata status if it's a successfull auth */
                jid j;
                xmlnode x;
                log_debug(ZONE,"auth for user successful");

                log_debug(ZONE,"notifying SM to start session");
                x=xmlnode_new_tag("route");
                xmlnode_put_attrib(x,"type","session");
                j=jid_new(xmlnode_pool(x),cdcur->host);
                jid_set(j,xmlnode_get_data(xmlnode_get_tag(xmlnode_get_tag(xmlnode_get_firstchild(p->x),"query?xmlns=jabber:iq:auth"),"username")),JID_USER);
                jid_set(j,xmlnode_get_data(xmlnode_get_tag(xmlnode_get_tag(xmlnode_get_firstchild(p->x),"query?xmlns=jabber:iq:auth"),"resource")),JID_RESOURCE);
                xmlnode_put_attrib(x,"to",jid_full(j));
                xmlnode_put_attrib(x,"from",xmlnode_get_attrib(p->x,"to"));
                deliver(dpacket_new(x),si->i);
            } else log_debug(ZONE,"Auth not successfull");
        } else if(cdcur->state==state_UNKNOWN&&j_strcmp(xmlnode_get_attrib(p->x,"type"),"session")==0)
        { /* got a session reply from the server */
            wbq q;
            cdcur->state = state_AUTHD;
            /* change the host id */
            cdcur->host = pstrdup(cur->p,xmlnode_get_attrib(p->x,"sfrom"));
            log_debug(ZONE,"Session Started");
            /* if we have packets in the queue, write them */
            while((q=(wbq)pth_msgport_get(cdcur->pre_auth_mp))!=NULL)
            {
                q->x=xmlnode_wrap(q->x,"route");
                xmlnode_put_attrib(q->x,"to",cdcur->host);
                xmlnode_put_attrib(q->x,"from",cdcur->id);
                deliver(dpacket_new(q->x),si->i);
            }
            pth_msgport_destroy(cdcur->pre_auth_mp);
            cdcur->pre_auth_mp=NULL;
        }
        log_debug(ZONE,"Writing packet to socket");
        io_write(cur,xmlnode_get_firstchild(p->x));
        return r_DONE;
    }

    if (j_strcmp(xmlnode_get_attrib(p->x,"typs"),"error")==0)
    { /* we got a 510, but no session to end */
        log_debug(ZONE,"510 ERROR, BUT NO SESSION"); 
        xmlnode_free(p->x);
        return r_DONE;
    }

    log_debug(ZONE,"pthsock_client connection not found");

    jutil_tofrom(p->x);
    xmlnode_put_attrib(p->x,"type","error");

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
                wbq q;
                /* queue packet until authed */
                q=pmalloco(xmlnode_pool(x),sizeof(_wbq));
                q->x=x;
                pth_msgport_put(cd->pre_auth_mp,(void*)q);
                return;
            }
            else if (NSCHECK(q,NS_AUTH))
            {
                jid j;
                xmlnode_put_attrib(xmlnode_get_tag(q,"digest"),"sid",cd->sid);
                cd->auth_id = pstrdup(c->p,xmlnode_get_attrib(x,"id"));
                if(cd->auth_id==NULL) 
                {
                    cd->auth_id = pstrdup(c->p,"pthsock_client_auth_ID");
                    xmlnode_put_attrib(x,"id","pthsock_client_auth_ID");
                }
                x=xmlnode_wrap(x,"route");
                j=jid_new(xmlnode_pool(x),cd->host);
                jid_set(j,xmlnode_get_data(xmlnode_get_tag(xmlnode_get_tag(xmlnode_get_firstchild(x),"query?xmlns=jabber:iq:auth"),"username")),JID_USER);
                jid_set(j,xmlnode_get_data(xmlnode_get_tag(xmlnode_get_tag(xmlnode_get_firstchild(x),"query?xmlns=jabber:iq:auth"),"resource")),JID_RESOURCE);
                xmlnode_put_attrib(x,"to",jid_full(j));
                xmlnode_put_attrib(x,"from",xmlnode_get_attrib(x,"to"));
                xmlnode_put_attrib(x,"type","auth");
                xmlnode_put_attrib(x,"from",cd->id);
                deliver(dpacket_new(x),((smi)cd->i)->i);
            }
            else if (NSCHECK(q,NS_REGISTER))
            {
                x=xmlnode_wrap(x,"route");
                xmlnode_put_attrib(x,"type","register");
                xmlnode_put_attrib(x,"from",cd->id);
                xmlnode_put_attrib(x,"to",cd->host);
                deliver(dpacket_new(x),((smi)cd->i)->i);
            }
        }
        else
        {
            xmlnode_put_attrib(x,"from",cd->id);
            xmlnode_put_attrib(x,"to",cd->host);
            log_debug(ZONE,"wrapped client packet as: %s",xmlnode2str(x));
            deliver(dpacket_new(x),((smi)cd->i)->i);
        }
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
    cd->pre_auth_mp=pth_msgport_create("pre_auth_mp");
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
        ret=xstream_eat(c->xs,buffer,bufsz);
        break;
    case IO_CLOSED:
        cd=(cdata)c->arg;
        log_debug(ZONE,"io_select Socket %d close notification",c->fd);
        if(cd->state==state_AUTHD)
        {
            x = xmlnode_new_tag("route");
            xmlnode_put_attrib(x,"type","error");
            xmlnode_put_attrib(x,"to",cd->host);
            xmlnode_put_attrib(x,"from",cd->id);
            log_debug(ZONE,"sending SM notification: %s",xmlnode2str(x));
            deliver(dpacket_new(x),((smi)cd->i)->i);
        }
        break;
    case IO_ERROR:
        if(c->xbuffer!=NULL)
        {
            if(((int)c->xbuffer)!=-1)
            {
                char *from=xmlnode_get_attrib(c->xbuffer,"to");
                char *to=xmlnode_get_attrib(c->xbuffer,"from");
                jutil_error(c->xbuffer,TERROR_EXTERNAL);
                c->xbuffer=xmlnode_wrap(c->xbuffer,"route");
                xmlnode_put_attrib(c->xbuffer,"from",from);
                xmlnode_put_attrib(c->xbuffer,"to",to);
                log_debug(ZONE,"bounding xbuffer");
                deliver(dpacket_new(c->xbuffer),si->i);
            }
            else
                pool_free(c->pbuffer); 
            log_debug(ZONE,"error on socket %d, bouncing queue",c->fd);
            c->xbuffer=NULL;
            c->wbuffer=c->cbuffer=NULL;
            c->pbuffer=NULL;
            while((q=(wbq)pth_msgport_get(c->queue))!=NULL)
            {
                if(q->type==queue_XMLNODE)
                {
                    char *from=xmlnode_get_attrib(c->xbuffer,"to");
                    char *to=xmlnode_get_attrib(c->xbuffer,"from");
                    jutil_error(q->x,TERROR_EXTERNAL);
                    c->xbuffer=xmlnode_wrap(c->xbuffer,"route");
                    xmlnode_put_attrib(c->xbuffer,"from",from);
                    xmlnode_put_attrib(c->xbuffer,"to",to);
                    deliver(dpacket_new(q->x),si->i);
                }
                else
                {
                    pool_free(q->p);
                }
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
    si->i = i;

    /* write mp */
    si->wmp = pth_msgport_create("pthsock_client_wmp");

    /* get the config */
    xc = xdb_cache(i);
    si->cfg = xdb_get(xc,NULL,jid_new(xmlnode_pool(x),"config@-internal"),"jabberd:pth-csock:config");

    si->host = host = i->id;
    port = xmlnode_get_tag_data(si->cfg,"listen");


    if (host == NULL || port == NULL)
    {
        log_error(ZONE,"pthsock_client invaild config");
        return;
    }

    /* register data callbacks */
    io_select_listen(atoi(port),NULL,pthsock_client_read,(void*)si);
    register_phandler(i,o_DELIVER,pthsock_client_packets,(void*)si);
}
