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
    <service id="pthsock client">
      <host>pth-csock.127.0.0.1</host>
      <load>
	    <pthsock_client>../load/pthsock_client.so</pthsock_client>
      </load>
      <pthcsock xmlns='jabberd:pth-csock:config'>
	    <host>pth-csock.127.0.0.1</host>
        <listen>5222</listen>
      </pthcsock>
    </service>
*/

#include "io.h"
pth_mutex_t s__m=PTH_MUTEX_INIT;
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

    log_debug(ZONE,"send 510 to session manager");
    x = xmlnode_new_tag("message");
    jutil_error(x,TERROR_DISCONNECTED);
    xmlnode_put_attrib(x,"sto",cd->host);
    xmlnode_put_attrib(x,"sfrom",cd->id);
    deliver(dpacket_new(x),((smi)cd->i)->i);

    log_debug(ZONE,"asking %d to close",c->fd);
    io_close(c);
}

result pthsock_client_packets(instance id, dpacket p, void *arg)
{
    smi si=(smi)arg;
    cdata cdcur;
    sock all_socks=io_select_get_list(io__instance);
    sock cur;
    char *type;
    int fd;

    log_debug(ZONE,"Got a packet from jabberd: %s",xmlnode2str(p->x));

    if (p->id->user == NULL)
    {
        log_debug(ZONE,"not a user %s",xmlnode2str(p->x));
        xmlnode_free(p->x);
        return r_DONE;
    }

    fd = atoi(p->id->user); 
    if (fd == 0)
    {
        xmlnode_free(p->x);
        return r_DONE;
    }

    log_debug(ZONE,"pthsock_client looking up %d",fd);
    

    pth_mutex_acquire(&s__m,0,NULL);
    /* XXX this for loop is UUUU-GLY */
    for (cur = all_socks; cur != NULL; cur = cur->next)
    {
        cdcur=((cdata)cur->arg);
        if (fd == cur->fd)
        {
            if (j_strcmp(p->id->resource,cdcur->res) == 0)
            { /* check to see if the session manager killed the session */
                if (*(xmlnode_get_name(p->x)) == 'm')
                {
                    if (xmlnode_get_tag(p->x,"error?code=510")!=NULL)
                    {
                        xmlnode x=xmlnode_new_tag("stream:error");
                        xmlnode_insert_cdata(x,"Disconnected",-1);
                        log_debug(ZONE,"received disconnect message from session manager");
                        io_write(cur,x);
                        pthsock_client_close(cur);
                        pth_mutex_release(&s__m);
                        return -1;
                    }
                }
                if(cdcur->state==state_UNKNOWN&&*(xmlnode_get_name(p->x))=='i')
                {
                    if(j_strcmp(xmlnode_get_attrib(p->x,"type"),"result") == 0)
                    {
                        if (j_strcmp(cdcur->auth_id,xmlnode_get_attrib(p->x,"id")) == 0)
                        {
                            log_debug(ZONE,"auth for %d successful",cdcur->id);
                            /* change the host id */
                            cdcur->host = pstrdup(cur->p,xmlnode_get_attrib(p->x,"sfrom"));
                            cur->state = state_AUTHD;
                        }
                        else 
                            log_debug(ZONE,"reg for %d successful",cur->fd);
                    }
                    else 
                        log_debug(ZONE,"user auth/registration falid");
                }
                xmlnode_hide_attrib(p->x,"sto");
                xmlnode_hide_attrib(p->x,"sfrom");
                log_debug(ZONE,"Calling write on %s",xmlnode2str(p->x));
                io_write(cur,p->x);
            }
            else 
                break;
            pth_mutex_release(&s__m);
            return r_DONE;
        }
    }
    pth_mutex_release(&s__m);

    /* don't bounce if it's error 510 */
    if (*(xmlnode_get_name(p->x)) == 'm')
        if (j_strcmp(xmlnode_get_attrib(p->x,"type"),"error") == 0)
            if (j_strcmp(xmlnode_get_attrib(xmlnode_get_tag(p->x,"error"),"code"),"510") == 0)
            {
                xmlnode_free(p->x);
                return r_DONE;
            }

    log_debug(ZONE,"pthsock_client connection not found");

    xmlnode_put_attrib(p->x,"sto",xmlnode_get_attrib(p->x,"sfrom"));
    xmlnode_put_attrib(p->x,"sfrom",jid_full(p->id));
    type = xmlnode_get_attrib(p->x,"type");

    jutil_error(p->x,TERROR_DISCONNECTED);

    if (type != NULL)
        /* HACK: hide the old type on the 510 error node */
        xmlnode_put_attrib(xmlnode_get_tag(p->x,"error?code=510"),"type",type);

    jutil_tofrom(p->x);
    deliver(dpacket_new(p->x),si->i);

    return r_DONE;
}

/* callback for xstream */
void pthsock_client_stream(int type, xmlnode x, void *arg)
{
    sock c = (sock)arg;
    cdata cs=(cdata)c->arg;
    xmlnode h;

    log_debug(ZONE,"Got Type %d packet from io_select: %s",type,xmlnode2str(x));

    pth_mutex_acquire(&s__m,0,NULL);
    switch(type)
    {
    case XSTREAM_ROOT:
        log_debug(ZONE,"root received for %d",c->fd);

        /* write are stream header */
        cs->host = pstrdup(c->p,xmlnode_get_attrib(x,"to"));
        h = xstream_header("jabber:client",NULL,cs->host);
        cs->sid = pstrdup(c->p,xmlnode_get_attrib(h,"id"));
        io_write_str(c,xstream_header_char(h));
        xmlnode_free(h);
        xmlnode_free(x);
        break;

    case XSTREAM_NODE:
        log_debug(ZONE,">>>> %s",xmlnode2str(x));

        /* only allow auth and registration queries at this point */
        if (c->state == state_UNKNOWN)
        {
            xmlnode q = xmlnode_get_tag(x,"query");
            if (*(xmlnode_get_name(x)) != 'i' || (NSCHECK(q,NS_AUTH) == 0 && NSCHECK(q,NS_REGISTER) == 0))
            {
                log_debug(ZONE,"user tried to send packet in unknown state");
                /* bounce */
                xmlnode_free(x);
                pthsock_client_close(c);
                pth_mutex_release(&s__m);
                return;
            }
            else if (NSCHECK(q,NS_AUTH))
            {
                xmlnode_put_attrib(xmlnode_get_tag(q,"digest"),"sid",cs->sid);
                cs->auth_id = pstrdup(c->p,xmlnode_get_attrib(x,"id"));
                if (cs->auth_id == NULL) /* if they didn't supply an id, then we make one */
                {
                    cs->auth_id = pstrdup(c->p,"1234");
                    xmlnode_put_attrib(x,"id","1234");
                }
            }
        }

        xmlnode_put_attrib(x,"sfrom",cs->id);
        xmlnode_put_attrib(x,"sto",cs->host);
        deliver(dpacket_new(x),((smi)cs->i)->i);
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
    pth_mutex_release(&s__m);
}


cdata pthsock_client_cdata(smi si,sock c)
{
    cdata cd;
    char buf[100];

    log_debug(ZONE,"Creating a new cdata to match socket %d",c->fd);
    cd = pmalloco(c->p, sizeof(_cdata));
    cd->i = (void*)si;
    c->xs = xstream_new(c->p,pthsock_client_stream,(void*)c);
    cd->state = state_UNKNOWN;
    cd->arg=(void*)c;

    memset(buf,0,99);

    /* HACK to fix race conditon */
    snprintf(buf,99,"%d",&c);
    cd->res = pstrdup(c->p,buf);

    /* we use <fd>@host to identify connetions */
    snprintf(buf,99,"%d@%s/%s",c->fd,si->host,cd->res);
    cd->id = pstrdup(c->p,buf);

    log_debug(ZONE,"socket id:%s",cd->id);

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
        log_debug(ZONE,"send 510 to session manager");
        x = xmlnode_new_tag("message");
        jutil_error(x,TERROR_DISCONNECTED);
        xmlnode_put_attrib(x,"sto",cd->host);
        xmlnode_put_attrib(x,"sfrom",cd->id);
        deliver(dpacket_new(x),((smi)cd->i)->i);
        break;
    case IO_ERROR:
        log_debug(ZONE,"error on one of the sockets, bouncing queue");
        if(c->xbuffer!=NULL)
        {
            jutil_error(c->xbuffer,TERROR_EXTERNAL);
            deliver(dpacket_new(c->xbuffer),si->i);
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
    register_phandler(i,o_DELIVER,pthsock_client_packets,(void*)si);
}
