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

/* socket manager instance */
struct cdata_st;

typedef struct smi_st
{
    instance i;
    struct cdata_st *conns;
    xmlnode cfg;
    pth_msgport_t wmp;
    char *host;
    int asock;  /* socket we accept connections on */
} *smi, _smi;

typedef struct cdata_st
{
    smi* i;
    int state;
    char *id, *host, *sid, *res, *auth_id;
    void *arg;
    struct cdata_st *next;
} _cdata,*cdata;

void pthsock_client_unlink(smi si, sock c)
{
    cdata cur, prev;

    log_debug(ZONE,"Unlinking Local sock copy %d",c->fd);

    /* remove connection from the list */
    for (cur = si->conns,prev = NULL; cur != NULL; prev = cur,cur = cur->next)
        if ((sock)cur->arg == c)
        {
            if (prev != NULL)
                prev->next = cur->next;
            else
                si->conns = cur->next;
            break;
        }
}

void pthsock_client_close(sock c)
{
    xmlnode x;
    cdata cd=(cdata)c->arg;
    smi si=(smi)cd->i;

    log_debug(ZONE,"asking %d to close",c->fd);
    io_close(c);
    pthsock_client_unlink(si,c);

    log_debug(ZONE,"send 510 to session manager");
    x = xmlnode_new_tag("message");
    jutil_error(x,TERROR_DISCONNECTED);
    xmlnode_put_attrib(x,"sto",cd->host);
    xmlnode_put_attrib(x,"sfrom",cd->id);
    deliver(dpacket_new(x),((smi)cd->i)->i);
}

result pthsock_client_packets(instance id, dpacket p, void *arg)
{
    smi si=(smi)arg;
    cdata cdcur;
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

    /* XXX this for loop is UUUU-GLY */
    for (cdcur = si->conns; cdcur != NULL; cdcur = cdcur->next)
    {
        cur=((sock)cdcur->arg);
        if (fd == cur->fd)
        {
            if (j_strcmp(p->id->resource,cdcur->res) == 0)
            { /* check to see if the session manager killed the session */
                if (*(xmlnode_get_name(p->x)) == 'm')
                {
                    if (xmlnode_get_tag(p->x,"error?code=510")!=NULL)
                    {
                        log_debug(ZONE,"received disconnect message from session manager");
                        io_write_str(cur,"<stream:error>Disconnected</stream:error>");
                        pthsock_client_close(cur);
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
            return r_DONE;
        }
    }

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
    char *block;

    log_debug(ZONE,"Got Type %d packet from io_select: %s",type,xmlnode2str(x));

    switch(type)
    {
    case XSTREAM_ROOT:
        log_debug(ZONE,"root received for %d",c->fd);

        /* write are stream header */
        cs->host = pstrdup(c->p,xmlnode_get_attrib(x,"to"));
        h = xstream_header("jabber:client",NULL,cs->host);
        cs->sid = pstrdup(c->p,xmlnode_get_attrib(h,"id"));
        block = xstream_header_char(h);
        io_write_str(c,block);
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
                c->state=state_CLOSE;
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
        io_write_str(c,"<stream:error>You sent malformed XML</stream:error>");
    case XSTREAM_CLOSE:
        log_debug(ZONE,"closing XSTREAM");
        pthsock_client_close(c);
        xmlnode_free(x);
    }
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

    cd->next=si->conns;
    si->conns=cd;

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
    int ret;

    if(c!=NULL) 
    {
     log_debug(ZONE,"io_select read event on %d:%d:%d, [%s]",c->fd,flags,bufsz,buffer);
    }
    else
    {
     log_debug(ZONE,"io_select read event [%s]:%d:%d",buffer,bufsz,flags);
    }

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
        log_debug(ZONE,"io_select Socket %d close notification",c->fd);
        pthsock_client_unlink(si,c);
        break;
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
    io_select(atoi(port),pthsock_client_read,(void*)si);
    register_phandler(i,o_DELIVER,pthsock_client_packets,(void*)si);
}
