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

#include <jabberd.h>

typedef enum { state_UNKNOWN, state_AUTHD, state_CLOSING, state_CLOSED } conn_state;

typedef struct csock_st
{
    instance i;
    pool p;
    conn_state state;
    xstream xs;
    char *id, *host, *sid, *res, *auth_id;
    pth_msgport_t queue;
    int sock, write_flag;
    struct csock_st *next;
} *csock, _csock;

/* socket manager instance */
typedef struct smi_st
{
    instance i;
    csock conns;
    xmlnode cfg;
    pth_msgport_t wmp;
    char *host;
    int asock;  /* socket we accept connections on */
} *smi, _smi;

/* simple wrapper around the pth messages to pass packets */
typedef struct
{
    pth_message_t head; /* the standard pth message header */
    dpacket p;
} *drop, _drop;

result pthsock_client_packets(instance id, dpacket p, void *arg)
{
    smi si = (smi) arg;
    csock cur;
    drop d;
    char *type;
    int sock;

    if (p->id->user == NULL)
    {
        log_debug(ZONE,"not a user %s",xmlnode2str(p->x));
        return r_DONE;
    }

    sock = atoi(p->id->user); 
    if (sock == 0)
        return r_DONE;

    log_debug(ZONE,"pthsock_client looking up %d",sock);

    for (cur = si->conns; cur != NULL; cur = cur->next)
        if (sock == cur->sock)
        {
            if (j_strcmp(p->id->resource,cur->res) == 0 && cur->state != state_CLOSING && cur->state != state_CLOSED)
            {
                d = pmalloc(xmlnode_pool(p->x),sizeof(_drop));
                d->p = p;
                cur->write_flag = 1;
                pth_msgport_put(cur->queue,(void*)d);

                /* notify the main thread with an empty message */
                d = pmalloco(xmlnode_pool(p->x),sizeof(_drop));
                pth_msgport_put(si->wmp,(void*)d);
            }
            else
                break;

            return r_DONE;
        }

    /* don't bounce if it's error 510 */
    if (*(xmlnode_get_name(p->x)) == 'm')
        if (j_strcmp(xmlnode_get_attrib(p->x,"type"),"error") == 0)
            if (j_strcmp(xmlnode_get_attrib(xmlnode_get_tag(p->x,"error"),"code"),"510") == 0)
                return r_DONE;

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

void pthsock_client_stream(int type, xmlnode x, void *arg)
{
    csock c = (csock)arg;
    xmlnode h;
    char *block;

    log_debug(ZONE,"pthsock_client_stream handling packet type %d",type);

    switch(type)
    {
    case XSTREAM_ROOT:
        log_debug(ZONE,"root received for %d",c->sock);

        /* write are stream header */
        c->host = pstrdup(c->p,xmlnode_get_attrib(x,"to"));
        h = xstream_header("jabber:client",NULL,c->host);
        c->sid = pstrdup(c->p,xmlnode_get_attrib(h,"id"));
        block = xstream_header_char(h);
        pth_write(c->sock,block,strlen(block));
        xmlnode_free(h);
        break;

    case XSTREAM_NODE:
        log_debug(ZONE,"node received for %d",c->sock);

        //log_debug(ZONE,">>>> %s",xmlnode2str(x));

        /* only allow auth and registration queries at this point */
        if (c->state == state_UNKNOWN)
        {
            xmlnode q = xmlnode_get_tag(x,"query");
            if (*(xmlnode_get_name(x)) != 'i' || (NSCHECK(q,NS_AUTH) == 0 && NSCHECK(q,NS_REGISTER) == 0))
            {
                log_debug(ZONE,"user tried to send packet in unknown state");
                c->state = state_CLOSING;
                /* bounce */
                return;
            }
            else if (NSCHECK(q,NS_AUTH))
            {
                xmlnode_put_attrib(xmlnode_get_tag(q,"digest"),"sid",c->sid);
                c->auth_id = pstrdup(c->p,xmlnode_get_attrib(x,"id"));
                if (c->auth_id == NULL) /* if they didn't supply an id, then we make one */
                {
                    c->auth_id = pstrdup(c->p,"1234");
                    xmlnode_put_attrib(x,"id","1234");
                }
            }
        }

        xmlnode_put_attrib(x,"sfrom",c->id);
        xmlnode_put_attrib(x,"sto",c->host);
        deliver(dpacket_new(x),c->i);
        break;

    case XSTREAM_ERR:
        pth_write(c->sock,"<stream::error>You sent malformed XML</stream:error>",52 * sizeof(char));
    case XSTREAM_CLOSE:
        log_debug(ZONE,"closing XSTREAM");
        if (c->state == state_AUTHD)
        {
            c->state = state_CLOSING;

            /* notify the session manager */
            h = xmlnode_new_tag("message");
            jutil_error(h,TERROR_DISCONNECTED);
            jutil_tofrom(h);
            xmlnode_put_attrib(h,"sto",c->host);
            xmlnode_put_attrib(h,"sfrom",c->id);
            deliver(dpacket_new(h),c->i);
        }
        else
            c->state = state_CLOSING;
    }
}

void pthsock_client_release(smi si, csock c)
{
    csock cur, prev;

    /* remove connection from the list */
    for (cur = si->conns,prev = NULL; cur != NULL; prev = cur,cur = cur->next)
        if (cur == c)
        {
            if (prev != NULL)
                prev->next = cur->next;
            else
                si->conns = cur->next;
            break;
        }

    pool_free(c->p);
}

void pthsock_client_close(csock c)
{
    xmlnode x;
    drop d;

    log_debug(ZONE,"closing socket '%d'",c->sock);

    if (c->state != state_CLOSING)
    {
        x = xmlnode_new_tag("message");
        jutil_error(x,TERROR_DISCONNECTED);
        xmlnode_put_attrib(x,"sto",c->host);
        xmlnode_put_attrib(x,"sfrom",c->id);
        deliver(dpacket_new(x),c->i);
    }
    else if(c->state != state_CLOSED)
        pth_write(c->sock,"</stream:stream>",16 * sizeof(char));

    close(c->sock);
    c->state = state_CLOSED;

    if (c->write_flag)
    {
        c->write_flag = 0;
        while ((d = (drop)pth_msgport_get(c->queue)) != NULL)
            xmlnode_free(d->p->x); /* XXX bounce instead of free */
    }

    pth_msgport_destory(c->queue);
}

int pthsock_client_write(csock c, dpacket p)
{
    char *block;

    log_debug(ZONE,"message for %d",c->sock);

    /* check to see if the session manager killed the session */
    if (*(xmlnode_get_name(p->x)) == 'm')
        if (j_strcmp(xmlnode_get_attrib(p->x,"type"),"error") == 0)
            if (j_strcmp(xmlnode_get_attrib(xmlnode_get_tag(p->x,"error"),"code"),"510") == 0)
            {
                log_debug(ZONE,"received disconnect message from session manager");
                if (c->state != state_CLOSED)
                {
                    c->state = state_CLOSED;
                    if (pth_write(c->sock,"<stream:error>Disconnected</stream:error>",41 * sizeof(char)) > 0)
                        pth_write(c->sock,"</stream:stream>",16 * sizeof(char));
                    close(c->sock);
                }
                else
                    log_debug(ZONE,"socket already closed");
                return 0;
            }

    if (c->state == state_UNKNOWN && *(xmlnode_get_name(p->x)) == 'i')
    {
        if (j_strcmp(xmlnode_get_attrib(p->x,"type"),"result") == 0)
        {
            if (j_strcmp(c->auth_id,xmlnode_get_attrib(p->x,"id")) == 0)
            {
                log_debug(ZONE,"auth for %d successful",c->sock);
                /* change the host id */
                c->host = pstrdup(c->p,xmlnode_get_attrib(p->x,"sfrom"));
                c->state = state_AUTHD;
            }
            else
                log_debug(ZONE,"reg for %d successful",c->sock);
        }
        else
            /* they didn't get authed/registered */
            log_debug(ZONE,"user auth/registration falid");
    }

    log_debug(ZONE,"writing %d",c->sock);

    xmlnode_hide_attrib(p->x,"sto");
    xmlnode_hide_attrib(p->x,"sfrom");
    block = xmlnode2str(p->x);

    //log_debug(ZONE,"<<<< %s",block);

    /* write the packet */
    if(pth_write(c->sock,block,strlen(block)) <= 0)
    {
        c->state = state_CLOSED;
        /* bounce p->p */
        return 0;
    }

    pool_free(p->p);;
    return 1;
}

csock pthsock_client_csock(smi si, int sock)
{
    pool p;
    csock c;
    char buf[100];

    p = pool_heap(2*1024);
    c = pmalloco(p, sizeof(_csock));
    c->p = p;
    c->i = si->i;
    c->xs = xstream_new(p,pthsock_client_stream,(void*)c);
    c->sock = sock;
    c->state = state_UNKNOWN;
    c->queue = pth_msgport_create("pthsock client queue");
    memset(buf,0,99);

    /* HACK to fix race conditon */
    snprintf(buf,99,"%d",&c);
    c->res = pstrdup(p,buf);

    /* we use <fd>@host to identify connetions */
    snprintf(buf,99,"%d@%s/%s",sock,si->host,c->res);
    c->id = pstrdup(p,buf);

    log_debug(ZONE,"socket id:%s",c->id);

    return c;
}

typedef struct tout_st
{
    struct timeval last;
    struct timeval timeout;
} tout;

int pthsock_client_time(void *arg)
{
    tout *t = (tout *) arg;
    struct timeval now, diff;

    if (t->last.tv_sec == 0)
    {
        gettimeofday(&t->last,NULL);
        return 0;
    }

    gettimeofday(&now,NULL);
    diff.tv_sec = now.tv_sec - t->last.tv_sec;
    diff.tv_usec = now.tv_usec - t->last.tv_usec;

    if (diff.tv_sec > t->timeout.tv_sec)
    {
        gettimeofday(&t->last,NULL);
        return 1;
    }

    if (diff.tv_sec == t->timeout.tv_sec && diff.tv_usec >= t->timeout.tv_usec)
    {
        gettimeofday(&t->last,NULL);
        return 1;
    }

    return 0;
}

void *pthsock_client_main(void *arg)
{
    smi si = (smi) arg;
    tout t;
    pth_msgport_t wmp;
    pth_event_t wevt, tevt, ering;
    fd_set rfds, wfds, afds;
    csock cur, c, temp;
    drop d;
    char buff[1024];
    int len, asock, sock;
    struct sockaddr_in sa;
    size_t sa_size = sizeof(sa);

    t.timeout.tv_sec = 0;
    t.timeout.tv_usec = 20000;
    t.last.tv_sec = 0;

    asock = si->asock;
    wmp = si->wmp;

    wevt = pth_event(PTH_EVENT_MSG,wmp);
    tevt = pth_event(PTH_EVENT_FUNC,pthsock_client_time,&t,pth_time(0,20000));
    ering = pth_event_concat(wevt,tevt,NULL);

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&afds);
    FD_SET(asock,&rfds);

    while (1)
    {
        if (pth_select_ev(FD_SETSIZE,&rfds,&wfds,NULL,NULL,ering) > 0)
        {
            log_debug(ZONE,"select");

            FD_ZERO(&afds);
            FD_SET(asock,&afds);

            if (FD_ISSET(asock,&rfds)) /* new connection */
            {
                sock = pth_accept(asock,(struct sockaddr*)&sa,(int*)&sa_size);
                if(sock < 0)
                {
                    log_debug(ZONE,"accept error");
                    break;
                }

                log_debug(ZONE,"pthsock_client: new socket accepted (fd: %d, ip: %s, port: %d)",sock,inet_ntoa(sa.sin_addr),ntohs(sa.sin_port));

                c = pthsock_client_csock(si,sock);
                c->next = si->conns;
                si->conns = c;

                FD_SET(sock,&afds);           
            }

            cur = si->conns;
            while(cur != NULL)
            {
                /* remove closed connections */
                if (cur->state == state_CLOSED)
                {
                    temp = cur;
                    cur = cur->next;
                    pthsock_client_release(si,temp);
                    continue;
                }

                /* read */
                if (FD_ISSET(cur->sock,&rfds))
                {
                    len = pth_read(cur->sock,buff,sizeof(buff));
                    if(len <= 0)
                    {
                        log_debug(ZONE,"Error reading on '%d', %s",cur->sock,strerror(errno));
                        pthsock_client_close(cur);
                    }
                    else
                    {
                        log_debug(ZONE,"read %d bytes",len);

                        xstream_eat(cur->xs,buff,len);
                        if (cur->state == state_CLOSING)
                            pthsock_client_close(cur);
                        else
                            FD_SET(cur->sock,&afds);
                    }
                }

                /* handle packets that need to be written */
                if (cur->write_flag)
                {
                    /* get and write the packets */
                    while ((d = (drop)pth_msgport_get(cur->queue)) != NULL)
                        if (!pthsock_client_write(c,d->p))
                            break;

                    cur->write_flag = 0;

                    /* if it closed while we tried to write then don't add it to the set */
                    if (c->state != state_CLOSING && c->state != state_CLOSED)
                        FD_SET(cur->sock,&afds);
                }
                else
                    FD_SET(cur->sock,&afds);

                cur = cur->next;
            }
            wfds = rfds = afds;
        }
    }
    return NULL;
}

/* everything starts here */
void pthsock_client(instance i, xmlnode x)
{
    smi si;
    xdbcache xc;
    pth_attr_t attr;
    char *host, *port;
    int sock;

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

    sock = make_netsocket(atoi(port),NULL,NETSOCKET_SERVER);
    if(sock < 0)
    {
        log_error(NULL,"pthsock_client is unable to listen on %d",atoi(port));
        return;
    }

    if(listen(sock,10) < 0)
    {
        log_error(NULL,"pthsock_client is unable to listen on %d",atoi(port));
        return;
    }

    si->asock = sock;

    register_phandler(i,o_DELIVER,pthsock_client_packets,(void*)si);

    attr = pth_attr_new();
    pth_attr_set(attr,PTH_ATTR_JOINABLE,FALSE);

    /* start main accept/read/write thread */
    pth_spawn(attr,pthsock_client_main,(void*)si);

    pth_attr_destroy(attr);
}
