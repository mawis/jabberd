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

typedef enum { state_UNKNOWN, state_AUTHD } conn_state;

typedef struct csock_st
{
    instance i;
    pool p;
    conn_state state;
    xstream xs;
    char *id, *host, *sid, *res, *auth_id;
    int sock;
    char *wbuffer;
    struct csock_st *next;
    void *arg;
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
    csock c;
    void *arg;
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
        xmlnode_free(p->x);
        return r_DONE;
    }

    sock = atoi(p->id->user); 
    if (sock == 0)
    {
        xmlnode_free(p->x);
        return r_DONE;
    }

    log_debug(ZONE,"pthsock_client looking up %d",sock);

    for (cur = si->conns; cur != NULL; cur = cur->next)
        if (sock == cur->sock)
        {
            if (j_strcmp(p->id->resource,cur->res) == 0)
            {
                d = pmalloc(xmlnode_pool(p->x),sizeof(_drop));
                d->p = p;
                d->c = cur;
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

int pthsock_client_write_dump(csock c)
{
    int len,retval;
    pth_event_t etime=pth_event(PTH_EVENT_TIME,pth_timeout(2,0));


    if(c->wbuffer==NULL) return 0;

    log_debug(ZONE,"about to dump to socket %d",c->sock);
    len=pth_write_ev(c->sock,c->wbuffer,strlen(c->wbuffer),etime);
    log_debug(ZONE,"dumped %d bytes of %d",len,strlen(c->wbuffer));
    if(len==0||pth_event_occurred(etime))
    {
        /* we didn't write anything.. postpone the write */
        retval=1;
    }
    if(len<0)
    { /* error occured while writing the packet */
        free(c->wbuffer);
        c->wbuffer=NULL;
        return -1;
    }
    else if(len!=strlen(c->wbuffer))
    {
        char *new=malloc(strlen(c->wbuffer)-len+1);
        char *temp=c->wbuffer+len;
        new[0]='\0';
        strcat(new,temp);
        free(c->wbuffer);
        c->wbuffer=new;
        retval=1;
    } 
    else
    {
        free(c->wbuffer);
        c->wbuffer=NULL;
        retval=0;
    }

    return retval;
}

void pthsock_client_unlink(smi si, csock c)
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
}

void pthsock_client_close(smi si,csock c)
{
    xmlnode x;
    if(si==NULL)si=(smi)c->arg;

    pthsock_client_unlink(si,c);
    log_debug(ZONE,"closing socket '%d'",c->sock);

    x = xmlnode_new_tag("message");
    jutil_error(x,TERROR_DISCONNECTED);
    xmlnode_put_attrib(x,"sto",c->host);
    xmlnode_put_attrib(x,"sfrom",c->id);
    deliver(dpacket_new(x),c->i);
    if(c->wbuffer!=NULL) free(c->wbuffer);
    c->wbuffer=strdup("</stream:stream>");
    if(pthsock_client_write_dump(c)&&c->wbuffer!=NULL)
       free(c->wbuffer); 

    close(c->sock);
    pool_free(c->p);
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
        if(c->wbuffer!=NULL)
        {
            char *new=malloc(strlen(c->wbuffer)+strlen(block)+1);
            new[0]='\0';
            strcat(new,c->wbuffer);
            strcat(new,block);
            free(c->wbuffer);
            c->wbuffer=new;
        }
        else
            c->wbuffer=strdup(block);

        xmlnode_free(h);
        xmlnode_free(x);
        pthsock_client_write_dump(c);
        break;

    case XSTREAM_NODE:
        log_debug(ZONE,"node received for %d",c->sock);

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
                pthsock_client_close(NULL,c);
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
        if(c->wbuffer!=NULL) free(c->wbuffer);
        c->wbuffer=strdup("<stream::error>You sent malformed XML</stream:error>");
        if(pthsock_client_write_dump(c)&&c->wbuffer!=NULL) free(c->wbuffer);
    case XSTREAM_CLOSE:
        log_debug(ZONE,"closing XSTREAM");

        pthsock_client_close(NULL,c);
        xmlnode_free(x);
    }
}

int pthsock_client_write(csock c, dpacket p)
{
    char *block;

    log_debug(ZONE,"message for %d",c->sock);

    /* check to see if the session manager killed the session */
    if (*(xmlnode_get_name(p->x)) == 'm')
        if (xmlnode_get_tag(p->x,"error?code=510")!=NULL)
        {
            log_debug(ZONE,"received disconnect message from session manager");
            if(c->wbuffer!=NULL) free(c->wbuffer);
            c->wbuffer=strdup("<stream:error>Disconnected</stream:error>");
            if(pthsock_client_write_dump(c)&&c->wbuffer!=NULL) free(c->wbuffer);
            return -1;
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
    if(block==NULL) return -1;

    log_debug(ZONE,"<<<< %s",block);

    if(c->wbuffer!=NULL)
    { /* add this to the write buffer */
        char *new_buffer=malloc(strlen(c->wbuffer)+strlen(block)+1);
        new_buffer[0]='\0';
        strcat(new_buffer,c->wbuffer);
        strcat(new_buffer,block);
        free(c->wbuffer);
        c->wbuffer=new_buffer;
    }
    else
    {
        c->wbuffer=strdup(block);
    }

    pool_free(p->p);

    /* write the packet */
    return pthsock_client_write_dump(c);
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
    c->arg=(void*)si;
    c->xs = xstream_new(p,pthsock_client_stream,(void*)c);
    c->sock = sock;
    c->state = state_UNKNOWN;

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

csock pthsock_client_accept(smi si,int asock)
{
    struct sockaddr_in sa;
    size_t sa_size = sizeof(sa);
    pth_event_t etime=pth_event(PTH_EVENT_TIME,pth_timeout(2,0));
    int sock;
    csock c;
    sock = pth_accept_ev(asock,(struct sockaddr*)&sa,(int*)&sa_size,etime);
    if(sock < 0||pth_event_occurred(etime))
    {
        log_debug(ZONE,"accept error");
        return NULL; 
    }

    log_debug(ZONE,"pthsock_client: new socket accepted (fd: %d, ip: %s, port: %d)",sock,inet_ntoa(sa.sin_addr),ntohs(sa.sin_port));

    c = pthsock_client_csock(si,sock);
    if(c==NULL) return NULL;
    c->next = si->conns;
    si->conns = c;
    return c;
}

void *pthsock_client_main(void *arg)
{
    smi si = (smi) arg;     /* our instance object */
    pth_event_t wevt;       /* the pth event for the mp */
    fd_set wfds,rfds, all_wfds,all_rfds; /* writes, reads, all */
    csock cur, c;    
    drop d;
    char buff[1024];
    int len, asock;

    asock = si->asock;

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&all_wfds);
    FD_ZERO(&all_rfds);
    FD_SET(asock,&rfds);

    wevt = pth_event(PTH_EVENT_MSG,si->wmp);

    while (1)
    {
        pth_select_ev(FD_SETSIZE,&rfds,&wfds,NULL,NULL,wevt);

        log_debug(ZONE,"out of pth select");

        /* handle packets that need to be written */
        if (pth_event_occurred(wevt))
        {
            while (1)
            {
                int ret;

                /* get the packet */
                d = (drop)pth_msgport_get(si->wmp);
                if (d == NULL) break;

                c = d->c;

                log_debug(ZONE,"write event for %d",c->sock);
                ret=pthsock_client_write(c,d->p);
                if(ret<0) /* error occured here */
                {
                    log_debug(ZONE,"error writing to socket, closing ");
                    FD_CLR(c->sock,&all_rfds);
                    FD_CLR(c->sock,&all_wfds);
                    pthsock_client_close(si,c);
                }
                else if(ret) /* didn't write all the data */
                {
                    log_debug(ZONE,"data still to write on %d",c->sock);
                    FD_SET(c->sock,&all_wfds);
                }
                else /* good write */
                {
                    log_debug(ZONE,"finished writing on %d",c->sock);
                    FD_CLR(c->sock,&all_wfds);
                }
            }
        }

        log_debug(ZONE,"normal select loop section...");
        

        FD_ZERO(&all_rfds); /* reset our "all" set */
        FD_SET(asock,&all_rfds);

        if (FD_ISSET(asock,&rfds)) /* new connection */
        {
            c=pthsock_client_accept(si,asock);
            if(c!=NULL) FD_SET(c->sock,&all_rfds);           
        }

        cur = si->conns;
        log_debug(ZONE,"looping through sockets");
        while(cur != NULL)
        {
            log_debug(ZONE,"checking socket %d",cur->sock);
            if (FD_ISSET(cur->sock,&rfds))
            { /* we need to read from a socket */
                log_debug(ZONE,"read event for %d",cur->sock);
                len = pth_read(cur->sock,buff,sizeof(buff));
                if(len <= 0)
                {
                    log_debug(ZONE,"Error reading on '%d', %s",cur->sock,strerror(errno));
                    FD_CLR(cur->sock,&all_rfds);
                    FD_CLR(cur->sock,&all_wfds);
                    pthsock_client_close(si,cur);
                }
                else
                {
                    log_debug(ZONE,"read %d bytes",len);
                    xstream_eat(cur->xs,buff,len);
                }
            }
            else if(FD_ISSET(cur->sock,&wfds))
            { /* ooo, we are ready to dump the rest of the data */
                int ret=pthsock_client_write_dump(cur);
                log_debug(ZONE,"write event for %d",cur->sock);
                if(ret<0)
                {
                    log_debug(ZONE,"error writing to socket %d",cur->sock);
                    FD_CLR(cur->sock,&all_rfds);
                    FD_CLR(cur->sock,&all_wfds);
                    pthsock_client_close(si,cur);
                }
                else if(!ret)
                { /* write was successfull */
                    FD_CLR(cur->sock,&all_wfds);
                }
                else
                    log_debug(ZONE,"data still to be written on %d",cur->sock); 
            }

            FD_SET(cur->sock,&all_rfds);
            if(cur->wbuffer!=NULL) 
            {
                log_debug(ZONE,"fd write SET for %d",cur->sock);
                FD_SET(cur->sock,&all_wfds);
            }
            else
            {
                FD_CLR(cur->sock,&all_wfds);
            }
            cur = cur->next;
        }
        log_debug(ZONE,"setting fds");
        wfds = all_wfds;
        rfds = all_rfds;
    }
    log_debug(ZONE,"\n\n\n\nWHOA! WE ARE OUT OF THE LOOP!!!\nCLIENTS ARE DISCONNECTED NOW!!!\n\n\n");
    pth_event_free(wevt,PTH_FREE_THIS);
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
