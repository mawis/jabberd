/*
  <service id="127.0.0.1 s2s">
    <host/>
    <load main="pthsock_server">
      <pthsock_server>../load/pthsock_server.so</pthsock_server>
    </load>
  </service>
*/

#include <jabberd.h>

typedef enum { conn_IN, conn_OUT, conn_CONNECT, conn_CLOSED } conn_type;

/* simple wrapper around the pth messages to pass packets */
typedef struct drop_st *drop, _drop;

typedef struct ssock_st
{
    pool p;
    instance i;
    pth_msgport_t amp;
    conn_type type;
    xstream xs;
    char *to;
    int sock, open;
    drop dlist; /* packets that are waiting written */
    struct ssock_st *next;
} *ssock, _ssock;

struct drop_st
{
    pth_message_t head; /* the standard pth message header */
    dpacket p;
    ssock s;
    struct drop_st *next;
};

/* server 2 server instance */
typedef struct ssi_st
{
    instance i;
    ssock conns;
    HASHTABLE out_tab;
    pth_msgport_t wmp;
    pth_msgport_t amp;
    int asock;
} *ssi, _ssi;

void *pthsock_server_connect(void *arg)
{   
    ssock s = (ssock)arg;
    drop d;
    pth_event_t evt;
    struct sockaddr_in sa;
    struct in_addr *saddr;
    int sock, flag = 1;

    log_debug(ZONE,"connect: HOST[%s]",s->to);

    bzero((void *)&sa,sizeof(struct sockaddr_in));

    if((sock = socket(AF_INET,SOCK_STREAM,0)) < 0)
        return NULL;
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&flag, sizeof(flag)) < 0)
        return NULL;

    saddr = make_addr(s->to);
    if(saddr == NULL)
        return NULL;

    sa.sin_family = AF_INET;
    sa.sin_port = htons(5269);
    sa.sin_addr.s_addr = saddr->s_addr;

    evt = pth_event(PTH_EVENT_TIME, pth_timeout(10,0));
    pth_fdmode(sock,PTH_FDMODE_NONBLOCK);
    if(pth_connect_ev(sock,(struct sockaddr*)&sa,sizeof sa, evt) < 0)
    {
        log_debug(ZONE,"pth_ssock error connecting");
        close(sock);
    }
    else
    {
        s->sock = sock;
        s->type = conn_OUT;

        /* tell the main thread we have a new connection */
        d = pmalloco(s->p,sizeof(_drop));
        d->s = s;
        pth_msgport_put(s->amp,(void*)d);
    }

    return s;
}

void pthsock_server_out(int type, xmlnode x, void *arg)
{
    ssock s = (ssock) arg;

    log_debug(ZONE,"out %d, received type %d",s->sock,type);

    /* we typicly shouldn't received anything here */
    switch (type)
    {
    case XSTREAM_ROOT:
        log_debug(ZONE,"root");
        break;

    case XSTREAM_NODE:
        log_debug(ZONE,"node");
        if(j_strcmp(xmlnode_get_name(x),"stream:error") == 0)
            log_warn("pthsock_s2s","remote server sent XML Stream error '%s'",xmlnode_get_data(xmlnode_get_firstchild(x)));
        else
            log_debug(ZONE,"pthsock_s2s received XML where it shouldn't");
        break;

    case XSTREAM_ERR:
        log_debug(ZONE,"error");
        if (pth_write(s->sock,"<stream::error>You sent malformed XML</stream:error>",52) <= 0)
            s->open = 0;
    case XSTREAM_CLOSE:
        log_debug(ZONE,"close");
        /* the other server shouldn't do this */
        log_debug(ZONE,"closing XSTREAM");
    }
}

result pthsock_server_packets(instance id, dpacket dp, void *arg)
{
    ssi si = (ssi) arg;
    pth_attr_t attr;
    pool p;
    ssock s;
    char *to;
    drop d, cur;
    jid from;

    to = dp->id->server;
    from = jid_new(xmlnode_pool(dp->x),xmlnode_get_attrib(dp->x,"from"));

    log_debug(ZONE,"pthsock_server looking up %s",to);

    /* XXX is this right?? */
    if (from)
        xmlnode_put_attrib(dp->x,"etherx:from",from->server);
    xmlnode_put_attrib(dp->x,"etherx:to",to);

    s = ghash_get(si->out_tab,to);

    if (s != NULL)
        if (s->type == conn_CLOSED)
            s = NULL;

    if (s == NULL)
    {
        log_debug(ZONE,"Creating new connection to %s",to);

        p = pool_new();
        s = pmalloco(p,sizeof(_ssock));
        s->type = conn_CONNECT;
        s->to = pstrdup(p,to);
        s->i = si->i;
        s->p = p;
        s->xs = xstream_new(p,pthsock_server_out,(void*)s);
        s->amp = si->amp;
        s->open = 0;

        ghash_put(si->out_tab,s->to,s);

        attr = pth_attr_new();
        pth_attr_set(attr,PTH_ATTR_JOINABLE,FALSE);

        pth_spawn(attr,pthsock_server_connect,(void*)s);

        pth_attr_destroy(attr);
    }

    d = pmalloco(xmlnode_pool(dp->x),sizeof(_drop));
    d->p = dp;
    d->s = s;

    if (s->type == conn_CONNECT) /* queue data */
    {
        log_debug(ZONE,"queueing data");

        if (s->dlist != NULL)
        {
            for(cur = s->dlist; cur->next != NULL; cur = cur->next);
            cur->next = d;
        }
        else
            s->dlist = d;
    }
    else /* it's connected */
        pth_msgport_put(si->wmp,(void*)d);

    log_debug(ZONE,"DONE");

    return r_DONE;
}

/* this is where we receive XML from other servers */
void pthsock_server_in(int type, xmlnode x, void *arg)
{
    ssock s = (ssock)arg;
    xmlnode h;
    char *block, *to;

    log_debug(ZONE,"pthsock_server_stream handling packet type %d",type);

    switch(type)
    {
    case XSTREAM_ROOT:
        log_debug(ZONE,"root received for %d",s->sock);

        if(xmlnode_get_attrib(x, "xmlns:etherx") == NULL && xmlnode_get_attrib(x,"etherx:secret") == NULL)
        {
            to = xmlnode_get_attrib(x,"to");
            if (to == NULL)
            {
                if (pth_write(s->sock,"<stream::error>You didn't send your to='host' attribute.</stream:error>",71) <= 0)
                    s->open = 0;

                s->type = conn_CLOSED;
            }
            else
            {
                h = xstream_header("jabber:server",NULL,to);
                block = xstream_header_char(h);
                if (pth_write(s->sock,block,strlen(block)) <= 0)
                {
                    s->type = conn_CLOSED;
                    s->open = 0;
                }
                xmlnode_free(h);
            }
        }
        else
            s->type = conn_CLOSED;   /* it wants to be a transport, to bad */

        break;

    case XSTREAM_NODE:
        log_debug(ZONE,"node received for %d",s->sock);

        xmlnode_hide_attrib(x,"etherx:from");
        xmlnode_hide_attrib(x,"etherx:to");

        deliver(dpacket_new(x),s->i);
        break;

    case XSTREAM_ERR:
        log_debug(ZONE,"failed to parse XML for %d",s->sock);
        if (pth_write(s->sock,"<stream::error>You sent malformed XML</stream:error>",52))
            s->open = 0;
    case XSTREAM_CLOSE:
        /* they closed there connections to us */
        log_debug(ZONE,"closing XML stream for %d",s->sock);
    }
}

void pthsock_server_remove(ssi si, ssock s)
{
    ssock cur, prev;

    /* remove connection from the list */
    for (cur = si->conns,prev = NULL; cur != NULL; prev = cur,cur = cur->next)
        if (cur->sock == s->sock)
        {
            if (prev != NULL)
                prev->next = cur->next;
            else
                si->conns = cur->next;
            break;
        }

    pool_free(s->p);
}

void pthsock_server_close(ssi si, ssock s)
{
    log_debug(ZONE,"closing socket '%d'",s->sock);

    if (s->type == conn_OUT)
        ghash_remove(si->out_tab,s->to);

    if (s->open) /* if this is true, then it's ok to still write to this socket */
    {
        s->open = 0;
        pth_write(s->sock,"</stream:stream>",16);
    }

    s->type = conn_CLOSED;
    close(s->sock);
}

int pthsock_server_write(ssi si, ssock s, dpacket p)
{
    char *block;

    log_debug(ZONE,"write for %d",s->sock);

    xmlnode_hide_attrib(p->x,"sto");
    xmlnode_hide_attrib(p->x,"sfrom");

    block = xmlnode2str(p->x);

    log_debug(ZONE,"<<<< %s",block);

    /* write the packet */
    if(pth_write(s->sock,block,strlen(block)) <= 0)
    {
        s->open = 0;
        pthsock_server_close(si,s);
        return 0;
    }

    pool_free(p->p);

    return 1;
}

typedef struct tout_st
{
    struct timeval last;
    struct timeval timeout;
} tout;

int pthsock_server_time(void *arg)
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

void *pthsock_server_main(void *arg)
{
    ssi si = (ssi) arg;
    tout t;
    pth_msgport_t wmp, amp;
    pth_event_t aevt, wevt, tevt, ering;
    fd_set rfds, afds;
    ssock cur, s;
    drop d;
    char buff[1024], *block;
    xmlnode x;
    int len, asock, sock;
    pool p;
    struct sockaddr_in sa;
    size_t sa_size = sizeof(sa);

    asock = si->asock;
    amp = si->amp;
    wmp = si->wmp;

    t.timeout.tv_sec = 0;
    t.timeout.tv_usec = 20000;
    t.last.tv_sec = 0;

    aevt = pth_event(PTH_EVENT_MSG,amp);
    wevt = pth_event(PTH_EVENT_MSG,wmp);
    tevt = pth_event(PTH_EVENT_FUNC,pthsock_server_time,&t,pth_time(0,20000));
    ering = pth_event_concat(aevt,wevt,tevt,NULL);

    FD_ZERO(&rfds);
    FD_SET(asock,&rfds);

    while (1)
    {
        if (pth_select_ev(FD_SETSIZE,&rfds,NULL,NULL,NULL,ering) > 0)
        {
            log_debug(ZONE,"select");
            FD_ZERO(&afds);

            if (FD_ISSET(asock,&rfds))
            {
                sock = pth_accept(asock,(struct sockaddr*)&sa,(int*)&sa_size);
                if(sock < 0)
                    break;

                log_debug(ZONE,"pthsock_server: new socket accepted (fd: %d, ip: %s, port: %d)",
                          sock,inet_ntoa(sa.sin_addr),ntohs(sa.sin_port));

                p = pool_heap(2*1024);
                s = pmalloco(p, sizeof(_ssock));
                s->p = p;
                s->xs = xstream_new(p,pthsock_server_in,(void*)s);
                s->sock = sock;
                s->i = si->i;

                FD_SET(s->sock,&afds);
                s->next = si->conns;
                si->conns = s;
            }

            FD_SET(asock,&afds);

            cur = si->conns;
            while(cur != NULL)
            {
                log_debug(ZONE,"checking cur->sock %d",cur->sock);
                if (cur->type == conn_CLOSED)
                {
                    pthsock_client_release(si,cur);
                }
                if (FD_ISSET(cur->sock,&rfds))
                {
                    len = pth_read(cur->sock,buff,1024);
                    if(len <= 0)
                    {
                        log_debug(ZONE,"Error reading on '%d', %s",cur->sock,strerror(errno));
                        cur->open = 0;
                        pthsock_server_close(si,cur);
                    }
                    else
                    {
                        log_debug(ZONE,"read %d bytes on %d:",len,cur->sock);

                        if (xstream_eat(cur->xs,buff,len) > XSTREAM_NODE || cur->type == conn_CLOSED)
                            pthsock_server_close(si,cur);
                        else
                            FD_SET(cur->sock,&afds);  
                    }
                }
                else
                    FD_SET(cur->sock,&afds);

                cur = cur->next;
            }
            rfds = afds;
        }

        /* handle packets that need to be writen */
        if (pth_event_occurred(wevt))
        {
            log_debug(ZONE,"write event");
            while (1)
            {
                /* get the packet */
                d = (drop)pth_msgport_get(wmp);
                if (d == NULL) break;

                s = d->s;
                if (!pthsock_server_write(si,s,d->p))
                    FD_CLR(s->sock,&rfds);
            }
        }

        /* add accepted connections to the fdset */
        if (pth_event_occurred(aevt))
        {
            log_debug(ZONE,"add event");
            while (1)
            {
                /* get the packet */
                d = (drop)pth_msgport_get(amp);
                if (d == NULL) break;

                s = d->s;
                FD_SET(s->sock,&rfds);
                s->next = si->conns;
                si->conns = s;

                /* start the stream */
                x = xstream_header("jabber:server",s->to,NULL);
                block = xstream_header_char(x);
                pth_write(s->sock,block,strlen(block));
                xmlnode_free(x);

                /* flush pending data */
                for (d = s->dlist; d != NULL; d = d->next)
                    if (!pthsock_server_write(si,s,d->p))
                        FD_CLR(d->s->sock,&rfds);
            }
        }
    }
}

/* everything starts here */
void pthsock_server(instance i, xmlnode x)
{
    ssi si;
    pth_attr_t attr;
    int asock;

    log_debug(ZONE,"pthsock_server loading");

    si = pmalloco(i->p,sizeof(_ssi));

    log_debug(ZONE,"pthsock_server_listen thread starting");

    asock = make_netsocket(5269,NULL,NETSOCKET_SERVER);
    if(asock < 0)
    {
        log_error(NULL,"pthsock_server is unable to create socket");
        return;
    }

    if(listen(asock,10) < 0)
    {
        log_error(NULL,"pthsock_server is unable to listen on port 5269");
        return;
    }

    si->asock = asock;

    /* write mp */
    si->wmp = pth_msgport_create("pthsock_server_wmp");
    /* used to notify main thread of a new connection */
    si->amp = pth_msgport_create("pthsock_server_amp");

    si->out_tab = ghash_create(20,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);

    register_phandler(i,o_DELIVER,pthsock_server_packets,(void*)si);

    attr = pth_attr_new();
    pth_attr_set(attr,PTH_ATTR_JOINABLE,FALSE);

    /* state main accept/read/write thread */
    pth_spawn(attr,pthsock_server_main,(void*)si);

    pth_attr_destroy(attr);
}
