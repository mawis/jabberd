/*

  <service id="v90modem60.auriga.bigsky.net s2s">
    <host/>
    <load main="pthsock_server">
      <pthsock_server>../load/pthsock_server.so</pthsock_server>
    </load>
  </service>

*/

/* gcc -fPIC -shared -o pthsock_server.so pthsock_server.c -I../src -g -O2 -Wall */

#include <jabberd.h>

/* conn_IN - another server intiated this connection to send xml to us
   conn_OUT - we intiated this connection
   conn_CLOSE - this connection is scheduled for removal
*/
typedef enum { conn_IN, conn_OUT, conn_CLOSE } conn_type;

typedef struct ssock_st
{
    pool pl;
    instance i;
    pth_msgport_t amp;
    conn_type type;
    xstream xs;
    char *to;
    int sock;
    dpacket p;
    struct ssock_st *next;
} *ssock, _ssock;

/* server 2 server instance */
typedef struct ssi_st
{
    pth_msgport_t wmp;
    pth_msgport_t amp;
    ssock conns;
    instance i;
    xmlnode cfg;
} *ssi, _ssi;

/* simple wrapper around the pth messages to pass packets */
typedef struct drop_st
{
    pth_message_t head; /* the standard pth message header */
    dpacket p;
    ssock s;
} *drop, _drop;

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
        /* tell the main thread we have a new connection */
        d = pmalloco(s->pl,sizeof(_drop));
        d->s = s;
        pth_msgport_put(s->amp,(void*)d); /* XXX */
    }

    return s;
}

void pthsock_server_out(int type, xmlnode x, void *arg)
{
    ssock s = (ssock) arg;

    /* we typicly shouldn't received anything here */
    switch (type)
    {
    case XSTREAM_ROOT:
        break;

    case XSTREAM_NODE:
        if(j_strcmp(xmlnode_get_name(x),"stream:error") == 0)
            log_warn("pthsock_s2s","remote server sent XML Stream error '%s'",xmlnode_get_data(xmlnode_get_firstchild(x)));
        else
            log_debug(ZONE,"pthsock_s2s received XML where it shouldn't");
        break;

    case XSTREAM_ERR:
        pth_write(s->sock,"<stream::error>You sent malformed XML</stream:error>",52);
    case XSTREAM_CLOSE:
        /* the other server shouldn't do this */
        log_debug(ZONE,"closing XSTREAM");
        s->type = conn_CLOSE;
    }
}

result pthsock_server_packets(instance id, dpacket p, void *arg)
{
    ssi si = (ssi) arg;
    pth_attr_t attr;
    pool pl;
    ssock s;
    char *to;

    /* keep a hash of OUT connections and reuse? */
    /* queue d in s->dq? */

    to = p->id->server;

    log_debug(ZONE,"pthsock_server looking up %s",to);

    pl = pool_new();
    s = pmalloco(pl,sizeof(_ssock));
    s->p = p;
    s->type = conn_OUT;
    s->to = pstrdup(pl,to);
    s->i = si->i;
    s->pl = pl;
    s->xs = xstream_new(pl,pthsock_server_out,(void*)s);
    s->amp = si->amp;

    s->next = si->conns;
    si->conns = s;

    attr = pth_attr_new();
    pth_attr_set(attr,PTH_ATTR_JOINABLE,FALSE);

    pth_spawn(attr,pthsock_server_connect,(void*)s);

    pth_attr_destroy(attr);

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

        if(xmlnode_get_attrib(x, "xmlns:etherx") != NULL && xmlnode_get_attrib(x,"etherx:secret") != NULL) /* it wants to be a transport, to bad */
        {
            s->type = conn_CLOSE;
        }

        to = xmlnode_get_attrib(x,"to");
        if (to == NULL)
        {
            pth_write(s->sock,"<stream::error>You didn't send your to='host' attribute.</stream:error>",71);
            s->type = conn_CLOSE;
        }

        h = xstream_header("jabber:server",NULL,to);
        block = xstream_header_char(h);
        pth_write(s->sock,block,strlen(block));
        xmlnode_free(h);
        break;

    case XSTREAM_NODE:
        log_debug(ZONE,"node received for %d",s->sock);
        log_debug(ZONE,">>>> %s",xmlnode2str(x));

        deliver(dpacket_new(x),s->i);
        break;

    case XSTREAM_ERR:
        pth_write(s->sock,"<stream::error>You sent malformed XML</stream:error>",52);
        log_debug(ZONE,"error XSTREAM");
        s->type = conn_CLOSE;
    case XSTREAM_CLOSE:
        /* they closed there connections to us */
        log_debug(ZONE,"closing XSTREAM");
        s->type = conn_CLOSE;
    }
}

void pthsock_server_close(ssi si, ssock s)
{
    ssock cur, prev;

    log_debug(ZONE,"read thread exiting for %d",s->sock);

    if (s->type == conn_CLOSE) /* if this is true, then it's ok to still write to this socket */
        pth_write(s->sock,"</stream:stream>",16);

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

    close(s->sock);
    pool_free(s->pl);
}

int pthsock_server_write(ssock s, dpacket p)
{
    char *block;

    log_debug(ZONE,"write for %d",s->sock);

    xmlnode_hide_attrib(p->x,"sto");
    xmlnode_hide_attrib(p->x,"sfrom");

    block = xmlnode2str(p->x);

    log_debug(ZONE,"<<<< %s",block);

    /* write the packet */
    if(pth_write(s->sock,block,strlen(block)) <= 0)
        return 0;

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
    fd_set rfds;
    ssock cur, s;
    drop d;
    char buff[1024], *block;
    xmlnode x;
    int len, selc, maxfd;

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
    maxfd = 0;

    while (1)
    {
        selc = pth_select_ev(maxfd + 1,&rfds,NULL,NULL,NULL,ering);

        if (selc > 0)
        {
            log_debug(ZONE,"select %d",selc);
            cur = si->conns;
            while(cur != NULL)
            {
log_debug(ZONE,"checking cur->sock %d",cur->sock);
                if (FD_ISSET(cur->sock,&rfds))
                {
                    --selc;
                    len = pth_read(cur->sock,buff,1024);
                    if(len <= 0)
                    {
                        log_debug(ZONE,"Error reading on '%d', %s",cur->sock,strerror(errno));
                        FD_CLR(cur->sock,&rfds);
                        pthsock_server_close(si,cur);
                    }

                    log_debug(ZONE,"read %d bytes on %d:",len,cur->sock);
                    xstream_eat(cur->xs,buff,len);
                    if (cur->type == conn_CLOSE)
                    {
                        FD_CLR(cur->sock,&rfds);
                        pthsock_server_close(si,cur);
                    }
                }
                if (selc == 0) break;   /* all done reading */
                cur = cur->next;
            }
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
                if (pthsock_server_write(s,d->p) == 0)
                {
                    log_debug(ZONE,"pth_write failed");
                    /* bounce d->p */

                    FD_CLR(d->s->sock,&rfds);
                    pthsock_server_close(si,d->s);
                }
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
                if (s->sock > maxfd)
                    maxfd = s->sock;

                if (s->type == conn_OUT) /* flush pending data */
                {
                    x = xstream_header("jabber:server",s->to,NULL);
                    block = xstream_header_char(x);
                    pth_write(s->sock,block,strlen(block));
                    xmlnode_free(x);

                    if (pthsock_server_write(s,s->p) == 0)
                    {
                        log_debug(ZONE,"pth_write failed for OUT");
                        /* bounce d->p */

                        FD_CLR(d->s->sock,&rfds);
                        pthsock_server_close(si,d->s);
                    }  
                }
            }
        }
    }
}

void *pthsock_server_listen(void *arg)
{
    ssi si = (ssi) arg;
    ssock s;
    drop d;
    pool p;
    pth_msgport_t amp;
    struct sockaddr_in sa;
    size_t sa_size = sizeof(sa);
    int sock, asock;

    log_debug(ZONE,"pthsock_server_listen thread starting");

    asock = make_netsocket(5269,NULL,NETSOCKET_SERVER);
    if(asock < 0)
    {
        log_error(NULL,"pthsock_server is unable to listen on port 5269");
        return NULL;
    }

    if(listen(asock,10) < 0)
    {
        log_error(NULL,"pthsock_server is unable to listen on port 5269");
        return NULL;
    }

    amp = si->amp;
    while(1)
    {
        sock = pth_accept(asock,(struct sockaddr*)&sa,(int*)&sa_size);
        if(sock < 0)
            break;

        log_debug(ZONE,"pthsock_server: new socket accepted (fd: %d, ip: %s, port: %d)",
                  sock,inet_ntoa(sa.sin_addr),ntohs(sa.sin_port));

        p = pool_heap(2*1024);
        s = pmalloco(p, sizeof(_ssock));
        s->pl = p;
        s->xs = xstream_new(p,pthsock_server_in,(void*)s);
        s->sock = sock;
        s->i = si->i;

        s->next = si->conns;
        si->conns = s;

        /* tell the main thread we accepted a connection */
        d = pmalloc(p,sizeof(_drop));
        d->s = s;
        pth_msgport_put(amp,(void*)d);
    }

    log_error(NULL,"pthsock_server listen on 5222 failed");

    return NULL;
}

/* everything starts here */
void pthsock_server(instance i, xmlnode x)
{
    ssi si;
    xdbcache xc;
    pth_attr_t attr;

    log_debug(ZONE,"pthsock_server loading");

    si = pmalloco(i->p,sizeof(_ssi));

    /* write mp */
    si->wmp = pth_msgport_create("pthsock_server_wmp");
    /* used to notify main thread of a new connection */
    si->amp = pth_msgport_create("pthsock_server_amp"); 

    /* get the config */
    xc = xdb_cache(i);
    si->cfg = xdb_get(xc,NULL,jid_new(xmlnode_pool(x),"config@-internal"),"jabberd:pth-ssock:config");

    register_phandler(i,o_DELIVER,pthsock_server_packets,(void*)si);

    attr = pth_attr_new();
    pth_attr_set(attr,PTH_ATTR_JOINABLE,FALSE);

    /* state main read/write thread */
    pth_spawn(attr,pthsock_server_main,(void*)si);

    /* start thread to accepted new connections */
    pth_spawn(attr,pthsock_server_listen,(void*)si);

    pth_attr_destroy(attr);
}
