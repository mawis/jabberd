/*
    <service id="pthsock client">
      <host>pth-csock.127.0.0.1</host>
      <load main='pthsock_client'>
	    <pthsock_client>../load/pthsock_client.so</pthsock_client>
      </load>
      <pthcsock xmlns='jabberd:pth-csock:config'>
	    <host>pth-csock.127.0.0.1</host>
        <listen>5222</listen>
      </pthcsock>
    </service>
*/

/* gcc -fPIC -shared -o pthsock_client.so pthsock_client.c -I../src -g -O2*/

#include <jabberd.h>

typedef enum { state_UNKNOWN, state_AUTHD, state_CLOSING } conn_state;

typedef struct reader_st
{
    instance i;
    pool p;
    conn_state state;
    xstream xs;
    pth_msgport_t mp;
    pth_event_t ering;
    char *id, *host;
    int sock;
    struct reader_st *next;
} *reader, _reader;

/* simple wrapper around the pth messages to pass packets */
typedef struct
{
    pth_message_t head; /* the standard pth message header */
    dpacket p;
    reader r;
} *drop, _drop;

reader pthsock_client__conns;

result pthsock_client_packets(instance id, dpacket p, void *arg)
{
    pth_msgport_t mp = (pth_msgport_t) arg;
    reader cur;
    drop d;
    int sock;

    if (p->id->user == NULL)
    {
        log_debug(ZONE,"no user %s",xmlnode2str(p->x));
        return;
    }

    sock = atoi(p->id->user); 
    if (sock == 0)
        return r_ERR;

    log_debug(ZONE,"looking up %d",sock);

    for (cur = pthsock_client__conns; cur != NULL; cur = cur->next)
    {
        if (sock == cur->sock)
        {
            d = pmalloc(xmlnode_pool(p->x),sizeof(_drop));
            d->p = p;
            d->r = cur;
            pth_msgport_put(mp,(void*)d);
            return r_DONE;
        }
    }

    return r_ERR;
}

void pthsock_client_stream(int type, xmlnode x, void *arg)
{
    reader r = (reader)arg;
    xmlnode h;
    char *block;

    log_debug(ZONE,"pthsock_client_stream handling packet type %d",type);

    switch(type)
    {
    case XSTREAM_ROOT:
        r->host = pstrdup(r->p,xmlnode_get_attrib(x,"to"));
        h = xstream_header("jabber:client",NULL,r->host);
        block = xstream_header_char(h);
        pth_write(r->sock,block,strlen(block));
        xmlnode_free(h);
        break;

    case XSTREAM_NODE:
        //log_debug(ZONE,">>>> %s",xmlnode2str(x));

        /* only allow auth and registration queries at this point */
        if (r->state == state_UNKNOWN)
        {
            xmlnode q = xmlnode_get_tag(x,"query");
            if (*(xmlnode_get_name(x)) != 'i' || (NSCHECK(q,NS_AUTH) == 0 && NSCHECK(q,NS_REGISTER) == 0))
            {
                log_debug(ZONE,"user tried to send packet in unknown state");
                r->state = state_CLOSING;
                /* bounce */
                pth_event_free(r->ering,PTH_FREE_THIS);
                r->ering = NULL;
                return;
            }
        }

        xmlnode_put_attrib(x,"sfrom",r->id);
        xmlnode_put_attrib(x,"sto",r->host);
        deliver(dpacket_new(x),r->i);
        break;

    case XSTREAM_ERR:
        pth_write(r->sock,"<stream::error>You sent malformed XML</stream:error>",52);
    case XSTREAM_CLOSE:
        log_debug(ZONE,"closing XSTREAM");
        if (r->state == state_AUTHD)
        {
            /* notify the session manager */
            h = xmlnode_new_tag("message");
            jutil_error(h,TERROR_DISCONNECTED);
            xmlnode_put_attrib(h,"sto",r->host);
            xmlnode_put_attrib(h,"sfrom",r->id);
            deliver(dpacket_new(h),r->i);
        }
        r->state = state_CLOSING;
    }
}

int pthsock_client_close(reader r)
{
    xmlnode x;
    reader cur, prev;

    log_debug(ZONE,"read thread exiting for %d",r->sock);

    if (r->state != state_CLOSING)
    {
        x = xmlnode_new_tag("message");
        jutil_error(x,TERROR_DISCONNECTED);
        xmlnode_put_attrib(x,"sto",r->host);
        xmlnode_put_attrib(x,"sfrom",r->id);
        deliver(dpacket_new(x),r->i);
    }
    else
        pth_write(r->sock,"</stream:stream>",16);

    /* remove connection from the list */
    for (cur = pthsock_client__conns,prev = NULL; cur != NULL; prev = cur,cur = cur->next)
        if (cur->sock == r->sock)
        {
            if (prev != NULL)
                prev->next = cur->next;
            else
                pthsock_client__conns = cur->next;
            break;
        }

    close(r->sock);
    pool_free(r->p);
}

int pthsock_client_write(reader r, dpacket p)
{
    char *block;
    int ret = 1;

    log_debug(ZONE,"incoming message for %d",r->sock);

    /* check to see if the session manager killed the session */
    if (*(xmlnode_get_name(p->x)) == 'm')
        if (j_strcmp(xmlnode_get_attrib(p->x,"type"),"error") == 0)
            if (j_strcmp(xmlnode_get_attrib(xmlnode_get_tag(p->x,"error"),"code"),"510") == 0)
            {
                log_debug(ZONE,"received disconnect message from session manager");
                r->state = state_CLOSING;
                pth_write(r->sock,"<stream:error>Disconnected</stream:error>",41);
                return 0;
            }

    if (r->state == state_UNKNOWN && *(xmlnode_get_name(p->x)) == 'i')
        if (j_strcmp(xmlnode_get_attrib(p->x,"type"),"result") == 0)
        {
            /* change the host id just incase */
            r->host = pstrdup(r->p,xmlnode_get_attrib(p->x,"sfrom"));
            r->state = state_AUTHD;
        }
        else
            /* they didn't get authed/registered */
            log_debug(ZONE,"user auth/registration falid");

    xmlnode_hide_attrib(p->x,"sto");
    xmlnode_hide_attrib(p->x,"sfrom");

    /* write the packet */
    block = xmlnode2str(p->x);

    //log_debug(ZONE,"<<<< %s",block);
   
    if(pth_write(r->sock,block,strlen(block)) <= 0)
        return 0;

    pool_free(p->p);

    return ret;
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
    pth_msgport_t wmp = (pth_msgport_t) arg, amp;
    pth_event_t aevt, wevt, tevt, ering;
    fd_set rfds;
    reader cur, r;
    drop d;
    char buff[1024], *block;
    int len, selc, maxfd;
    tout t;

    t.timeout.tv_sec = 0;
    t.timeout.tv_usec = 20000;
    t.last.tv_sec = 0;

    amp =  pth_msgport_find("pthsock_client_amp");
    aevt = pth_event(PTH_EVENT_MSG,amp);
    wevt = pth_event(PTH_EVENT_MSG,wmp);
    tevt = pth_event(PTH_EVENT_FUNC,pthsock_client_time,&t,pth_time(0,20000));
    ering = pth_event_concat(aevt,wevt,tevt,NULL);

    FD_ZERO(&rfds);
    maxfd = 0;

    while (1)
    {
        selc = pth_select_ev(maxfd + 1,&rfds,NULL,NULL,NULL,ering);

        if (selc > 0)
        {
            log_debug(ZONE,"select %d",selc);
            cur = pthsock_client__conns;
            while(cur != NULL)
            {
                if (FD_ISSET(cur->sock,&rfds))
                {
                    --selc;
                    len = pth_read(cur->sock,buff,1024);
                    if(len <= 0)
                    {
                        log_debug(ZONE,"Error reading on '%d', %s",cur->sock,strerror(errno));
                        FD_CLR(cur->sock,&rfds);
                        pthsock_client_close(cur);
                    }

                    log_debug(ZONE,"read %d bytes",len);
                    xstream_eat(cur->xs,buff,len);
                    if (cur->state == state_CLOSING)
                    {
                        FD_CLR(cur->sock,&rfds);
                        pthsock_client_close(cur);
                    }
                }
                if (selc == 0) break;   /* all done reading */
                cur = cur->next;
            }
        }

        /* handle packets that need to be writen */
        if (pth_event_occurred(wevt))
        {
            log_debug(ZONE,"write");
            while (1)
            {
                /* get the packet */
                d = (drop)pth_msgport_get(wmp);
                if (d == NULL) break;

                r = d->r;
                if (pthsock_client_write(r,d->p) == 0)
                {
                    if (r->state != state_CLOSING)
                    {
                        log_debug(ZONE,"pth_write failed");
                    }

                    FD_CLR(d->r->sock,&rfds);
                    pthsock_client_close(d->r);
                }
            }
        }

        /* add accepted connections to the fdset */
        if (pth_event_occurred(aevt))
        {
            log_debug(ZONE,"accept");
            while (1)
            {
                /* get the packet */
                d = (drop)pth_msgport_get(amp);
                if (d == NULL) break;
                r = d->r;
                FD_SET(r->sock,&rfds);
                if (r->sock > maxfd)
                    maxfd = r->sock;
                log_debug(ZONE,"%d max",maxfd);
            }
        }
    }
}

void *pthsock_client_listen(void *arg)
{
    xmlnode cfg = (xmlnode)arg;
    instance i;
    struct sockaddr_in sa;
    size_t sa_size = sizeof(sa);
    int sock, s;
    pth_msgport_t mp;
    reader r;
    pool p;
    drop d;
    char *host, *port;

    log_debug(ZONE,"pthsock_client_listen thread starting");

    i = (instance) xmlnode_get_vattrib(cfg,"id");
    host = xmlnode_get_tag_data(cfg,"host");
    port = xmlnode_get_tag_data(cfg,"listen");

    if (host == NULL || port == NULL)
    {
        log_error(ZONE,"pthsock_client invaild config");
        return;
    }

    s = make_netsocket(atoi(port),NULL,NETSOCKET_SERVER);
    if(s < 0)
    {
        log_error(NULL,"pthsock_client is unable to listen on %d",atoi(port));
        return NULL;
    }

    if(listen(s,10) < 0)
    {
        log_error(NULL,"pthsock_client is unable to listen on %d",atoi(port));
        return NULL;
    }

    mp = pth_msgport_find("pthsock_client_amp");
    pthsock_client__conns = NULL;

    while(1)
    {
        sock = pth_accept(s,(struct sockaddr*)&sa,(int*)&sa_size);
        if(sock < 0)
            break;

        log_debug(ZONE,"pthsock_client: new socket accepted (fd: %d, ip: %s, port: %d)",
                  sock,inet_ntoa(sa.sin_addr),ntohs(sa.sin_port));

        p = pool_heap(2*1024);
        r = pmalloco(p, sizeof(_reader));
        r->p = p;   
        r->i = i;
        r->xs = xstream_new(p,pthsock_client_stream,(void*)r);
        r->sock = sock;
        r->state = state_UNKNOWN;
        r->mp = pth_msgport_create("pthscok");
        r->id = pmalloco(p,strlen(host) + 11 * sizeof(char));
        snprintf(r->id,strlen(host) + 10 * sizeof(char),"%d@%s",sock,host);

        log_debug(ZONE,"socket id:%s",r->id);

        r->next = pthsock_client__conns;
        pthsock_client__conns = r;

        d = pmalloc(p,sizeof(_drop));
        d->r = r;
        pth_msgport_put(mp,(void*)d);
    }

    log_error(NULL,"pthsock_client listen on 5222 failed");

    return NULL;
}

/* everything starts here */
void pthsock_client(instance i, xmlnode x)
{
    int s;
    pth_attr_t attr;
    xmlnode cfg;
    xdbcache xc;
    pth_msgport_t wmp;

    log_debug(ZONE,"pthsock_client loading");

    wmp = pth_msgport_create("pthsock_client_wmp");
    pth_msgport_create("pthsock_client_amp");

    register_phandler(i,o_DELIVER,pthsock_client_packets,(void*)wmp);

    xc = xdb_cache(i);
    cfg = xdb_get(xc,NULL,jid_new(xmlnode_pool(x),"config@-internal"),"jabberd:pth-csock:config");
    xmlnode_put_vattrib(cfg,"id",(void*)i);

    attr = pth_attr_new();
    pth_attr_set(attr,PTH_ATTR_JOINABLE,FALSE);

    /* state main read/write thread */
    pth_spawn(attr,pthsock_client_main,(void*)wmp);

    /* start thread with this socket */
    pth_spawn(attr,pthsock_client_listen,(void*)cfg);

    pth_attr_destroy(attr);
}
