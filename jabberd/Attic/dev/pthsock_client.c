/*
    <service id="pthsock client">
      <host>127.0.0.1</host>
      <load main='pthsock_client'>
	    <pthsock_client>../load/pthsock_client.so</pthsock_client>
      </load>
      <pthcsock xmlns='pth-csock'>
	    <host>pth-csock.127.0.0.1</host>
        <port>5222</port>
      </pthcsock>
    </service>
*/

/* gcc -fPIC -shared -o pthsock_client.so pthsock_client.c -I../src */

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
        return r_PASS;

    log_debug(ZONE,"looking up %s",sock);

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

    log_debug(ZONE,"not found");

    return r_PASS;
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
        // log_debug(ZONE,"node %s",xmlnode2str(x));

        /* only allow auth and registration queries at this point */
        if (r->state == state_UNKNOWN)
        {
            xmlnode q = xmlnode_get_tag(x,"query");
            if (*(xmlnode_get_name(x)) != 'i' || (NSCHECK(q,NS_AUTH) == 0 && NSCHECK(q,NS_REGISTER) == 0))
            {
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

    default:
    }
}

int pthsock_client_close(reader r)
{
    xmlnode x;
    reader cur, prev;
    int rc;

    log_debug(ZONE,"read thread exiting for %d",r->sock);

    rc = xstream_eat(r->xs,NULL,0);

    if (rc == XSTREAM_ERR)
    {
        pth_write(r->sock,"<stream::error>You sent malformed XML</stream:error>",52);
        pth_write(r->sock,"</stream:stream>",16);
    }
    else if (rc == XSTREAM_CLOSE || r->state == state_CLOSING)
        pth_write(r->sock,"</stream:stream>",16);

    if (r->state != state_CLOSING)
    {
        x = xmlnode_new_tag("message");
        jutil_error(x,TERROR_DISCONNECTED);
        xmlnode_put_attrib(x,"sto",r->host);
        xmlnode_put_attrib(x,"sfrom",r->id);
        deliver(dpacket_new(x),r->i);
    }

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

    log_debug(ZONE,"incoming message for %d",r->sock);

    /* check to see if it's the session manager killing the session */
    if (*(xmlnode_get_name(p->x)) == 'm')
        if (j_strcmp(xmlnode_get_attrib(p->x,"type"),"error") == 0)
            if (j_strcmp(xmlnode_get_attrib(xmlnode_get_tag(p->x,"error"),"code"),"510") == 0)
            {
                log_debug(ZONE,"received disconnect message from session manager");
                r->state = state_CLOSING;
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
        {
            /* they didn't get authed/registered */
            log_debug(ZONE,"user auth/registration falid");
            r->state = state_CLOSING;
            return 0;
        }

    log_debug(ZONE,"writting %d",r->sock);

    xmlnode_hide_attrib(p->x,"sto");
    xmlnode_hide_attrib(p->x,"sfrom");

    /* write the packet */
    block = xmlnode2str(p->x);
    if(pth_write(r->sock,block,strlen(block)) <= 0)
        return 0;

    pool_free(p->p);

    return 1;
}

void *pthsock_client_main(void *arg)
{
    pth_msgport_t wmp = (pth_msgport_t) arg, amp;
    fd_set rfds;
    struct timeval tv;
    int selc;
    int maxfd = 0;
    reader cur;
    char buff[1024], *block;
    drop d;
    int len, rc;
    reader r;

    amp =  pth_msgport_find("pthsock_client_amp");

    FD_ZERO(&rfds);

    tv.tv_sec = 0;
    tv.tv_usec = 10;

    while (1)
    {
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        selc = pth_select(maxfd + 1,&rfds,NULL,NULL,&tv);

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
                        log_debug(ZONE,"Error reading on '%d', %s",cur->sock,sterror(errno));
                        FD_CLR(cur->sock,&rfds);
                        pthsock_client_close(cur);
                    }

                    rc = xstream_eat(cur->xs,buff,len);
                    if (rc > XSTREAM_NODE || cur->state == state_CLOSING)
                    {
                        FD_CLR(cur->sock,&rfds);
                        pthsock_client_close(cur);
                    }
                }
                if (selc == 0) break;   /* all done reading */
                cur = cur->next;
            }
        }
        else if (selc < 0)
            log_debug(ZONE,"select error");

        /* handle packets that need to be writen */
        while (1)
        {
            /* get the packet */
            d = (drop)pth_msgport_get(wmp);
            if (d == NULL) break;

            log_debug(ZONE,"write");
            if (pthsock_client_write(d->r,d->p) == 0)
            {
                FD_CLR(d->r->sock,&rfds);
                pthsock_client_close(d->r);
            }
        }

        /* add acepted connections to the fdset */
        while (1)
        {
            /* get the packet */
            d = (drop)pth_msgport_get(amp);
            if (d == NULL) break;
            log_debug(ZONE,"accept");
            FD_SET(d->r->sock,&rfds);
            if (d->r->sock > maxfd)
                maxfd = d->r->sock;
            log_debug(ZONE,"%d max",maxfd);
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
    port = xmlnode_get_tag_data(cfg,"port");

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
        r->id = pmalloco(p,strlen(host) + 6 * sizeof(char));
        snprintf(r->id,strlen(host) + 5 * sizeof(char),"%d@%s",sock,host);

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
    cfg = xdb_get(xc,NULL,jid_new(xmlnode_pool(x),"config@-internal"),"pth-csock");
    xmlnode_put_vattrib(cfg,"id",(void*)i);

    attr = pth_attr_new();
    pth_attr_set(attr,PTH_ATTR_JOINABLE,FALSE);

    /* state main read/write thread */
    pth_spawn(attr,pthsock_client_main,(void*)wmp);
    pth_yield(NULL);

    /* start thread with this socket */
    pth_spawn(attr,pthsock_client_listen,(void*)cfg);

    pth_attr_destroy(attr);
}
