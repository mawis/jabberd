/* listens on 5222, simplistic thread spawning and session IO matching and delivery */

/* gcc -fPIC -shared -o pthsock_client.so pthsock_client.c -I../src */

#include <jabberd.h>

/* simple wrapper around the pth messages to pass packets */
typedef struct
{
    pth_message_t head; /* the standard pth message header */
    dpacket p;
} *drop, _drop;

typedef enum { state_UNKNOWN, state_AUTHD, state_CLOSING } conn_state;

typedef struct reader_st
{
    instance i;
    pool p;
    pth_msgport_t mp;
    pth_event_t ering;
    int sock;
    xstream xs;
    conn_state state;
    char *id, *host;
    struct reader_st *next;
} *reader, _reader;

reader pthsock_client__conns;

result pthsock_client_packets(instance id, dpacket p, void *arg)
{
    char *sto;
    reader cur;
    drop d;
    int sock;

    sto = xmlnode_get_attrib(p->x,"sto");
    for (cur = pthsock_client__conns; cur != NULL; cur = cur->next)
        if (strcmp(sto,cur->id) == 0)
            break;

    if (cur == NULL)
        r_PASS;

    d = pmalloc(xmlnode_pool(p->x),sizeof(_drop));
    d->p = p;
    pth_msgport_put(cur->mp,(void*)d);

    return r_DONE;
}

void pthsock_client_stream(int type, xmlnode x, void *arg)
{
    reader r = (reader)arg;
    char *block, *attr;
    xmlnode cur;

    log_debug(ZONE,"pthsock_client_stream handling packet type %d",type);

    switch(type)
    {
    case XSTREAM_ROOT:
        cur = xstream_header("jabber:client",NULL,NULL);
        r->host = pstrdup(r->p,xmlnode_get_attrib(x,"to"));
        block = xstream_header_char(cur);
        pth_write(r->sock,block,strlen(block));
        xmlnode_free(cur);
        break;

    case XSTREAM_NODE:
        if (r->state == state_UNKNOWN) /* only allow auth and registration query at this point */
        {
            if (*(xmlnode_get_name(x)) == 'i')
            {
                attr = xmlnode_get_attrib(xmlnode_get_tag(x,"query"),"xmlns");
                if (attr == NULL)
                    r->state = state_CLOSING;
                else if (strcmp(attr,"jabber:iq:auth") && strcmp(attr,"jabber:iq:register"))
                    r->state = state_CLOSING;
            }
            else
                r->state = state_CLOSING;
        }

        if (r->state == state_CLOSING)
        {
            /* bounce */
            pth_event_free(r->ering,PTH_FREE_THIS);
            r->ering = NULL;
            return;
        }

        xmlnode_put_attrib(x,"sfrom",r->id);
        xmlnode_put_attrib(x,"sto",r->host);
        deliver(dpacket_new(x),r->i);
        break;

    default:
    }
}

void *pthsock_client_reader(void *arg)
{
    reader r = (reader)arg;
    pth_event_t revt, wevt;
    char buff[1024], *attr, *block;
    xstream xs;
    drop d;
    int rc, len;
    dpacket p;

    log_debug(ZONE,"pthsock_client_reader thread starting");

    xs = xstream_new(r->p, pthsock_client_stream, arg);
    revt = pth_event(PTH_EVENT_FD|PTH_UNTIL_FD_READABLE,r->sock);
    wevt = pth_event(PTH_EVENT_MSG,r->mp);
    r->ering = pth_event_concat(revt,wevt,NULL);

    while(pth_wait(r->ering) > 0)
    {
        /* handle reading the incoming stream */
        if(pth_event_occurred(revt))
        {
            len = pth_read(r->sock,buff,1024);
            if(len <= 0)
                break;

            rc = xstream_eat(xs,buff,len);
            if (rc > XSTREAM_NODE)
                break;
        }

        if(pth_event_occurred(wevt))
        {
            log_debug(ZONE,"incoming message for %d",r->sock);

            /* get packet */
            d = (drop)pth_msgport_get(r->mp);
            p = d->p;

            if (*(xmlnode_get_name(p->x)) == 'm')
            {
                attr = xmlnode_get_attrib(p->x,"type");
                if (attr != NULL && strcmp(attr,"error") == 0)
                {
                    attr = xmlnode_get_attrib(xmlnode_get_tag(p->x,"error"),"code");
                    if (attr != NULL && strcmp(attr,"510"))
                    {
                        r->state = state_CLOSING;
                        break;
                    }
                }
            }

            if (r->state = state_UNKNOWN)
            {
                if (*(xmlnode_get_name(p->x)) == 'i')
                {
                    if (strcmp(xmlnode_get_attrib(p->x,"type"),"result") == 0)
                    {
                        /* change the host id */
                        r->host = pstrdup(r->p,xmlnode_get_attrib(p->x,"sfrom"));
                        r->state = state_AUTHD;
                    }
                    else
                    {
                        /* they didn't get authed/registered */
                        r->state = state_CLOSING;
                        break;
                    }
                }
            }

            xmlnode_hide_attrib(p->x,"sto");
            xmlnode_hide_attrib(p->x,"sfrom");

            /* write the packet */
            block = xmlnode2str(p->x);
            if(pth_write(r->sock,block,strlen(block)) <= 0)
                break;

            pool_free(p->p);
            p = NULL;
        }
    }

    log_debug(ZONE,"read thread exiting for %d",r->sock);

    if (rc == XSTREAM_ERR)
    {
        pth_write(r->sock,"<stream::error>You sent malformed XML</stream:error>",52);
        pth_write(r->sock,"</stream:stream>",16);
    }
    else if (rc == XSTREAM_CLOSE || r->state == state_CLOSING)
        pth_write(r->sock,"</stream:stream>",16);

    if(p != NULL)
    { 
        /* bounce */
        pool_free(p->p);
    }

    /* bounce any waiting in the mp */
    for(d = (drop)pth_msgport_get(r->mp);d != NULL; d = (drop)pth_msgport_get(r->mp))
    {
        p = d->p;
        /* bounce */
        pool_free(p->p);
    }

    close(r->sock);
    /* XXX remove from list */
    pool_free(r->p);
    pth_event_free(wevt,PTH_FREE_THIS);
    pth_event_free(revt,PTH_FREE_THIS);

    return NULL;
}

void *pthsock_client_listen(void *arg)
{
    xmlnode cfg = (xmlnode)arg;
    instance i;
    struct sockaddr_in sa;
    size_t sa_size = sizeof(sa);
    int sock, s;
    reader r;
    pool p;
    pth_attr_t attr;
    char *host;

    log_debug(ZONE,"pthsock_client_listen thread starting");

    s = make_netsocket(5222,NULL,NETSOCKET_SERVER);
    if(s < 0)
    {
        log_error(NULL,"pthsock_client is unable to listen on 5222");
        return NULL;
    }

    if(listen(s,10) < 0)
    {
        log_error(NULL,"pthsock_client is unable to listen on 5222");
        return NULL;
    }

    i = (instance) xmlnode_get_vattrib(cfg,"id");
    host = xmlnode_get_tag_data(cfg,"host");

    while(1)
    {
        sock = pth_accept(s,(struct sockaddr*)&sa,(int*)&sa_size);
        if(sock < 0)
            break;

        log_debug(ZONE,"pthsock_client: new socket accepted (fd: %d, ip: %s, port: %d)",sock,inet_ntoa(sa.sin_addr),ntohs(sa.sin_port));

        p = pool_heap(2*1024);
        r = pmalloco(p, sizeof(_reader));
        r->p = p;
        r->sock = sock;
        r->i = i;
        r->state = state_UNKNOWN;
        r->id = pmalloco(p,strlen(host) + 6);
        snprintf(r->id,strlen(host) + 5,"%d@pth-csock.%s",sock,host);

        r->next = pthsock_client__conns;
        pthsock_client__conns = r;

        /* start thread with this socket */
        attr = pth_attr_new();
        pth_attr_set(attr,PTH_ATTR_JOINABLE,FALSE);
        pth_spawn(attr, pthsock_client_reader,(void *)r);
        pth_attr_destroy(attr);
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

    log_debug(ZONE,"pthsock_client loading");

    register_phandler(i,o_DELIVER,pthsock_client_packets,NULL);

    xc = xdb_cache(i);
    cfg = xdb_get(xc,NULL,jid_new(xmlnode_pool(x),"config@-internal"),"pth-csock");
    xmlnode_put_vattrib(cfg,"id",(void*)i);

    /* start thread with this socket */
    attr = pth_attr_new();
    pth_attr_set(attr,PTH_ATTR_JOINABLE,FALSE);
    pth_spawn(attr,pthsock_client_listen,(void*)cfg);
    pth_attr_destroy(attr);
}
