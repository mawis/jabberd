/* listens on 5222, simplistic thread spawning and session IO matching and delivery */

#include <jabberd.h>

/* need to create master dynamic flat array, to match session ID's to reader/writer structs */

result pthsock_client_packets(instance id, dpacket p, void *arg)
{

    /* match up incoming packets to their socket, and write */
    return r_OK;
}

typedef struct reader_struct
{
    instance id;
    int sock;
    xstream xs;
    int status;
    pool p;
} *reader, _reader;


void pthsock_client_stream(int type, xmlnode x, void *arg)
{
    reader r = (reader)arg;

    log_debug(ZONE,"pthsock_client_stream handling packet type %d",type);

    switch(type)
    {
    case XSTREAM_ERR:
        log_debug(ZONE,"pthsock_client_stream handling packet type %d",type);
        /* send stream:error */
        /* yes, fall through */
    case XSTREAM_CLOSE:
        /* send closing </stream:stream>, then close the socket */
        break;
    case XSTREAM_ROOT:
        /* store the domain we're going to */
        break;
    case XSTREAM_NORM:
        /* set sid="" and from="" and deliver the packet */
        break;
    }

    
}

void *pthsock_client_reader(void *arg)
{
    reader r = (reader)arg;

    log_debug(ZONE,"pthsock_client_reader thread starting");

    r->xs = xstream_new(r->p, pthsock_client_stream, arg);

    while(1)
    {
        /* block on read calls, feed data to xstream_eat() */
    }

    return NULL;
}

void *pthsock_client_listen(void *arg)
{
    instance id = (instance)arg;
    struct sockaddr_in sa;
    size_t sa_size = sizeof(sa);
    rlimit all_r, ip_r;
    int sock, s;
    reader r;
    pool p;
    pth_attr_t attr;

    log_debug(ZONE,"pthsock_client_listen thread starting");

    s = make_netsocket(5222, NULL, NETSOCKET_SERVER);
    if(s < 0)
    {
        log_error(NULL,"pthsock_client is unable to listen on 5222");
        return NULL;
    }

    if(listen(s, 10) < 0)
    {
        log_error(NULL,"pthsock_client is unable to listen on 5222");
        return NULL;
    }

    while(1)
    {
        sock = pth_accept(s, (struct sockaddr *) &sa, (int *) &sa_size);
        if(sock < 0)
            break;

        log_debug(ZONE,"pthsock_client: new socket accepted (fd: %d, ip: %s, port: %d)", sock, inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));

        p = pool_heap(2*1024);
        r = pmalloco(p, sizeof(_reader));
        r->p = p;
        r->sock = sock;
        r->id = id;
        
        /* start thread with this socket */
        attr = pth_attr_new();
        pth_attr_set(attr, PTH_ATTR_JOINABLE, FALSE);
        pth_spawn(attr, pthsock_client_reader, (void *)r);
        pth_attr_destroy(attr);
    }

    log_error(NULL,"pthsock_client listen on 5222 failed");
    return NULL;
}

/* everything starts here */
void pthsock_client(instance id, xmlnode x)
{
    int s;
    pth_attr_t attr;

    register_phandler(id, o_LAST, pthsock_client_packets, NULL);

    log_debug(ZONE,"pthsock_client starting");

    /* start thread with this socket */
    attr = pth_attr_new();
    pth_attr_set(attr, PTH_ATTR_JOINABLE, FALSE);
    pth_spawn(attr, pthsock_client_listen, (void *)id);
    pth_attr_destroy(attr);

}

