#include "jabberd.h"

/* how many seconds until packets begin to "bounce" that should be delivered */
#define ACCEPT_PACKET_TIMEOUT 600
/* how many seconds a socket has to send a valid handshake */
#define ACCEPT_HANDSHAKE_TIMEOUT 30
/* the arg to the listen() call */
#define ACCEPT_LISTEN_BACKLOG 10

/* each instance can share ports */

/*
how does this mess work... hmmm...

the accept section lives in an instance
it can share an ip/port w/ another section, but the secret must be unique,
so it either finds an existing listen thread and adds it's secret and instance pair to it,
or starts a new listen thread
and each section registers a "default" sink packet handler
when new connections come in, a read and write thread are started to deal with it
if a valid handshake is negotiated, the write thread starts to pull packets from the default sink handler
if the default sink is already in use by another write thread, another sink packet handler is registered
when the write threads exit, only the default sink would persist, others all r_UNREG

the handshake is:
<handshake host="1234.foo.jabber.org">SHAHASH of id+secret</handshake>
the host attrib is optional, and when used causes a new sink/handler to be registerd in the o_MODIFY stage to "hijack" packets to that host
note: the use of the host attrib and <host> element in the config are not automagically paired, must be done by the administrator configuring jabberd and whatever app is using the socket
also, set host="void" to disable any packets or data being written to the socket

<accept>
  <ip>1.2.3.4</ip>
  <port>2020</port>
  <secret>foobar</secret>
</accept>

*/

/* simple wrapper around the pth messages to pass packets */
typedef struct
{
    pth_message_t head; /* the standard pth message header */
    dpacket p;
} *drop, _drop;

/* simple wrapper around pth message ports, so we could use something else in the future easily */
typedef struct
{
    instance i;
    pth_msgport_t mp;
    int flag_open, flag_busy, flag_transient;
    time_t last;
    char *filter;
    pool p;
} *sink, _sink;

/* data shared for handlers related to a connection */
typedef struct
{
    int sock, flag_ok, flag_read, flag_write;
    instance i;
    sink s;
    pool p;
    char *id;
} *acceptor, _acceptor;


/* write packets to sink */
result base_accept_phandler(instance i, dpacket p, void *arg)
{
    sink s = (sink)arg;
    drop d;

    /* first, check if this sink is temporary and nothing's at the other end anymore, if so, adios amigo */
    if(!(s->flag_open) && s->flag_transient)
    {
        pth_msgport_free(s->mp);
        pool_free(s->p);
        return r_UNREG;
    }

    /* hack, we are a filter */
    if(s->filter != NULL)
    {
        if(j_strcmp(s->filter, p->host) != 0)
            return r_PASS;

        /* yay, we match! continue with a copy of the packet */
        p = dpacket_new(xmlnode_dup(p->x));
    }

    d = pmalloc(p->p, sizeof(_drop));
    d->p = p;

    pth_msgport_put(s->mp, (pth_message_t *)d);

    return r_OK;
}


void *base_accept_write(void *arg)
{
    acceptor a = (acceptor)arg; /* shared data for this connection */
    dpacket p = NULL; /* the associated packet */
    char *block; /* the data being written */

    a->flag_write = 1; /* signal that the write thread is up */

    while(1)
    {
        a->s->last = time(NULL);
        a->s->flag_busy = 0;

        /* get packet phase */


        /* write packet phase */
        a->s->flag_busy = 1;
        block = xmlnode2str(p->x);
        if(pth_write(a->sock, block, strlen(block)) < 0)
            break;

        /* all sent, yay */
        pool_free(p->p);
        p = NULL;
    }

    /* tidy up */
    close(a->sock);

    /* clear any flags */
    a->s->flag_busy = a->s->flag_open = a->flag_write = 0;

    /* yuck, if we had our own transient sink, we should bounce any waiting packets */
    if(a->s->flag_transient)
    {
        if(p == NULL)
            p = pth_msgport_get()

        for(;p != NULL; p = pth_msgport_get())
            bouncer();

    }else{ /* if we were working on a packet, put it back in the default sink */
        if(p != NULL)
            base_accept_phandler(a->i, p, (void *)(a->s));
    }

    /* free the acceptor, if we're the last out the door */
    if(!(a->flag_read) && !(a->flag_timer))
        pool_free(a->p);
}

void base_accept_read_packets(int type, xmlnode x, void *arg)
{
    acceptor a = (acceptor)arg;
    xmlnode cur;
    char *secret, *block;
    spool s;
    pool p;
    sink snew;

    switch(type)
    {
    case XSTREAM_ROOT:
        /* create and send header, store the id="" in the acceptor to validate the secret l8r */
        cur = xstream_header("jabberd:sockets",NULL,NULL);
        a->id = pstrdup(a->p,xmlnode_get_attrib(cur,"id"));
        block = xstream_header_char(cur);
        pth_write(a->sock,block,strlen(block));
        xmlnode_free(cur);
        break;
    case XSTREAM_NODE:
        if(a->flag_ok > 0)
        {
            deliver(dpacket_new(x), a->s->i);
        }else{
            if(j_strcmp(xmlnode_get_name(x),"handshake") != 0 || (secret = xmlnode_get_data(x)) == NULL)
            {
                xmlnode_free(x);
                return;
            }

            /* check the <handshake>...</handshake> against all known secrets for this port/ip */
            for(cur = xmlnode_get_firstchild(a->secrets); cur != NULL; cur = xmlnode_get_nextsibling(cur))
            {
                s = spool_new(xmlnode_pool(x));
                spooler(s,a->id,xmlnode_get_data(cur),s);
                if(j_strcmp(shahash(spool_print(s)),secret) == 0)
                    break;
            }

            if(cur == NULL)
            {
                pth_write(a->sock,"<stream:error>Invalid Handshake</stream:error>",46);
                pth_write(a->sock,"</stream:stream>",16);
                close(a->sock);
                return;
            }

            /* setup flags in acceptor now that we're ok */
            a->flag_ok = 1;
            a->s = (sink)xmlnode_get_vattrib(cur,"sink");
            block = xmlnode_get_attrib(x,"host");

            /* special hack, to totally ignore the "write" side for this connection */
            if(j_strcmp(block,"void") == 0) return; 

            /* the default sink is in use or we want our own transient one, make it */
            if(a->s->flag_open || block != NULL)
            {
                p = pool_new();
                snew = pmalloc_x(p, sizeof(_sink));
                snew->mp = pth_msgport_create("base_accept_transient");
                snew->i = a->s->i;
                snew->last = time(NULL);
                snew->p = p;
                snew->flag_transient = 1;
                snew->filter = pstrdup(p,block);
                a->s = snew;
                if(block != NULL) /* if we're filtering to a specific host, we need to do that BEFORE delivery! ugly... is the o_* crap any use? */
                    register_phandler(id, o_MODIFY, base_accept_phandler, (void *)snew);
                else
                    register_phandler(id, o_DELIVER, base_accept_phandler, (void *)snew);
            }

            a->s->flag_open = 1; /* signal that the sink is in use */
        }
        break;
    default:
    }

}

/* thread to read from socket */
void *base_accept_read(void *arg)
{
    acceptor a = (acceptor)arg;
    xstream xs;
    int len;
    char buff[1024];

    xs = xstream_new(a->p, base_accept_read_packets, arg);
    a->flag_read = 1;

    /* spin waiting on data from the socket, feeding to xstream */
    while(1)
    {
        len = pth_read(a->sock, buff, 1024);
        if(len < 0) break;

        if(xstream_eat(xs, buff, len) > XSTREAM_NODE) break;
    }

    /* just cleanup and quit */
    close(a->sock);
    a->flag_read = 0;
    if(!(a->flag_write) && !(a->flag_timer)) /* free the acceptor, if we're the last out the door */
        pool_free(a->p);
}

/* fire once and check the acceptor, if it hasn't registered yet, goodbye! */
void base_accept_garbage(void *arg)
{
    acceptor a = (acceptor)arg;

    a->flag_timer = 0; /* we've fired */
    if(!(a->flag_ok))
    {
        pth_write(a->sock,"<stream:error>Timed Out</stream:error>",38);
        pth_write(a->sock,"</stream:stream>",16);
        close(a->sock);
        if(!(a->flag_write) && !(a->flag_read)) /* free a, since we're the last out the door */
            pool_free(a->p);
    }

    return r_UNREG;
}

/* thread to listen on a particular port/ip */
void *base_accept_listen(void *arg)
{
    xmlnode secrets = (xmlnode)arg;
    acceptor a;
    int port, root, sock;
    pool p;
    struct sockaddr_in sa;
    size_t sa_size = sizeof(sa);

    /* look at the port="" and optional ip="" attribs and start a listening socket */
    root = make_netsocket(atoi(xmlnode_get_attrib(secrets,"port"), xmlnode_get_attrib(secrets,"ip"), NETSOCKET_SERVER);
    if(root < 0 || listen(root, ACCEPT_LISTEN_BACKLOG) < 0)
    {
        /* XXX log error! */
        return NULL;
    }

    while(1)
    {
        /* when we get a new socket */
        sock = pth_accept(root, (struct sockaddr *) &sa, (int *) &sa_size);
        if(sock < 0)
        {
            /* XXX log error! */
            break;
        }

        /* create acceptor */
        p = pool_new();
        a = pmalloc_x(p, sizeof(_acceptor));
        a->p = p;
        a->secrets = secrets;
        a->sock = sock;

        /* spawn read thread */
        pth_spwan(PTH_ATTR_DEFAULT, base_accept_read, (void *)a);

        /* create temporary heartbeat to cleanup the socket if it never get's registered */
        a->flag_timer = 1;
        register_heartbeat(ACCEPT_HANDSHAKE_TIMEOUT, base_accept_garbage, (void *)a);
    }
}

/* cleanup routine to make sure packets are getting delivered out of the DEFAULT sink */
result base_accept_plumber(void *arg)
{
    sink s = (sink)arg;

    while(s->flag_busy && time(NULL) - s->last > ACCEPT_PACKET_TIMEOUT)
    {
        /* XXX get the messages from the sink and bounce them intelligently */
        fprintf(stderr,"base_accept: bouncing packets\n");
    }

    return r_OK;
}

xmlnode base_accept__listeners;

result base_accept_config(instance id, xmlnode x, void *arg)
{
    char *port, *ip;
    xmlnode cur;
    sink s;

    port = xmlnode_get_data(xmlnode_get_tag(x, "port"));
    ip = xmlnode_get_data(xmlnode_get_tag(x, "ip"));
    if(id == NULL)
    {
        printf("base_accept_config validating configuration\n");
	if(port == NULL || xmlnode_get_data(xmlnode_get_tag(x, "secret")) == NULL)
	    return r_ERR;
        return r_PASS;
    }

    printf("base_accept_config performing configuration %s\n",xmlnode2str(x));

    /* look for an existing accept section that is the same */
    for(cur = xmlnode_get_firstchild(base_accept__listeners); cur != NULL; cur = xmlnode_get_nextsibling(cur))
        if(strcmp(port,xmlnode_get_attrib(cur,"port")) == 0 && (ip == NULL && xmlnode_get_attrib(cur,"ip") == NULL || strcmp(ip,xmlnode_get_attrib(cur,"ip")) == 0))
            break;

    /* create a new section for this section */
    if(cur == NULL)
    {
        cur = xmlnode_insert_tag(base_accept__listeners, "listen");
        xmlnode_put_attrib(cur,"port",port);
        xmlnode_put_attrib(cur,"ip",ip);

        /* start a new listen thread */
        pth_spawn(PTH_ATTR_DEFAULT, base_accept_listen, (void *)cur);
    }

    /* create and configure the DEFAULT permanent sink */
    s = pmalloc_x(id->p, sizeof(_sink));
    s->mp = pth_msgport_create("base_accept");
    s->i = id;
    s->last = time(NULL);
    s->p = id->p; /* we're as permanent as the instance */

    /* register phandler, and register cleanup heartbeat */
    register_phandler(id, o_DELIVER, base_accept_phandler, (void *)sink);
    register_beat(10, base_accept_plumber, (void *)sink);

    /* insert secret into it and hide sink in that new secret */
    xmlnode_put_vattrib(xmlnode_insert_tag_node(cur,xmlnode_get_tag(x,"secret")),"sink",(void *)s);
}

void base_accept(void)
{
    printf("base_accept loading...\n");

    /* master list of all listen threads */
    base_accept__listeners = xmlnode_new_tag("listeners");

    register_config("accept",base_accept_config,NULL);
}
