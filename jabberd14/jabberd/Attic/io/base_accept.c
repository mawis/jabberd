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

#include "jabberd.h"

/* how many seconds until packets begin to "bounce" that should be delivered */
#define ACCEPT_PACKET_TIMEOUT 30
/* how many seconds a socket has to send a valid handshake */
#define ACCEPT_HANDSHAKE_TIMEOUT 5
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
the host attrib is optional, and when used causes a new sink/handler to be registerd in the o_PREDELIVER stage to "hijack" packets to that host
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
    int flag_open, flag_transient, flag_busy;
    time_t last;
    char *filter;
    pool p;
} *sink, _sink;

/* data shared for handlers related to a connection */
typedef struct
{
    int sock;
    sink s;
    pool p;
    char *id;
    xmlnode secrets;
    pth_event_t emp, eread, etime, ering;
} *acceptor, _acceptor;


/* write packets to sink */
result base_accept_phandler(instance i, dpacket p, void *arg)
{
    sink s = (sink)arg;
    drop d;

    /* first, check if this sink is temporary and nothing's at the other end anymore, if so, adios amigo */
    if(!(s->flag_open) && s->flag_transient)
    {
        pth_msgport_destroy(s->mp);
        pool_free(s->p);
        return r_UNREG;
    }

    /* hack, we are a filter */
    if(s->filter != NULL)
    {
        /* let the default handler handle this */
        /* if there is none, the plumber will bounce it */
        if(j_strcmp(s->filter, p->host) != 0)
            return r_PASS;
    }

    d = pmalloco(p->p, sizeof(_drop));
    d->p = p;

    pth_msgport_put(s->mp, (pth_message_t *)d);

    return r_DONE;
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
        log_debug(ZONE,"socket connected, sending xstream header: %s",block);
        pth_write(a->sock,block,strlen(block));
        xmlnode_free(cur);
        xmlnode_free(x);
        break;
    case XSTREAM_NODE:
        log_debug(ZONE,"base_accept: %s",xmlnode2str(x));
        if(a->emp != NULL) /* we're full open */
        {
            deliver(dpacket_new(x), a->s->i);
            return;
        }

        if(j_strcmp(xmlnode_get_name(x),"handshake") != 0 || (secret = xmlnode_get_data(x)) == NULL)
        {
            pth_write(a->sock,"<stream:error>Must send handshake first</stream:error>",54);
            xmlnode_free(x);
            return;
        }

        /* check the <handshake>...</handshake> against all known secrets for this port/ip */
        for(cur = xmlnode_get_firstchild(a->secrets); cur != NULL; cur = xmlnode_get_nextsibling(cur))
        {
            s = spool_new(xmlnode_pool(x));
            spooler(s,a->id,xmlnode_get_data(cur),s);
            if(j_strcmp(shahash(spool_print(s)),secret) == 0 || j_strcmp(xmlnode_get_data(cur),secret) == 0) /* XXX REMOVE the cleartext option before release! */
                break;
        }

        if(cur == NULL)
        {
            pth_write(a->sock,"<stream:error>Invalid Handshake</stream:error>",46);
            pth_write(a->sock,"</stream:stream>",16);
            a->ering = NULL; /* cancel the io loop */
            xmlnode_free(x);
            return;
        }

        /* setup flags in acceptor now that we're ok */
        a->s = (sink)xmlnode_get_vattrib(cur,"sink");
        block = xmlnode_get_attrib(x,"host");

        /* special hack, to totally ignore the "write" side for this connection */
        if(j_strcmp(block,"void") == 0) return; 

        /* the default sink is in use or we want our own transient one, make it */
        if(a->s->flag_open || block != NULL)
        {
            p = pool_new();
            snew = pmalloco(p, sizeof(_sink));
            snew->mp = pth_msgport_create("base_accept_transient");
            snew->i = a->s->i;
            snew->last = time(NULL);
            snew->p = p;
            snew->flag_transient = 1;
            snew->filter = pstrdup(p,block);
            a->s = snew;
            if(block != NULL) /* if we're filtering to a specific host, we need to do that BEFORE delivery! ugly... is the o_* crap any use? */
                register_phandler(a->s->i, o_PREDELIVER, base_accept_phandler, (void *)snew);
            else
                register_phandler(a->s->i, o_DELIVER, base_accept_phandler, (void *)snew);
        }

        pth_write(a->sock,"<handshake/>",12);
        a->s->flag_open = 1; /* signal that the sink is in use */

        /* set up the mp event into the ring to enable packets to be fed back */
        a->emp = pth_event(PTH_EVENT_MSG,a->s->mp);
        if(a->etime != NULL)
            pth_event_free(a->etime, PTH_FREE_THIS);
        a->ering = pth_event_concat(a->eread, a->emp, NULL);
        xmlnode_free(x);
        break;
    default:
        xmlnode_free(x);
        break;
    }

}

/* thread to handle io from socket */
void *base_accept_io(void *arg)
{
    acceptor a = (acceptor)arg;
    xstream xs;
    int len;
    char buff[1024], *block;
    dpacket p = NULL;
    drop d;

    log_debug(ZONE,"io thread starting for %d",a->sock);

    xs = xstream_new(a->p, base_accept_read_packets, arg);
    a->eread = pth_event(PTH_EVENT_FD|PTH_UNTIL_FD_READABLE,a->sock);
    a->etime = pth_event(PTH_EVENT_TIME, pth_timeout(ACCEPT_HANDSHAKE_TIMEOUT,0));
    a->ering = pth_event_concat(a->eread, a->etime, NULL);

    /* spin waiting on data from the socket, feeding to xstream */
    while(pth_wait(a->ering) > 0)
    {
        /* handle reading the incoming stream */
        if(pth_event_occurred(a->eread))
        {
            log_debug(ZONE,"io read event for %d",a->sock);
            len = pth_read(a->sock, buff, 1024);
            if(len <= 0) break;

            if(xstream_eat(xs, buff, len) > XSTREAM_NODE) break;
        }

        /* handle the packets to be sent to the socket */
        if(pth_event_occurred(a->emp))
        {
            log_debug(ZONE,"io incoming message event for %d",a->sock);

            /* flag that we're working */
            a->s->last = time(NULL);
            a->s->flag_busy = 1;

            /* get packet */
            d = (drop)pth_msgport_get(a->s->mp);
            if(d == NULL) continue;
            p = d->p;

            /* write packet phase */
            block = xmlnode2str(p->x);
            if(pth_write(a->sock, block, strlen(block)) <= 0)
                break;

            /* all sent, yay */
            pool_free(p->p);
            p = NULL;
            a->s->flag_busy = 0;
        }

        /* handle timeout if the handshake hasn't happened yet */
        if(a->emp == NULL && pth_event_occurred(a->etime))
        {
            log_debug(ZONE,"io timeout event for %d",a->sock);
            log_warn(NULL,"base_accept: Timeout on accepted socket");
            pth_write(a->sock,"<stream:error>Timed Out</stream:error>",38);
            pth_write(a->sock,"</stream:stream>",16);
            break;
        }
    }

    log_debug(ZONE,"read thread exiting for %d: %s",a->sock, strerror(errno));
    log_notice(NULL,"base_accept: connection died on accepted socket");

    /* clean up the write side of things first */
    if(a->emp != NULL)
    {
        a->s->flag_open = a->s->flag_busy = 0;

        /* clean up any waiting packets */
        if(a->s->flag_transient)
        {
            if(p != NULL)
            { /* bounce the unsent packet */
                log_warn(NULL,"base_accept Bouncing packet intended for %s",xmlnode_get_attrib(p->x,"to"));
                deliver_fail(p,"External Server Error");
            }

            /* bounce any waiting in the mp */
            for(d = (drop)pth_msgport_get(a->s->mp);d != NULL; d = (drop)pth_msgport_get(a->s->mp))
            {
                log_warn(NULL,"base_accept Bouncing packet intended for %s",xmlnode_get_attrib(d->p->x,"to"));
                deliver_fail(d->p,"External Server Error");
            }
        }else{ /* if we were working on a packet, put it back in the default sink */
            if(p != NULL)
                base_accept_phandler(a->s->i, p, (void *)(a->s));
        }

        pth_event_free(a->emp, PTH_FREE_THIS);
    }

    /* cleanup and quit */
    close(a->sock);
    pth_event_free(a->eread, PTH_FREE_THIS);
    pool_free(a->p);

    return NULL;
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

    log_debug(ZONE,"new listener thread starting for %s",xmlnode2str(secrets));

    /* look at the port="" and optional ip="" attribs and start a listening socket */
    root = make_netsocket(atoi(xmlnode_get_attrib(secrets,"port")), xmlnode_get_attrib(secrets,"ip"), NETSOCKET_SERVER);
    if(root < 0 || listen(root, ACCEPT_LISTEN_BACKLOG) < 0)
    {
        /* XXX log error! */
        log_debug(ZONE,"base_accept failed to listen on port %s for ip %s",xmlnode_get_attrib(secrets,"port"),xmlnode_get_attrib(secrets,"ip"));
        log_alert(NULL,"base_accept failed to listen on port %s for ip %s",xmlnode_get_attrib(secrets,"port"),xmlnode_get_attrib(secrets,"ip"));
        exit(1); /* don't start the server with a bad config */
        return NULL;
    }

    while(1)
    {
        /* when we get a new socket */
        sock = pth_accept(root, (struct sockaddr *) &sa, (int *) &sa_size);
        if(sock < 0)
        {
            log_warn(NULL,"base_accept error accepting: %s",strerror(errno));
            log_alert(NULL,"base_accept not listening on port %s for ip %s",xmlnode_get_attrib(secrets,"port"),xmlnode_get_attrib(secrets,"ip"));
            break;
        }

        /* create acceptor */
        p = pool_new();
        a = pmalloco(p, sizeof(_acceptor));
        a->p = p;
        a->secrets = secrets;
        a->sock = sock;

        log_debug(ZONE,"new connection on port %d from ip %s as fd %d",port,inet_ntoa(sa.sin_addr),sock);
        log_notice(NULL,"base_accept: new connection on port %d from ip %s",port,inet_ntoa(sa.sin_addr),sock);

        /* spawn io thread */
        pth_spawn(PTH_ATTR_DEFAULT, base_accept_io, (void *)a);
    }

    return NULL;
}

/* cleanup routine to make sure packets are getting delivered out of the DEFAULT sink */
result base_accept_plumber(void *arg)
{
    sink s = (sink)arg;
    drop d;

    log_debug(ZONE,"plumber checking on sink %X",s);
    if((time(NULL) - s->last) > ACCEPT_PACKET_TIMEOUT)
    { /* packets timed out without anywhere to send them */
        while((d=(drop)pth_msgport_get(s->mp))!=NULL)
        {
            log_warn(NULL,"base_accept Bouncing packet intended for %s",xmlnode_get_attrib(d->p->x,"to"));
            deliver_fail(d->p,"External Server Error");
        }
    }

    return r_DONE;
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
        xmlnode test;
        spool sp=NULL;
        char *secret=xmlnode_get_data(xmlnode_get_tag(x,"secret"));
        int error=0;

        log_debug(ZONE,"base_accept_config validating configuration\n");
        if((test=xmlnode_get_tag(x,"port"))==NULL)
        {
            if(sp==NULL) sp=spool_new(xmlnode_pool(x));
            spooler(sp,"Failed to find 'port' tag\n",sp);
            error=1;
        }
        else if(port==NULL)
        {
            if(sp==NULL) sp=spool_new(xmlnode_pool(x));
            spooler(sp,"No Data in 'port' tag. must contain a port number\n",sp);
            error=1;
        }
        if((test=xmlnode_get_tag(x,"secret"))==NULL)
        {
            if(sp==NULL) sp=spool_new(xmlnode_pool(x));
            spooler(sp,"Failed to find 'secret' tag\n",sp);
            error=1;
        }
        else if(secret==NULL)
        {
            if(sp==NULL) sp=spool_new(xmlnode_pool(x));
            spooler(sp,"No Data in 'secret' tag. must contain a password\n",sp);
            error=1;
        }
        if(error) 
        {
            xmlnode_put_attrib(x,"error",spool_print(sp));
            return r_ERR;
        }
        return r_PASS;
    }

    log_debug(ZONE,"base_accept_config performing configuration %s\n",xmlnode2str(x));

    /* look for an existing accept section that is the same */
    for(cur = xmlnode_get_firstchild(base_accept__listeners); cur != NULL; cur = xmlnode_get_nextsibling(cur))
        if(strcmp(port,xmlnode_get_attrib(cur,"port"))==0&&((ip==NULL&&xmlnode_get_attrib(cur,"ip")==NULL)||strcmp(ip,xmlnode_get_attrib(cur,"ip"))==0))
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
    s = pmalloco(id->p, sizeof(_sink));
    s->mp = pth_msgport_create("base_accept");
    s->i = id;
    s->last = time(NULL);
    s->p = id->p; /* we're as permanent as the instance */

    log_debug(ZONE,"new sink %X",s);

    /* register phandler, and register cleanup heartbeat */
    register_phandler(id, o_DELIVER, base_accept_phandler, (void *)s);
    register_beat(10, base_accept_plumber, (void *)s);

    /* insert secret into it and hide sink in that new secret */
    xmlnode_put_vattrib(xmlnode_insert_tag_node(cur,xmlnode_get_tag(x,"secret")),"sink",(void *)s);

    return r_DONE;
}

void base_accept(void)
{
    log_debug(ZONE,"base_accept loading...\n");

    /* master list of all listen threads */
    base_accept__listeners = xmlnode_new_tag("listeners");

    register_config("accept",base_accept_config,NULL);
}
