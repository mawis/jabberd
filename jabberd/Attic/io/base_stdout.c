#include "jabberd.h"

/*

<stdout/>

with this flag in any instance of any type, it causes all packets to be delivered to standard out (STDOUT) from the jabberd process
it also flags a thread to read on STDIN for incoming packets

*/

/* simple wrapper around the pth messages to pass packets */
typedef struct
{
    pth_message_t head; /* the standard pth message header */
    dpacket p;
} *drop, _drop;

/* write packets to sink */
result base_stdout_phandler(instance i, dpacket p, void *arg)
{
    pth_msgport_t mp = (pth_msgport_t)arg;
    drop d;

    d = pmalloco(p->p, sizeof(_drop));
    d->p = p;

    pth_msgport_put(mp, (pth_message_t *)d);

    return r_OK;
}

void base_stdin_packets(int type, xmlnode x, void *arg)
{
    xmlnode cur;

    switch(type)
    {
    case XSTREAM_ROOT:
        /* create and send header, store the id="" in the stdoutor to validate the secret l8r */
        cur = xstream_header("jabberd:sockets",NULL,NULL);
        a->id = pstrdup(a->p,xmlnode_get_attrib(cur,"id"));
        block = xstream_header_char(cur);
        pth_write(a->sock,block,strlen(block));
        xmlnode_free(cur);
        break;
    case XSTREAM_NODE:
        if(a->emp != NULL) /* we're full open */
        {
            deliver(dpacket_new(x), a->s->i);
            return;
        }

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
            if(j_strcmp(shahash(spool_print(s)),secret) == 0 || j_strcmp(xmlnode_get_data(cur),secret) == 0) /* XXX REMOVE the cleartext option before release! */
                break;
        }

        if(cur == NULL)
        {
            pth_write(a->sock,"<stream:error>Invalid Handshake</stream:error>",46);
            pth_write(a->sock,"</stream:stream>",16);
            a->ering = NULL; /* cancel the io loop */
            return;
        }

        /* setup flags in stdoutor now that we're ok */
        a->s = (sink)xmlnode_get_vattrib(cur,"sink");
        block = xmlnode_get_attrib(x,"host");

        /* special hack, to totally ignore the "write" side for this connection */
        if(j_strcmp(block,"void") == 0) return; 

        /* the default sink is in use or we want our own transient one, make it */
        if(a->s->flag_open || block != NULL)
        {
            p = pool_new();
            snew = pmalloco(p, sizeof(_sink));
            snew->mp = pth_msgport_create("base_stdout_transient");
            snew->i = a->s->i;
            snew->last = time(NULL);
            snew->p = p;
            snew->flag_transient = 1;
            snew->filter = pstrdup(p,block);
            a->s = snew;
            if(block != NULL) /* if we're filtering to a specific host, we need to do that BEFORE delivery! ugly... is the o_* crap any use? */
                register_phandler(a->s->i, o_MODIFY, base_stdout_phandler, (void *)snew);
            else
                register_phandler(a->s->i, o_DELIVER, base_stdout_phandler, (void *)snew);
        }

        pth_write(a->sock,"<handshake/>",12);
        a->s->flag_open = 1; /* signal that the sink is in use */

        /* set up the mp event into the ring to enable packets to be fed back */
        a->emp = pth_event(PTH_EVENT_MSG,a->s->mp);
        a->ering = pth_event_concat(a->eread, a->emp, NULL);
        break;
    default:
    }

}

/* thread to handle io from socket */
void *base_stdin(void *arg)
{
    stdoutor a = (stdoutor)arg;
    xstream xs;
    int len;
    char buff[1024], *block;
    dpacket p = NULL;
    drop d;

    log_debug(ZONE,"io thread starting for %d",a->sock);

    xs = xstream_new(a->p, base_stdout_read_packets, arg);
    a->eread = pth_event(PTH_EVENT_FD|PTH_UNTIL_FD_READABLE,a->sock);
    a->etime = pth_event(PTH_EVENT_TIME, pth_timeout(stdout_HANDSHAKE_TIMEOUT,0));
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
            pth_write(a->sock,"<stream:error>Timed Out</stream:error>",38);
            pth_write(a->sock,"</stream:stream>",16);
            break;
        }
    }

    log_debug(ZONE,"read thread exiting for %d",a->sock);

    /* clean up the write side of things first */
    if(a->emp != NULL)
    {
        a->s->flag_open = a->s->flag_busy = 0;

        /* clean up any waiting packets */
        if(a->s->flag_transient)
        {
            if(p != NULL)
            { /* bounce the unsent packet */
                /* bounce */
                pool_free(p->p);
            }

            /* bounce any waiting in the mp */
            for(d = (drop)pth_msgport_get(a->s->mp);d != NULL; d = (drop)pth_msgport_get(a->s->mp))
            {
                p = d->p;
                /* bounce */
                pool_free(p->p);
            }
        }else{ /* if we were working on a packet, put it back in the default sink */
            if(p != NULL)
                base_stdout_phandler(a->s->i, p, (void *)(a->s));
        }

        pth_event_free(a->emp, PTH_FREE_THIS);
    }

    /* cleanup and quit */
    close(a->sock);
    pool_free(a->p);

    pth_event_free(a->eread, PTH_FREE_THIS);
    pth_event_free(a->etime, PTH_FREE_THIS);

    return NULL;
}

/* thread to handle io from socket */
void *base_stdout(void *arg)
{
    stdoutor a = (stdoutor)arg;
    xstream xs;
    int len;
    char buff[1024], *block;
    dpacket p = NULL;
    drop d;

    log_debug(ZONE,"io thread starting for %d",a->sock);

    xs = xstream_new(a->p, base_stdout_read_packets, arg);
    a->eread = pth_event(PTH_EVENT_FD|PTH_UNTIL_FD_READABLE,a->sock);
    a->etime = pth_event(PTH_EVENT_TIME, pth_timeout(stdout_HANDSHAKE_TIMEOUT,0));
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
            pth_write(a->sock,"<stream:error>Timed Out</stream:error>",38);
            pth_write(a->sock,"</stream:stream>",16);
            break;
        }
    }

    log_debug(ZONE,"read thread exiting for %d",a->sock);

    /* clean up the write side of things first */
    if(a->emp != NULL)
    {
        a->s->flag_open = a->s->flag_busy = 0;

        /* clean up any waiting packets */
        if(a->s->flag_transient)
        {
            if(p != NULL)
            { /* bounce the unsent packet */
                /* bounce */
                pool_free(p->p);
            }

            /* bounce any waiting in the mp */
            for(d = (drop)pth_msgport_get(a->s->mp);d != NULL; d = (drop)pth_msgport_get(a->s->mp))
            {
                p = d->p;
                /* bounce */
                pool_free(p->p);
            }
        }else{ /* if we were working on a packet, put it back in the default sink */
            if(p != NULL)
                base_stdout_phandler(a->s->i, p, (void *)(a->s));
        }

        pth_event_free(a->emp, PTH_FREE_THIS);
    }

    /* cleanup and quit */
    close(a->sock);
    pool_free(a->p);

    pth_event_free(a->eread, PTH_FREE_THIS);
    pth_event_free(a->etime, PTH_FREE_THIS);

    return NULL;
}

result base_stdout_config(instance id, xmlnode x, void *arg)
{
    static int flag_stdin = 0;
    static pth_msgport_t mp = pth_msgport_create("base_stdout");
    xmlnode cur;

    if(id == NULL) return r_PASS;

    log_debug(ZONE,"base_stdout_config performing configuration");

    if(!flag_stdin)
    {
        pth_spawn(PTH_ATTR_DEFAULT, base_stdin, NULL);
        flag_stdin = 1;
    }

    /* register phandler with the stdout mp */
    register_phandler(id, o_DELIVER, base_stdout_phandler, (void *)mp);

    return r_OK;
}

void base_stdout(void)
{
    printf("base_stdout loading...\n");

    register_config("stdout",base_stdout_config,NULL);
}
