/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "License").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the License.  You
 * may obtain a copy of the License at http://www.jabber.com/license/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2000 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * --------------------------------------------------------------------------*/
 
#include "io.h"
/* struct to hold data for our instance */

/***************************************************\
*      I N T E R N A L   F U N C T I O N S          *
\***************************************************/

typedef struct io_st
{
    pool p;             /* pool to hold this data */
    sock master__list;  /* a list of all the socks */
    pth_t t;            /* a pointer to thread for signaling */
} _ios,*ios;

/* global object */
ios io__data = NULL;
int io__timeout = 0;

/*
 * callback for Heartbeat, increments karma, and signals the
 * select loop, whenever a socket's punishment is over
 */
result karma_heartbeat(void*arg)
{
    sock cur;
    int was_negative = 0;

    /* if there is nothing to do, just return */
    if(io__data==NULL || io__data->master__list == NULL) 
        return r_DONE;

    /* loop through the list, and add karma where appropriate */
    for(cur = io__data->master__list; cur != NULL; cur = cur->next)
    {
        if(io__timeout > 0 && cur->type == type_NORMAL && cur->activity > 0 && (time(NULL) - cur->activity > io__timeout))
            io_close(cur);

        /* don't update if we are closing, or pre-initilized */
        if(cur->state == state_CLOSE || cur->k.val == KARMA_INIT) 
            continue;

        /* if we are being punished, set the flag */
        if(cur->k.val < 0) was_negative = 1; 

        /* possibly increment the karma */
        karma_increment( &cur->k );

        /* punishment is over */
        if(was_negative && cur->k.val == cur->k.restore)  
            pth_raise(io__data->t, SIGUSR2);
    }

    /* always return r_DONE, to keep getting heartbeats */
    return r_DONE;
}

/*
 * Cleanup function when server is shutting down, closes
 * all sockets, so that everything can be cleaned up
 * properly.
 */
void io_select_shutdown(void *arg)
{
    sock cur;

    /* no need to do anything if io__data hasn't been used yet */
    if(io__data == NULL) return;

    /* loop each socket, and close it */
    for(cur = io__data->master__list; cur != NULL; cur = cur->next)
    {
        io_close(cur);
    }
}

/* 
 * Dump this socket's write queue.  tries to write
 * as much of the write queue as it can, before the
 * write call would block the server
 * returns -1 on error, 0 on success, and 1 if more data to write
 */
int _io_write_dump(sock c)
{
    int len;
    wbq q;

    /* if there is nothing currently being written... */
    if(c->xbuffer == NULL) {
        /* grab the next packet from the queue */
        c->wbuffer = c->cbuffer = NULL;
        q= (wbq)pth_msgport_get(c->queue);

        /* if there is nothing else to write, we are done */
        if(q == NULL) return 0;

        /* setup this packet to be written */
        c->xbuffer = q->x;
        c->wbuffer = xmlnode2str(c->xbuffer);
        c->cbuffer = c->wbuffer;
    }
    /* the -1 flag is used to denote a string to write */
    else if( ((int)c->xbuffer) != -1)
    {
        /* if we haven't started writing, setup to write */
        if(c->wbuffer == NULL) c->wbuffer=xmlnode2str(c->xbuffer);
        if(c->cbuffer == NULL) c->cbuffer=c->wbuffer;
    }

    /* try to write as much as we can */
    while(1)
    {
        /* write a bit from the current buffer */
        len = pth_write(c->fd, c->cbuffer, strlen(c->cbuffer));
        log_debug(ZONE, "WRITE %d len %d of %s\n", c->fd, len, c->cbuffer);
        if(len == 0)
        {
            /* bounce the queue */
            (*(io_cb)c->cb)(c, NULL, 0, IO_ERROR, c->cb_arg); 
            return -1;
        }
        if(len < 0)
        { 
            /* if we have an error, that isn't a blocking issue */ 
            if(errno != EWOULDBLOCK && errno != EINTR && errno != EAGAIN)
            { 
                /* bounce the queue */
                (*(io_cb)c->cb)(c, NULL, 0, IO_ERROR, c->cb_arg);
            }
            return -1;
        }
        /* we didnt' write it all, move the current buffer up */
        else if(len < strlen(c->cbuffer))
        {  
            c->cbuffer += len;
            return 1;
        } 
        /* we wrote the entire node, kill it */
        else
        {  
            pool_free(c->pbuffer);
            /* and grab the next... */
            q = (wbq)pth_msgport_get(c->queue);
            /* if we are done writing nodes */
            if(q == NULL)
            { 
                c->xbuffer = NULL;
                c->wbuffer = c->cbuffer = NULL;
                return 0;
            }
            if(q->type == queue_XMLNODE)
            {
                c->xbuffer = q->x;
                c->wbuffer = xmlnode2str(c->xbuffer);
                c->pbuffer = xmlnode_pool(q->x);
            }
            else /* if type is queue_TEXT */
            {
                ((int)c->xbuffer) = -1;
                c->wbuffer = q->data;
                c->pbuffer = q->p;
            }
            c->cbuffer = c->wbuffer;
        }
    } 
}

/* 
 * unlinks a socket from the master list 
 */
void io_unlink(sock c)
{
    if(io__data == NULL) return;
    if(io__data->master__list == c)
       io__data->master__list = io__data->master__list->next;
    if(c->prev != NULL) c->prev->next = c->next;
    if(c->next != NULL) c->next->prev = c->prev;
}

/* 
 * links a socket to the master list 
 */
void io_link(sock c)
{
    if(io__data == NULL) return;
    c->next = io__data->master__list;
    c->prev = NULL;
    if(io__data->master__list != NULL) 
        io__data->master__list->prev = c;
    io__data->master__list = c;
}


/* 
 * internal close function 
 * does a final write of the queue, bouncing and freeing all memory
 */
void _io_close(sock c)
{
    int ret = 0;

    /* ensure that the state is set to CLOSED */
    c->state = state_CLOSE;

    /* take it off the master__list */
    io_unlink(c);

    /* try to write what's in the queue */
    if(c->xbuffer != NULL) 
        ret = _io_write_dump(c);

    /* if we didn't write it all, bounce the current queue */
    if(ret == 1) 
        (*(io_cb)c->cb)(c, NULL, 0, IO_ERROR, c->cb_arg);

    /* notify of the close */
    (*(io_cb)c->cb)(c, NULL, 0, IO_CLOSED, c->cb_arg);

    /* write our closing stream header
     * XXX this doesn't really belong here */
    pth_write(c->fd, "</stream:stream>", 16);

    /* close the socket, and free all memory */
    close(c->fd);

    if(c->rated) 
        jlimit_free(c->rate);

    pth_msgport_destroy(c->queue);
    pool_free(c->p);

    log_debug(ZONE,"freed socket");
}


/* 
 * accept an incoming connection from a listen sock 
 */
sock _io_accept(sock s)
{
    struct sockaddr_in sa;
    size_t sa_size = sizeof(sa);
    int fd,flags;
    sock c;
    pool p;

    /* pull a socket off the accept queue */
    fd = accept(s->fd, (struct sockaddr*)&sa, (int*)&sa_size);
    if(fd <= 0)
    { 
        /* this will try again eventually, 
         * if it's a blocking issue */
        return NULL; 
    }

    /* set the socket to non-blocking */
    flags =  fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);

    /* make sure that we aren't rate limiting this IP */
    if(s->rated && jlimit_check(s->rate, inet_ntoa(sa.sin_addr), 1))
    {
        log_warn("io_select", "%s is being connection rate limited", inet_ntoa(sa.sin_addr));
        close(fd);
        return NULL;
    }

    log_debug(ZONE, "new socket accepted (fd: %d, ip: %s, port: %d)", fd, inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));

    /* create a new sock object for this connection */
    p            = pool_new();
    c            = pmalloco(p, sizeof(_sock));
    c->k.val     = KARMA_INIT;
    c->k.bytes   = 0;
    c->k.max     = s->k.max;
    c->k.inc     = s->k.inc;
    c->k.dec     = s->k.dec;
    c->k.penalty = s->k.penalty;
    c->k.restore = s->k.restore;
    c->queue     = pth_msgport_create("queue");
    c->p         = p;
    c->fd        = fd;
    c->state     = state_ACTIVE;
    c->type      = type_NORMAL;
    c->cb        = s->cb;
    c->cb_arg    = s->cb_arg;
    c->p         = p;
    c->ip        = pstrdup(p, inet_ntoa(sa.sin_addr));
    return c;
}

/* 
 * main select loop thread 
 */
void _io_main(void *arg)
{
    fd_set      wfds,       /* fd set for current writes   */
                rfds,       /* fd set for current reads    */
                all_wfds,   /* fd set for all writes       */
                all_rfds;   /* fd set for all reads        */
    pth_event_t wevt;       /* pth event ring for signal   */
    sigset_t    sigs;       /* signal set to catch SIGUSR2 */
    sock        cur,
                temp;    
    char        buff[8192]; /* max socket read */
    int         len,
                sig,        /* needed to catch signal      */
                maxlen,     /* most data to read from sock */
                maxfd=0;

    /* init the signal junk */
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGUSR2);
    pth_sigmask(SIG_BLOCK, &sigs, NULL);

    /* init the socket junk */
    maxfd = 0;
    if(io__data->master__list != NULL)
        maxfd = io__data->master__list->fd;
    FD_ZERO(&all_wfds);
    FD_ZERO(&all_rfds);
    
    /* init the pth event */
    wevt = pth_event(PTH_EVENT_SIGS, &sigs, &sig);

    /* init the client */
    if(io__data->master__list != NULL)
        (*(io_cb)io__data->master__list->cb)(NULL, NULL, 0, IO_INIT, NULL); 

    /* loop forever -- will only exit when
     * io__data->master__list is NULL */
    while (1)
    {
        rfds = all_rfds;
        wfds = all_wfds;
        /* wait for a socket event */
        pth_select_ev(maxfd+1, &rfds, &wfds, NULL, NULL, wevt);

        /* reset maxfd, in case it changes */
        maxfd=0;

        log_debug(ZONE,"io_main checking sockets");

        /* loop through the sockets, check for stuff to do */
        for(cur = io__data->master__list; cur != NULL;)
        {
            /* if the sock is not in the read set, and has good karma,
             * or if we need to initialize this socket */
            if((!FD_ISSET(cur->fd,&all_rfds) && cur->k.val > 0) || cur->k.val == KARMA_INIT)
            {
                /* reset the karma to restore val */
                cur->k.val=cur->k.restore;

                /* and make sure that they are in the read set */
                FD_SET(cur->fd,&all_rfds);
            }

            /* pause while the rest of jabberd catches up */
            pth_yield(NULL);

            /* if this socket needs to close */
            if(cur->state == state_CLOSE)
            {
                log_debug(ZONE, "closing socket");
                temp = cur;
                cur = cur->next;
                FD_CLR(temp->fd, &all_rfds);
                FD_CLR(temp->fd, &all_wfds);
                _io_close(temp);
                continue;
            }

            /* if this socket needs to be read from */
            if(FD_ISSET(cur->fd, &rfds))
            {
                /* new connection */
                if(cur->type == type_LISTEN)
                {
                    sock c = _io_accept(cur);
                    if(c != NULL)
                    {
                        (*(io_cb)c->cb)(c, NULL, 0, IO_NEW, c->cb_arg);
                        io_link(c); /* it's now at the top of the list */
                        FD_SET(c->fd, &all_rfds);
                        if(c->fd > maxfd)
                            maxfd=c->fd;
                    }

                    cur = cur->next;
                    continue;
                }

                /* update activity timer */
                cur->activity = time(NULL);

                /* we need to read from a socket */
                maxlen = KARMA_READ_MAX(cur->k.val);
                /* leave room for the NULL */
                if(maxlen >= 8192) maxlen = 8191; 

                /* read maxlen data */
                len = pth_read(cur->fd,buff,maxlen);

                /* if we had a bad read */
                if(len==0)
                { 
                    /* kill this socket and move on */
                    temp = cur;
                    cur = cur->next;
                    FD_CLR(temp->fd, &all_rfds);
                    FD_CLR(temp->fd, &all_wfds);
                    _io_close(temp);
                    continue;
                }
                /* an error occured */
                else if(len < 0)
                { 
                    /* ignore these errors */
                    if(errno == EWOULDBLOCK || errno == EINTR || errno == EAGAIN) 
                        FD_SET(cur->fd, &all_rfds);
                    else
                    {
                        temp = cur;
                        cur = cur->next;
                        FD_CLR(temp->fd, &all_rfds);
                        FD_CLR(temp->fd, &all_wfds);
                        _io_close(temp);
                        continue;
                    }
                }
                /* we had a good read */
                else
                {
                    if( karma_check( &cur->k, len ) )
                    { /* they read the max, tsk tsk */
                        if(cur->k.val <= 0) /* ran out of karma */
                        {
                            log_notice("io_select", "socket #%d is out of karma", cur->fd);
                            /* pay the penence */
                            FD_CLR(cur->fd, &all_rfds); 
                            /* let them process this read */
                        }
                    }
                    buff[len] = '\0';
                    (*(io_cb)cur->cb)(cur,buff, len, IO_NORMAL, cur->cb_arg);
                }
            }

            /* if we need to write to this socket */
            if(FD_ISSET(cur->fd, &wfds) || cur->xbuffer != NULL)
            {   
                /* write the current buffer */
                int ret = _io_write_dump(cur);

                /* update activity timer */
                cur->activity = time(NULL);

                /* if an error occured */
                if(ret < 0)
                {
                    /* ignore these errors */
                    if(errno == EWOULDBLOCK || errno == EINTR) 
                        FD_SET(cur->fd, &all_wfds);
                    else
                    {
                        temp = cur;
                        cur = cur->next;
                        FD_CLR(temp->fd, &all_rfds);
                        FD_CLR(temp->fd, &all_wfds);
                        _io_close(temp);
                        continue;
                    }
                }
                /* if we are done writing */
                else if(!ret) 
                    FD_CLR(cur->fd, &all_wfds);
                /* if we still have more to write */
                else FD_SET(cur->fd, &all_wfds);
            }

            /* we may have wanted the socket closed after this operation */
            if(cur->state == state_CLOSE)
            {
                temp = cur;
                cur = cur->next;
                FD_CLR(temp->fd, &all_rfds);
                FD_CLR(temp->fd, &all_wfds);
                _io_close(temp);
                continue;
            }
            
            /* find the max fd */
            if(cur->fd > maxfd)
                maxfd = cur->fd;

            /* check the next socket */
            cur = cur->next;

        } 
        
        /* XXX 
         * yes, spin through the entire list again, 
         * otherwise you can't write to a socket 
         * from another socket's read call) if 
         * there are packets to be written, wait 
         * for a write slot */
        for(cur = io__data->master__list; cur != NULL; cur = cur->next)
            if(cur->xbuffer != NULL) FD_SET(cur->fd, &all_wfds);
            else FD_CLR(cur->fd, &all_wfds);

        /* if there are no more sockets to loop on */
        if(io__data->master__list == NULL)
            break; 
    }

    /* cleanup the socket data */
    pool_free(io__data->p);
    io__data=NULL;
}

/* struct passed to the connecting thread */
typedef struct connect_st
{
    pool p;
    sock c;
    char *host;
    int port;
} _conn_st, *conn_st;

/* pth thread to connect to a remote host 
 * if this were using pthreads, this wouldn't block the server 
 */
void _io_select_connect(void *arg)
{
    conn_st cst = (conn_st)arg;
    sock c      = cst->c;
    pth_event_t evt;
    struct sockaddr_in sa;
    struct in_addr *saddr;
    pool p;
    pth_attr_t attr;
    int fd,flag = 1;
    int flags;

    log_debug(ZONE, "io_select Connecting to host: %s:%d", cst->host, cst->port);

    bzero((void*)&sa, sizeof(struct sockaddr_in));

    /* create a socket to connect with */
    fd = socket(AF_INET, SOCK_STREAM,0);

    /* set socket options */
    if(fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&flag, sizeof(flag)) < 0)
    {
        (*(io_cb)c->cb)(c, NULL, 0, IO_ERROR, c->cb_arg);
        (*(io_cb)c->cb)(c, NULL, 0, IO_CLOSED, c->cb_arg);
        pool_free(c->p);
        return;
    }

    saddr = make_addr(cst->host);
    if(saddr == NULL)
    {
        (*(io_cb)c->cb)(c, NULL, 0, IO_ERROR, c->cb_arg);
        (*(io_cb)c->cb)(c, NULL, 0, IO_CLOSED, c->cb_arg);
        pool_free(c->p);
        return;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(cst->port);
    sa.sin_addr.s_addr = saddr->s_addr;

    /* wait a max of 5 seconds for this connect */
    evt = pth_event(PTH_EVENT_TIME, pth_timeout(5,0));

    /* attempt to connect to the remote host */
    if(pth_connect_ev(fd, (struct sockaddr*)&sa, sizeof sa, evt) < 0)
    {
        log_debug(ZONE, "io_select connect failed to connect to: %s", cst->host);
        (*(io_cb)c->cb)(c, NULL, 0, IO_ERROR, c->cb_arg);
        (*(io_cb)c->cb)(c, NULL, 0, IO_CLOSED, c->cb_arg);
        close(fd);
        pool_free(c->p);
        return;
    }

    /* make sure we got a valid fd */
    if(fd <= 0)
    {
        log_debug(ZONE, "io_select connect failed to connect to: %s", cst->host);
        (*(io_cb)c->cb)(c, NULL, 0, IO_ERROR, c->cb_arg);
        (*(io_cb)c->cb)(c, NULL, 0, IO_CLOSED, c->cb_arg);
        close(fd);
        pool_free(c->p);
        return;
    }

    /* set to non-blocking */
    flags = fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);
    c->fd = fd;

    /* if this is the first socket on the list */
    if(io__data == NULL)
    {
        /* register a cleanup and heartbeat */
        register_shutdown(io_select_shutdown, NULL);
        register_beat(KARMA_HEARTBEAT, karma_heartbeat, NULL);

        /* malloc our instance object */
        p           = pool_new();
        io__data    = pmalloco(p, sizeof(_ios));
        io__data->p = p;

        /* start main accept/read/write thread */
        attr = pth_attr_new();
        pth_attr_set(attr,PTH_ATTR_JOINABLE,FALSE);
        io__data->t=pth_spawn(attr,(void*)_io_main,(void*)io__data);
        pth_attr_destroy(attr);

        /* pause to allow the main loop to register signal handlers */
        pth_yield(NULL);
    }

    /* notify the client that the socket is born */
    (*(io_cb)c->cb)(c, NULL, 0, IO_NEW, c->cb_arg);

    /* link after we call new, to avoid race conditions */
    io_link(c); 

    /* notify the select loop */
    pth_raise(io__data->t, SIGUSR2);
}


/***************************************************\
*      E X T E R N A L   F U N C T I O N S          *
\***************************************************/

/* 
 * returns a list of all the sockets in this instance 
 */
sock io_select_get_list(void)
{
    if(io__data == NULL) return NULL;
    return io__data->master__list;
}

/* 
 * client call to close the socket 
 */
void io_close(sock c) 
{
    c->state = state_CLOSE;
    if(io__data != NULL)
        pth_raise(io__data->t, SIGUSR2);
}

/* 
 * writes a str to the client socket 
 */
void io_write_str(sock c, char *buffer)
{
    wbq q;
    pool p = pool_new();

    /* if we already have stuff to write */
    if(c->wbuffer != NULL)
    {
        /* add it to our write queue */
        q=pmalloco(p, sizeof(_wbq));
        q->data = pstrdup(p, buffer);
        q->p = p;
        q->type = queue_TEXT;
        pth_msgport_put(c->queue, (void*)q); 
    }
    /* otherwise, just make it our current packet */
    else
    { 
        /* hack to write text, so xbuffer != NULL */
        ((int)c->xbuffer) = -1; 
        c->wbuffer = pstrdup(p, buffer);
        c->cbuffer = c->wbuffer;
        c->pbuffer = p;
    }
    /* notify the select loop that a packet needs writing */
    pth_raise(io__data->t, SIGUSR2);
}

/* 
 * adds an xmlnode to the write buffer 
 */
void io_write(sock c, xmlnode x)
{
    wbq q;


    /* if there is alredy a packet being written */
    if(c->xbuffer != NULL)
    { 
        /* just add it to our write buffer */
        q=pmalloco(xmlnode_pool(x), sizeof(_wbq));
        q->type = queue_XMLNODE;
        q->p = xmlnode_pool(x);
        q->x = x;
        /* add it to the queue */
        pth_msgport_put(c->queue, (void*)q); 
    }
    /* otherwise, just make it our current packet */
    else
    { 
        c->xbuffer = x;
        c->pbuffer = xmlnode_pool(x);
    }
    /* notify the select loop that a packet needs writing */
    pth_raise(io__data->t, SIGUSR2);
}


/* 
 * request to connect to a remote host 
 */
void io_select_connect_ex(char *host, int port, void* arg, io_cb cb, void *cb_arg, struct karma *k)
{
    sock c       = NULL;
    pool p       = pool_new();
    conn_st cst  = pmalloco(p,sizeof(_conn_st));

    /* create the conn_st to pass to _io_select_connect */
    cst->host    = pstrdup(p, host);
    cst->port    = port;

    /* create the sock, and assign default values */
    c=pmalloco(p, sizeof(_sock));

    /* assign default karma values */
    c->k.val     = k->val;
    c->k.bytes   = k->bytes;
    c->k.max     = k->max;
    c->k.inc     = k->inc;
    c->k.dec     = k->dec;
    c->k.restore = k->restore;

    /* set socket options */
    c->queue     = pth_msgport_create("queue");
    c->type      = type_NORMAL;
    c->state     = state_ACTIVE;
    c->p         = p;
    c->ip        = pstrdup(p, host);

    /* set callback data */
    c->arg       = arg;
    c->cb_arg    = cb_arg;
    c->cb        = cb;
    c->arg       = arg;

    /* assign the sock to the conn_st */
    cst->c       = c;
    
    /* spawn a connection attempt */
    pth_spawn(PTH_ATTR_DEFAULT, (void*)_io_select_connect, (void*)cst);
}

/* 
 * request to connect to a remote host 
 */
void io_select_connect(char *host, int port, void* arg, io_cb cb, void *cb_arg)
{
    /* create default values, and call io_select_connect_ex */
    struct karma k;

    /* set the defaults */
    k.val     = KARMA_INIT;
    k.bytes   = 0;
    k.max     = KARMA_MAX;
    k.inc     = KARMA_INC;
    k.dec     = KARMA_DEC;
    k.penalty = KARMA_PENALTY;
    k.restore = KARMA_RESTORE;

    /* call the _ex function with the defaults */
    io_select_connect_ex(host, port, arg, cb, cb_arg, &k);
}

/* 
 * call to start listening with select 
 */
void io_select_listen_ex(int port, char *listen_host, io_cb cb, void *arg, int rate_time, int max_points, struct karma *k)
{
    sock new;
    pool p;
    pth_attr_t attr;
    int fd;
    int flags;

    log_debug(ZONE, "io_select to listen on %d [%s]",port, listen_host);

    /* attempt to open a listening socket */
    fd = make_netsocket(port, listen_host, NETSOCKET_SERVER);

    /* if we got a bad fd we can't listen */
    if(fd < 0)
    {
        log_alert(NULL, "io_select unable to listen on %d [%s]", port, listen_host);
        return;
    }

    /* start listening with a max accept queue of 10 */
    if(listen(fd, 10) < 0)
    {
        log_alert(NULL, "io_select unable to listen on %d [%s]", port, listen_host);
        return;
    }

    /* set the socket to non-blocking */
    flags = fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);

    /* create the sock object, and assign the values */
    p              = pool_new();
    new            = pmalloco(p, sizeof(_sock));
    new->k.val     = k->val;
    new->k.bytes   = k->bytes;
    new->k.max     = k->max;
    new->k.inc     = k->inc;
    new->k.dec     = k->dec;
    new->k.restore = k->restore;
    new->k.penalty = k->penalty;
    new->fd        = fd;
    new->p         = p;
    new->type      = type_LISTEN;
    new->state     = state_ACTIVE;
    new->queue     = pth_msgport_create("queue");
    new->cb        = cb;
    new->cb_arg    = arg;

    /* if we are imposing conn rate limits */
    if(rate_time != 0)
    {
        new->rated = 1;
        new->rate = jlimit_new(rate_time, max_points);
    }

    log_debug(ZONE, "io_select starting to listen on %d [%s]", port, listen_host);

    /* if this is our first socket to use io_select */
    if(io__data == NULL)
    {
        /* register the shutdown call */
        register_shutdown(io_select_shutdown, NULL);

        /* register a heartbeat to increment karma */
        register_beat(KARMA_HEARTBEAT, karma_heartbeat, NULL);

        /* create the io__data, and assign values */
        p = pool_new();
        io__data = pmalloco(p, sizeof(_ios));
        io__data->p = p;

        /* start main accept/read/write thread */
        attr = pth_attr_new();
        pth_attr_set(attr, PTH_ATTR_JOINABLE, FALSE);
        io__data->t=pth_spawn(attr,(void*)_io_main,(void*)io__data);
        pth_attr_destroy(attr);

        /* pause before sending the signal, so that the thread
         * has time to set it's signal set to block SIGUSR2 */
        pth_yield(NULL);
    }

    /* add this socket to the list */
    io_link(new);

    /* notify the select loop */
    pth_raise(io__data->t,SIGUSR2); 
}

/* 
 * call to start listening with select 
 */
void io_select_listen(int port, char *listen_host, io_cb cb, void *arg, int rate_time, int max_points)
{
    struct karma k;

    /* call listen with default karma values */
    k.val     = KARMA_INIT;
    k.bytes   = 0;
    k.max     = KARMA_MAX;
    k.inc     = KARMA_INC;
    k.dec     = KARMA_DEC;
    k.penalty = KARMA_PENALTY;
    k.restore = KARMA_RESTORE;

    io_select_listen_ex(port, listen_host, cb, arg, rate_time, max_points, &k);
}

