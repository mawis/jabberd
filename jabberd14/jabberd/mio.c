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

/*
   MIO -- Managed Input/Output
   ---------------------------

   The purpose of this file, is mainly to provide support, to any component
   of jabberd, for abstraced I/O functions.  This works much like tstreams,
   and will incorporate the functionality of io_select initially, but will
   be expanded to support any socket handling model, such as polld, SIGIO, etc

   This works to abstract the socket work, and hide it from the component,
   this way, the component does not have to deal with any complexeties of
   socket functions.
*/
#define MIO
#include <jabberd.h>

/********************************************************
 *************  Internal MIO Functions  *****************
 ********************************************************/

typedef struct mio_main_st
{
    pool p;             /* pool to hold this data */
    mio master__list;  /* a list of all the socks */
    pth_t t;            /* a pointer to thread for signaling */
    int shutdown;
    int zzz[2];
} _ios,*ios;

typedef struct mio_connect_st
{
    pool p;
    char *ip;
    int port;
    void *cb;
    void *cb_arg;
    mio_connect_func cf;
    mio_handlers mh;
    pth_t t;
    int connected;
} _connect_data,  *connect_data;

/* global object */
ios mio__data = NULL;
extern xmlnode greymatter__;

int KARMA_DEF_HEARTBEAT  = KARMA_HEARTBEAT;
int KARMA_DEF_INIT       = KARMA_INIT;
int KARMA_DEF_MAX        = KARMA_MAX;
int KARMA_DEF_INC        = KARMA_INC;
int KARMA_DEF_DEC        = KARMA_DEC;
int KARMA_DEF_PENALTY    = KARMA_PENALTY;
int KARMA_DEF_RESTORE    = KARMA_RESTORE;
int KARMA_DEF_RESETMETER = KARMA_RESETMETER;
int KARMA_DEF_RATE_T     = 5;
int KARMA_DEF_RATE_P     = 25;

int _mio_allow_check(const char *address)
{
    xmlnode io = xmlnode_get_tag(greymatter__, "io");
    xmlnode cur;

    if(xmlnode_get_tag(io, "allow") == NULL)
        return 1; /* if there is no allow section, allow all */

    for(cur = xmlnode_get_firstchild(io); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        char *ip, *netmask;
        struct in_addr in_address, in_ip, in_netmask;
        if(xmlnode_get_type(cur) != NTYPE_TAG)
            continue;

        if(j_strcmp(xmlnode_get_name(cur), "allow") != 0) 
            continue;

        ip = xmlnode_get_tag_data(cur, "ip");
        netmask = xmlnode_get_tag_data(cur, "mask");

        if(ip == NULL)
            continue;

        inet_aton(address, &in_address);

        if(ip != NULL)
            inet_aton(ip, &in_ip);

        if(netmask != NULL)
        {
            inet_aton(netmask, &in_netmask);
            if((in_address.s_addr & in_netmask.s_addr) == (in_ip.s_addr & in_netmask.s_addr))
            { /* this ip is in the allow network */
                return 1;
            }
        }
        else
        {
            if(in_ip.s_addr == in_address.s_addr)
                return 2; /* exact matches hold greater weight */
        }
    }

    /* deny the rest */
    return 0;
}

int _mio_deny_check(const char *address)
{
    xmlnode io = xmlnode_get_tag(greymatter__, "io");
    xmlnode cur;

    if(xmlnode_get_tag(io, "deny") == NULL)
        return 0; /* if there is no allow section, allow all */

    for(cur = xmlnode_get_firstchild(io); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        char *ip, *netmask;
        struct in_addr in_address, in_ip, in_netmask;
        if(xmlnode_get_type(cur) != NTYPE_TAG)
            continue;

        if(j_strcmp(xmlnode_get_name(cur), "deny") != 0) 
            continue;

        ip = xmlnode_get_tag_data(cur, "ip");
        netmask = xmlnode_get_tag_data(cur, "mask");

        if(ip == NULL)
            continue;

        inet_aton(address, &in_address);

        if(ip != NULL)
            inet_aton(ip, &in_ip);

        if(netmask != NULL)
        {
            inet_aton(netmask, &in_netmask);
            if((in_address.s_addr & in_netmask.s_addr) == (in_ip.s_addr & in_netmask.s_addr))
            { /* this ip is in the deny network */
                return 1;
            }
        }
        else
        {
            if(in_ip.s_addr == in_address.s_addr)
                return 2; /* must be an exact match, if no netmask */
        }
    }

    return 0;
}

/*
 * callback for Heartbeat, increments karma, and signals the
 * select loop, whenever a socket's punishment is over
 */
result _karma_heartbeat(void*arg)
{
    mio cur;

    /* if there is nothing to do, just return */
    if(mio__data == NULL || mio__data->master__list == NULL) 
        return r_DONE;

    /* loop through the list, and add karma where appropriate */
    for(cur = mio__data->master__list; cur != NULL; cur = cur->next)
    {
        if(cur->k.dec != 0)
        { /* Karma is enabled for this connection */
            int was_negative = 0;
            /* don't update if we are closing, or pre-initilized */
            if(cur->state == state_CLOSE || cur->k.init == 0) 
                continue;
     
            /* if we are being punished, set the flag */
            if(cur->k.val < 0) was_negative = 1; 
     
            /* possibly increment the karma */
            karma_increment( &cur->k );
     
            /* punishment is over */
            if(was_negative && cur->k.val >= 0)  
            {
               log_debug(ZONE, "Punishment Over for socket %d: ", cur->fd);
               pth_write(mio__data->zzz[1]," ",1);
            }
        }
    }

    /* always return r_DONE, to keep getting heartbeats */
    return r_DONE;
}

/* 
 * unlinks a socket from the master list 
 */
void _mio_unlink(mio m)
{
    if(mio__data == NULL) 
        return;

    if(mio__data->master__list == m)
       mio__data->master__list = mio__data->master__list->next;

    if(m->prev != NULL) 
        m->prev->next = m->next;

    if(m->next != NULL) 
        m->next->prev = m->prev;
}

/* 
 * links a socket to the master list 
 */
void _mio_link(mio m)
{
    if(mio__data == NULL) 
        return;

    m->next = mio__data->master__list;
    m->prev = NULL;

    if(mio__data->master__list != NULL) 
        mio__data->master__list->prev = m;

    mio__data->master__list = m;
}

/* 
 * Dump this socket's write queue.  tries to write
 * as much of the write queue as it can, before the
 * write call would block the server
 * returns -1 on error, 0 on success, and 1 if more data to write
 */
int _mio_write_dump(mio m)
{
    int len;
    mio_wbq cur;

    /* try to write as much as we can */
    while(m->queue != NULL)
    {
        cur = m->queue;

        log_debug(ZONE, "write_dump writing data: %.*s", cur->len, cur->cur);

        /* write a bit from the current buffer */
        len = (*m->mh->write)(m, cur->cur, cur->len);
        /* we had an error on the write */
        if(len == 0)
        {
            if(m->cb != NULL)
                (*(mio_std_cb)m->cb)(m, MIO_ERROR, m->cb_arg);
            return -1;
        }
        if(len < 0)
        { 
            /* if we have an error, that isn't a blocking issue */ 
            if(errno != EWOULDBLOCK && errno != EINTR && errno != EAGAIN)
            { 
                /* bounce the queue */
                if(m->cb != NULL)
                    (*(mio_std_cb)m->cb)(m, MIO_ERROR, m->cb_arg);
                return -1;
            }
            return 1;
        }
        /* we didnt' write it all, move the current buffer up */
        else if(len < cur->len)
        { 

            cur->cur += len;
            cur->len -= len;
            return 1;
        } 
        /* we wrote the entire node, kill it and move on */
        else
        {  
            m->queue = m->queue->next;

            if(m->queue == NULL)
                m->tail = NULL;

            pool_free(cur->p);
        }
    } 
    return 0;
}

/* 
 * internal close function 
 * does a final write of the queue, bouncing and freeing all memory
 */
void _mio_close(mio m)
{
    int ret = 0;
    xmlnode cur;

    /* ensure that the state is set to CLOSED */
    m->state = state_CLOSE;

    /* take it off the master__list */
    _mio_unlink(m);

    /* try to write what's in the queue */
    if(m->queue != NULL) 
        ret = _mio_write_dump(m);

    if(ret == 1) /* still more data, bounce it all */
        if(m->cb != NULL)
            (*(mio_std_cb)m->cb)(m, MIO_ERROR, m->cb);

    /* notify of the close */
    if(m->cb != NULL)
        (*(mio_std_cb)m->cb)(m, MIO_CLOSED, m->cb_arg);

    /* close the socket, and free all memory */
    close(m->fd);

    if(m->rated) 
        jlimit_free(m->rate);

    pool_free(m->mh->p);

    /* cleanup the write queue */
    while((cur = mio_cleanup(m)) != NULL)
        xmlnode_free(cur);

    pool_free(m->p);

    log_debug(ZONE,"freed MIO socket");
}

/* 
 * accept an incoming connection from a listen sock 
 */
mio _mio_accept(mio m)
{
    struct sockaddr_in serv_addr;
    size_t addrlen = sizeof(serv_addr);
    int fd;
    int allow, deny;
    mio new;

    log_debug(ZONE, "_mio_accept calling accept on fd #%d", m->fd);

    /* pull a socket off the accept queue */
    fd = (*m->mh->accept)(m, (struct sockaddr*)&serv_addr, (socklen_t*)&addrlen);
    if(fd <= 0)
    {
        return NULL;
    }

    allow = _mio_allow_check(inet_ntoa(serv_addr.sin_addr));
    deny  = _mio_deny_check(inet_ntoa(serv_addr.sin_addr));

    if(deny >= allow)
    {
        log_warn("mio", "%s was denied access, due to the allow list of IPs", inet_ntoa(serv_addr.sin_addr));
        close(fd);
        return NULL;
    }

    /* make sure that we aren't rate limiting this IP */
    if(m->rated && jlimit_check(m->rate, inet_ntoa(serv_addr.sin_addr), 1))
    {
        log_warn("io_select", "%s(%d) is being connection rate limited", inet_ntoa(serv_addr.sin_addr), fd);
        close(fd);
        return NULL;
    }

    log_debug(ZONE, "new socket accepted (fd: %d, ip: %s, port: %d)", fd, inet_ntoa(serv_addr.sin_addr), ntohs(serv_addr.sin_port));

    /* create a new sock object for this connection */
    new      = mio_new(fd, m->cb, m->cb_arg, mio_handlers_new(m->mh->read, m->mh->write, m->mh->parser));
    new->ip  = pstrdup(new->p, inet_ntoa(serv_addr.sin_addr));
#ifdef HAVE_SSL
    new->ssl = m->ssl;
    
    /* XXX temas:  This is so messy, but I can't see a better way since I can't
     *             hook into the mio_cleanup routines.  MIO still needs some
     *             work.
     */
    pool_cleanup(new->p, _mio_ssl_cleanup, (void *)new->ssl);
#endif

    mio_karma2(new, &m->k);

    if(m->cb != NULL)
        (*(mio_std_cb)new->cb)(new, MIO_NEW, new->cb_arg);

    return new;
}

/* raise a signal on the connecting thread to time it out */
result _mio_connect_timeout(void *arg)
{
    connect_data cd = (connect_data)arg;

    if(cd->connected)
    {
        pool_free(cd->p);
        return r_UNREG;
    }

    log_debug(ZONE, "mio_connect taking too long connecting to %s, signaling to stop", cd->ip);
    if(cd->t != NULL)
        pth_raise(cd->t, SIGUSR2);

    return r_DONE; /* loop again */
}

void _mio_connect(void *arg)
{
    connect_data cd = (connect_data)arg;
    struct sockaddr_in sa;
    struct in_addr     *saddr;
    int                flag = 1,
                       flags;
    mio                new;
    pool               p;
    sigset_t           set;

    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    pth_sigmask(SIG_BLOCK, &set, NULL);


    bzero((void*)&sa, sizeof(struct sockaddr_in));

    /* create the new mio object, can't call mio_new.. don't want it in select yet */
    p           = pool_new();
    new         = pmalloco(p, sizeof(_mio));
    new->p      = p;
    new->type   = type_NORMAL;
    new->state  = state_ACTIVE;
    new->ip     = pstrdup(p,cd->ip);
    new->cb     = (void*)cd->cb;
    new->cb_arg = cd->cb_arg;
    mio_set_handlers(new, cd->mh);

    /* create a socket to connect with */
    new->fd = socket(AF_INET, SOCK_STREAM,0);

    /* set socket options */
    if(new->fd < 0 || setsockopt(new->fd, SOL_SOCKET, SO_REUSEADDR, (char*)&flag, sizeof(flag)) < 0)
    {
        if(cd->cb != NULL)
            (*(mio_std_cb)cd->cb)(new, MIO_CLOSED, cd->cb_arg);
        cd->connected = -1;

        mio_handlers_free(new->mh);
        if(new->fd > 0)
            close(new->fd);
        pool_free(p);
        return;
    }

    /* optionally bind to a local address */
    if(xmlnode_get_tag_data(greymatter__, "io/bind") != NULL)
    {
        struct sockaddr_in sa;
        sa.sin_family = AF_INET;
        sa.sin_port   = 0;
        inet_aton(xmlnode_get_tag_data(greymatter__, "io/bind"), &sa.sin_addr);
        bind(new->fd, (struct sockaddr*)&sa, sizeof(struct sockaddr_in));
    }

    /* set the socket to non-blocking */
    flags =  fcntl(new->fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(new->fd, F_SETFL, flags);

    saddr = make_addr(cd->ip);
    if(saddr == NULL)
    {
        if(cd->cb != NULL)
            (*(mio_std_cb)cd->cb)(new, MIO_CLOSED, cd->cb_arg);
        cd->connected = -1;

        mio_handlers_free(new->mh);
        if(new->fd > 0)
            close(new->fd);
        pool_free(p);
        return;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(cd->port);
    sa.sin_addr.s_addr = saddr->s_addr;

    log_debug(ZONE, "calling the connect handler for mio object %X", new);
    if((*cd->cf)(new, (struct sockaddr*)&sa, sizeof sa) < 0)
    {
        if(cd->cb != NULL)
            (*(mio_std_cb)cd->cb)(new, MIO_CLOSED, cd->cb_arg);
        cd->connected = -1;

        if(new->fd > 0)
            close(new->fd);
        mio_handlers_free(new->mh);
        pool_free(p);
        return;
    }

    /* XXX pthreads race condition.. cd->connected may be checked in the timeout, and cd freed before these calls */

    /* set the default karma values */
    mio_karma(new, KARMA_INIT, KARMA_MAX, KARMA_INC, KARMA_DEC, KARMA_PENALTY, KARMA_RESTORE);
    
    /* add to the select loop */
    _mio_link(new);
    cd->connected = 1; 

    /* notify the select loop */
    if(mio__data != NULL)
        pth_write(mio__data->zzz[1]," ",1);

    /* notify the client that the socket is born */
    if(new->cb != NULL)
        (*(mio_std_cb)new->cb)(new, MIO_NEW, new->cb_arg);

}

/* 
 * main select loop thread 
 */
void _mio_main(void *arg)
{
    fd_set      wfds,       /* fd set for current writes   */
                rfds,       /* fd set for current reads    */
                all_wfds,   /* fd set for all writes       */
                all_rfds;   /* fd set for all reads        */
    mio         cur,
                temp;    
    char        buf[8192]; /* max socket read buffer      */
    int         maxlen,
                len,
                retval,
                bcast=-1,
                maxfd=0;

    log_debug(ZONE, "MIO is starting up");

    /* init the socket junk */
    maxfd = mio__data->zzz[0];
    FD_ZERO(&all_wfds);
    FD_ZERO(&all_rfds);

    /* the optional local broadcast receiver */
    if(xmlnode_get_tag(greymatter__,"io/announce") != NULL)
    {
        bcast = make_netsocket(j_atoi(xmlnode_get_attrib(xmlnode_get_tag(greymatter__,"io/announce"),"port"),5222),NULL,NETSOCKET_UDP);
        if(bcast < 0)
        {
            log_notice("mio","failed to create network announce handler socket");
        }else if(bcast > maxfd){
            maxfd = bcast;
        }
        log_debug(ZONE,"started announcement handler");
    }

    /* loop forever -- will only exit when
     * mio__data->master__list is NULL */
    while (1)
    {
        rfds = all_rfds;
        wfds = all_wfds;

        log_debug(ZONE,"mio while loop top");

        /* if we are closing down, exit the loop */
        if(mio__data->shutdown == 1 && mio__data->master__list == NULL)
            break;

        /* wait for a socket event */
        FD_SET(mio__data->zzz[0],&rfds); /* include our wakeup socket */
        if(bcast > 0)
            FD_SET(bcast,&rfds); /* optionally include our announcements socket */
        retval = pth_select(maxfd+1, &rfds, &wfds, NULL, NULL);
        /* if retval is -1, fd sets are undefined across all platforms */

        log_debug(ZONE,"mio while loop, working");

        /* reset maxfd, in case it changes */
        maxfd=mio__data->zzz[0];

        /* check our zzz */
        if(FD_ISSET(mio__data->zzz[0],&rfds))
        {
            pth_read(mio__data->zzz[0],buf,8192);
        }

        /* check our pending announcements */
        if(bcast > 0 && FD_ISSET(bcast,&rfds))
        {
            struct sockaddr_in remote_addr;
            int addrlen = sizeof(remote_addr);
            xmlnode curx;
            curx = xmlnode_get_firstchild(xmlnode_get_tag(greymatter__,"io/announce"));
            len = pth_recvfrom(bcast,buf,8192,0,(struct sockaddr*)&remote_addr,&addrlen);
            log_debug(ZONE,"ANNOUNCER: received some data from %s: %.*s",inet_ntoa(remote_addr.sin_addr),len,buf);
            /* sending our data out */
            for(; curx != NULL; curx = xmlnode_get_nextsibling(curx))
            {
                if(xmlnode_get_type(curx) != NTYPE_TAG) continue;
                len = snprintf(buf,8192,"%s",xmlnode2str(curx));
                log_debug(ZONE,"announcement packet: %.*s",len,buf);
                pth_sendto(bcast,buf,len,0,(struct sockaddr*)&remote_addr,addrlen);
            }
        }

        /* loop through the sockets, check for stuff to do */
        for(cur = mio__data->master__list; cur != NULL;)
        {

            /* if this socket needs to close */
            if(cur->state == state_CLOSE)
            {
                temp = cur;
                cur = cur->next;
                FD_CLR(temp->fd, &all_rfds);
                FD_CLR(temp->fd, &all_wfds);
                _mio_close(temp);
                continue;
            }

            /* find the max fd */
            if(cur->fd > maxfd)
                maxfd = cur->fd;

            /* if the sock is not in the read set, and has good karma and we got a non read event,
             * or if we need to initialize this socket */
            if(cur->k.init == 0 || (!FD_ISSET(cur->fd, &all_rfds) && cur->k.val >= 0) )
            {
                if(cur->k.init == 0)
                {
                    /* set to intialized */
                    cur->k.init = 1;
                    log_debug(ZONE, "socket %d has been intialized with starting karma %d ", cur->fd, cur->k.val);
                }
                else
                {
                    /* reset the karma to restore val */
                    log_debug(ZONE, "socket %d has restore karma %d byte meter %d", cur->fd, cur->k.val, cur->k.bytes);
                }
                /* and make sure that they are in the read set */
                FD_SET(cur->fd,&all_rfds);
            }

            /* pause while the rest of jabberd catches up */
            pth_yield(NULL);

            if(retval == -1) 
            { /* we can't check anything else, and be XP on all platforms here.. */
                cur = cur->next;
                continue;
            }

            /* if this socket needs to be read from */
            if(FD_ISSET(cur->fd, &rfds)) /* do not read if select returned error */
            {
                /* new connection */
                if(cur->type == type_LISTEN)
                {
                    mio m = _mio_accept(cur);

                    /* this is needed here too */
                    if(cur->fd > maxfd)
                        maxfd = cur->fd;

                    if(m != NULL)
                    {
                        FD_SET(m->fd, &all_rfds);
                        if(m->fd > maxfd)
                            maxfd=m->fd;
                    }

                    cur = cur->next;
                    continue;
                }

                maxlen = KARMA_READ_MAX(cur->k.val);

                if(maxlen > 8191) maxlen = 8191;

                len = (*(cur->mh->read))(cur, buf, maxlen);

                /* if we had a bad read */
                if(len == 0 && maxlen > 0)
                { 
                    mio_close(cur);
                    continue; /* loop on the same socket to kill it for real */
                }
                else if(len < 0)
                {
                    if(errno != EWOULDBLOCK && errno != EINTR && errno != EAGAIN) 
                    {
                        /* kill this socket and move on */
                        mio_close(cur);
                        continue;  /* loop on the same socket to kill it for real */
                    }
                }
                else 
                {
                    if(cur->k.dec != 0)
                    { /* karma is enabled */
                        karma_decrement(&cur->k, len);
                        /* Check if that socket ran out of karma */
                        if(cur->k.val <= 0)
                        { /* ran out of karma */
                            log_notice("MIO_XML_READ", "socket from %s is out of karma", cur->ip);
                            FD_CLR(cur->fd, &all_rfds); /* this fd is being punished */
                        }
                    }

                    buf[len] = '\0';

                    log_debug(ZONE, "MIO read from socket %d: %s", cur->fd, buf);
                    (*cur->mh->parser)(cur, buf, len);
                }
            } 

            /* we could have gotten a bad parse, and want to close */
            if(cur->state == state_CLOSE)
            { /* loop again to close the socket */
                continue;
            }

            /* if we need to write to this socket */
            if((FD_ISSET(cur->fd, &wfds) || cur->queue != NULL))
            {   
                int ret;

                /* write the current buffer */
                ret = _mio_write_dump(cur);

                /* if an error occured */
                if(ret == -1)
                {
                    mio_close(cur);
                    continue; /* loop on the same socket to kill it for real */
                }
                /* if we are done writing */
                else if(ret == 0) 
                    FD_CLR(cur->fd, &all_wfds);
                /* if we still have more to write */
                else if(ret == 1)
                    FD_SET(cur->fd, &all_wfds);
            }

            /* we may have wanted the socket closed after this operation */
            if(cur->state == state_CLOSE)
                continue; /* loop on the same socket to kill it for real */

            /* check the next socket */
            cur = cur->next;
        } 
        
        /* XXX 
         * *tsbandit pokes jer: Why are we doing this again? i forget
         * yes, spin through the entire list again, 
         * otherwise you can't write to a socket 
         * from another socket's read call) if 
         * there are packets to be written, wait 
         * for a write slot */
        for(cur = mio__data->master__list; cur != NULL; cur = cur->next)
            if(cur->queue != NULL) FD_SET(cur->fd, &all_wfds);
            else FD_CLR(cur->fd, &all_wfds);
    }
}

/***************************************************\
*      E X T E R N A L   F U N C T I O N S          *
\***************************************************/

/* 
   starts the _mio_main() loop
*/
void mio_init(void)
{
    pool p;
    pth_attr_t attr;
    xmlnode io = xmlnode_get_tag(greymatter__, "io");

#ifdef HAVE_SSL
    if(xmlnode_get_tag(io, "ssl") != NULL)
        mio_ssl_init(xmlnode_get_tag(io, "ssl"));
#endif

    KARMA_DEF_INIT       = j_atoi(xmlnode_get_tag_data(io, "karma/init"), KARMA_INIT);
    KARMA_DEF_MAX        = j_atoi(xmlnode_get_tag_data(io, "karma/max"), KARMA_MAX);
    KARMA_DEF_INC        = j_atoi(xmlnode_get_tag_data(io, "karma/inc"), KARMA_INC);
    KARMA_DEF_DEC        = j_atoi(xmlnode_get_tag_data(io, "karma/dec"), KARMA_DEC);
    KARMA_DEF_PENALTY    = j_atoi(xmlnode_get_tag_data(io, "karma/penalty"), KARMA_PENALTY);
    KARMA_DEF_RESTORE    = j_atoi(xmlnode_get_tag_data(io, "karma/restore"), KARMA_RESTORE);
    KARMA_DEF_RATE_T     = j_atoi(xmlnode_get_attrib(xmlnode_get_tag(io, "rate"), "time"), 5);
    KARMA_DEF_RATE_P     = j_atoi(xmlnode_get_attrib(xmlnode_get_tag(io, "rate"), "points"), 25);
    KARMA_DEF_RESETMETER = j_atoi(xmlnode_get_tag_data(io, "karma/resetmeter"), KARMA_RESETMETER);

    /* Global settings for karma */
    KARMA_DEF_HEARTBEAT = j_atoi(xmlnode_get_tag_data(io, "karma/heartbeat"), KARMA_HEARTBEAT);


    if(mio__data == NULL)
    {
        register_beat(KARMA_DEF_HEARTBEAT, _karma_heartbeat, NULL);

        /* malloc our instance object */
        p            = pool_new();
        mio__data    = pmalloco(p, sizeof(_ios));
        mio__data->p = p;
        pipe(mio__data->zzz);

        /* start main accept/read/write thread */
        attr = pth_attr_new();
        pth_attr_set(attr,PTH_ATTR_JOINABLE,FALSE);
        mio__data->t=pth_spawn(attr,(void*)_mio_main,NULL);
        pth_attr_destroy(attr);

        /* give time to init the signal handlers */
        pth_yield(NULL);
    }
}

/*
 * Cleanup function when server is shutting down, closes
 * all sockets, so that everything can be cleaned up
 * properly.
 */
void mio_stop(void)
{
    mio cur, mnext;

    log_debug(ZONE, "MIO is shutting down");

    /* no need to do anything if mio__data hasn't been used yet */
    if(mio__data == NULL) 
        return;

    /* flag that it is okay to exit the loop */
    mio__data->shutdown = 1;

    /* loop each socket, and close it */
    for(cur = mio__data->master__list; cur != NULL;)
    {
        mnext = cur->next;
        _mio_close(cur);
    	cur = mnext;
    }

    /* signal the loop to end */
    pth_abort(mio__data->t);

    pool_free(mio__data->p);
    mio__data = NULL;
}

/* 
   creates a new mio object from a file descriptor
*/
mio mio_new(int fd, void *cb, void *arg, mio_handlers mh)
{
    mio   new    =  NULL;
    pool  p      =  NULL;
    int   flags  =  0;

    if(fd <= 0) 
        return NULL;
    
    /* create the new MIO object */
    p           = pool_new();
    new         = pmalloco(p, sizeof(_mio));
    new->p      = p;
    new->type   = type_NORMAL;
    new->state  = state_ACTIVE;
    new->fd     = fd;
    new->cb     = (void*)cb;
    new->cb_arg = arg;
    mio_set_handlers(new, mh);

    /* set the default karma values */
    mio_karma(new, KARMA_INIT, KARMA_MAX, KARMA_INC, KARMA_DEC, KARMA_PENALTY, KARMA_RESTORE);
    mio_rate(new, KARMA_DEF_RATE_T, KARMA_DEF_RATE_P);
    
    /* set the socket to non-blocking */
    flags =  fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);

    /* add to the select loop */
    _mio_link(new);

    /* notify the select loop */
    if(mio__data != NULL)
        write(mio__data->zzz[1]," ",1);

    return new;
}

/*
   resets the callback function
*/
mio mio_reset(mio m, void *cb, void *arg)
{
    if(m == NULL) 
        return NULL;

    m->cb     = cb;
    m->cb_arg = arg;

    return m;
}

/* 
 * client call to close the socket 
 */
void mio_close(mio m) 
{
    if(m == NULL) 
        return;

    m->state = state_CLOSE;
    if(mio__data != NULL)
        write(mio__data->zzz[1]," ",1);
}

/* 
 * writes a str, or xmlnode to the client socket 
 */
void mio_write(mio m, xmlnode x, char *buffer, int len)
{
    mio_wbq new;
    pool p;


    if(m == NULL) 
        return;

    /* if there is nothing to write */
    if(x == NULL && buffer == NULL)
    {
        log_debug("mio", "[%s] mio_write called without x or buffer", ZONE);
        return;
    }

    /* create the pool for this wbq */
    if(x != NULL)
        p = xmlnode_pool(x);
    else
        p = pool_new();

    /* create the wbq */
    new    = pmalloco(p, sizeof(_mio_wbq));
    new->p = p;

    /* set the queue item type */
    if(buffer != NULL)
    {
        new->type = queue_CDATA;

        if (len == -1)
            len = strlen(buffer);

        /* XXX more hackish code to print the stream header right on a NUL xmlnode socket */
        if(m->type == type_NUL && strncmp(buffer,"<stream:stream",14))
        {
            len++;
            new->data = pmalloco(p,len);
            sprintf(new->data,"%.*s/>",len-2,buffer);
        }else{
            new->data = pmalloco(p,len);
            memcpy(new->data,buffer,len);
        }
    }
    else
    {
        new->type = queue_XMLNODE;
        new->data = xmlnode2str(x);
        len = new->data ? strlen(new->data) : 0;
    }
    /* include the \0 if we're special */
    if(m->type == type_NUL)
    {
        len++;
    }

    /* assign values */
    new->x    = x;
    new->cur  = new->data;

    new->len = len;

    /* put at end of queue */
    if(m->tail == NULL)
        m->queue = new;
    else
        m->tail->next = new;
    m->tail = new;

    log_debug(ZONE, "mio_write called on x: %X buffer: %.*s", x, len, buffer);
    /* notify the select loop that a packet needs writing */
    if(mio__data != NULL)
        write(mio__data->zzz[1]," ",1);
}

/*
   sets karma values
*/
void mio_karma(mio m, int val, int max, int inc, int dec, int penalty, int restore)
{
    if(m == NULL)
       return;

    m->k.val     = val;
    m->k.max     = max;
    m->k.inc     = inc;
    m->k.dec     = dec;
    m->k.penalty = penalty;
    m->k.restore = restore;
}

void mio_karma2(mio m, struct karma *k)
{
    if(m == NULL)
       return;

    karma_copy(&m->k, k);
}

/*
   sets connection rate limits
*/
void mio_rate(mio m, int rate_time, int max_points)
{
    if(m == NULL) 
        return;

    m->rated = 1;
    if(m->rate != NULL)
        jlimit_free(m->rate);

    m->rate = jlimit_new(rate_time, max_points);
    m->rated = 1;
}

/*
   pops the last xmlnode from the queue 
*/
xmlnode mio_cleanup(mio m)
{
    mio_wbq     cur;
    
    if(m == NULL || m->queue == NULL) 
        return NULL;

    /* find the first queue item with a xmlnode attached */
    for(cur = m->queue; cur != NULL;)
    {

        /* move the queue up */
        m->queue = cur->next;

        /* set the tail pointer if needed */
        if(m->queue == NULL)
            m->tail = NULL;

        /* if there is no node attached */
        if(cur->x == NULL)
        {
            /* just kill this item, and move on..
             * only pop xmlnodes 
             */
            mio_wbq next = m->queue;
            pool_free(cur->p);
            cur = next;
            continue;
        }

        /* and pop this xmlnode */
        return cur->x;
    }

    /* no xmlnodes found */
    return NULL;
}

/* 
 * request to connect to a remote host 
 */
void mio_connect(char *host, int port, void *cb, void *cb_arg, int timeout, mio_connect_func f, mio_handlers mh)
{
    connect_data cd = NULL;
    pool         p  = NULL;

    /* verify data */
    if(host == NULL || port == 0) 
        return;

    if(timeout <= 0)
        timeout = 30; /* default timeout */

    if(f == NULL)
        f = MIO_RAW_CONNECT;

    if(mh == NULL)
        mh = mio_handlers_new(NULL, NULL, NULL);

    /* create the connect struct */
    p          = pool_new();
    cd         = pmalloco(p, sizeof(_connect_data));
    cd->p      = p;
    cd->ip     = pstrdup(p, host);
    cd->port   = port;
    cd->cb     = cb;
    cd->cb_arg = cb_arg;
    cd->cf     = f;
    cd->mh     = mh;
    cd->t      = pth_spawn(PTH_ATTR_DEFAULT, (void*)_mio_connect, (void*)cd);

    register_beat(timeout, _mio_connect_timeout, (void*)cd);

}

/* 
 * call to start listening with select 
 */
mio mio_listen(int port, char *listen_host, void *cb, void *arg, mio_accept_func f, mio_handlers mh)
{
    mio        new;
    int        fd;

    if(f == NULL)
        f = MIO_RAW_ACCEPT;

    if(mh == NULL)
        mh = mio_handlers_new(NULL, NULL, NULL);

    mh->accept = f;

    log_debug(ZONE, "io_select to listen on %d [%s]",port, listen_host);

    /* attempt to open a listening socket */
    fd = make_netsocket(port, listen_host, NETSOCKET_SERVER);

    /* if we got a bad fd we can't listen */
    if(fd < 0)
    {
        log_alert(NULL, "io_select unable to listen on %d [%s]", port, listen_host);
        return NULL;
    }

    /* start listening with a max accept queue of 10 */
    if(listen(fd, 10) < 0)
    {
        log_alert(NULL, "io_select unable to listen on %d [%s]", port, listen_host);
        return NULL;
    }

    /* create the sock object, and assign the values */
    new       = mio_new(fd, cb, arg, mh);
    new->type = type_LISTEN;
    new->ip   = pstrdup(new->p, listen_host);

    log_debug(ZONE, "io_select starting to listen on %d [%s]", port, listen_host);

    return new;
}

mio_handlers mio_handlers_new(mio_read_func rf, mio_write_func wf, mio_parser_func pf)
{
    pool p = pool_new();
    mio_handlers new;

    new = pmalloco(p, sizeof(_mio_handlers));

    new->p = p;

    /* yay! a chance to use the tertiary operator! */
    new->read   = rf ? rf : MIO_RAW_READ;
    new->write  = wf ? wf : MIO_RAW_WRITE;
    new->parser = pf ? pf : MIO_RAW_PARSER;

    return new;
}

void mio_handlers_free(mio_handlers mh)
{
    if(mh == NULL)
        return;

    pool_free(mh->p);
}

void mio_set_handlers(mio m, mio_handlers mh)
{
    mio_handlers old;

    if(m == NULL || mh == NULL)
        return;

    old = m->mh;
    m->mh = mh;

    mio_handlers_free(old);
}
