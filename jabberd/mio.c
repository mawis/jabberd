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
} _ios,*ios;

/* global object */
ios mio__data = NULL;

/* *******************************************
 * Internal Expat Callbacks
 * *******************************************/

void _mio_xstream_startElement(mio m, const char* name, const char** attribs)
{
    /* If stacknode is NULL, we are starting a new packet and must
       setup for by pre-allocating some memory */
    if (m->stacknode == NULL)
    {
	    pool p = pool_heap(5 * 1024); /* 5k, typically 1-2k each, plus copy of self
				   and workspace */
	    m->stacknode = xmlnode_new_tag_pool(p, name);
	    xmlnode_put_expat_attribs(m->stacknode, attribs);

	    /* If the parser_depth is 0, this must be the root node.. */
	    if (m->parser_depth == 0)
	    {
	        m->parser_depth++;
            if(m->cb != NULL)
	            (*(mio_xml_cb)m->cb)(m, MIO_XML_ROOT, m->cb_arg, m->stacknode);
	        m->stacknode = NULL;
	    }
    }
    else 
    {
	    m->stacknode = xmlnode_insert_tag(m->stacknode, name);
	    xmlnode_put_expat_attribs(m->stacknode, attribs);
    }
}

void _mio_xstream_endElement(mio m, const char* name)
{
    /* If the stacknode is already NULL, then this closing element
       must be the closing ROOT tag, so notify and exit */
    if (m->stacknode == NULL)
    {
        if(m->cb != NULL)
	        (*(mio_xml_cb)m->cb)(m, MIO_XML_CLOSE, m->cb_arg, NULL);
    }
    else
    {
	    xmlnode parent = xmlnode_get_parent(m->stacknode);
	    /* Fire the NODE event if this closing element has no parent */
	    if (parent == NULL)
	    {
            if(m->cb != NULL)
	            (*(mio_xml_cb)m->cb)(m, MIO_XML_NODE, m->cb_arg, m->stacknode);
	    }
	    m->stacknode = parent;
    }
    m->parser_depth--;
}

void _mio_xstream_CDATA(mio m, const char* cdata, int len)
{
    if (m->stacknode != NULL)
	xmlnode_insert_cdata(m->stacknode, cdata, len);
}

void _mio_xstream_cleanup(void* arg)
{
    mio m = (void*)arg;

    xmlnode_free(m->stacknode);
    XML_ParserFree(m->parser);
    m->parser = NULL;
}

mio _mio_xstream_init(mio m)
{
    if (m != NULL)
    {
	/* Initialize the parser */
	m->parser = XML_ParserCreate(NULL);
	XML_SetUserData(m->parser, m);
	XML_SetElementHandler(m->parser, (void*)_mio_xstream_startElement, 
			      (void*)_mio_xstream_endElement);
	XML_SetCharacterDataHandler(m->parser, (void*)_mio_xstream_CDATA);
	/* Setup a cleanup routine to release the parser when everything
	   is done */
	pool_cleanup(m->p, _mio_xstream_cleanup, (void*)m);
    }
    return m;
}

/* ----------------------------------------------------
 * 
 * Internal timer functions and structures
 *
 *------------------------------------------------------ */

typedef struct mio_timer_st
{
    int time_left;
    mio m;
    struct mio_timer_st *next;
    struct mio_timer_st *prev;
    pool mempool;
} *mio_timer, _mio_timer;

/* GLOBALS */
pth_mutex_t G_timer_mutex = PTH_MUTEX_INIT;
mio_timer   G_head        = NULL;

#define _get_timer_lock()     pth_mutex_acquire(&G_timer_mutex, 0, NULL)
#define _release_timer_lock() pth_mutex_release(&G_timer_mutex);

/*
 * Assumption: Calling function holds the timer lock
 */
void _mio_remove_timer(mio_timer mt)
{
    if (mt == NULL)
	    return;

    if(mt->prev != NULL)
	    mt->prev->next = mt->next;

    if(mt->next != NULL)
	    mt->next->prev = mt->prev;

    if (mt == G_head)
        G_head = mt->next;

    pool_free(mt->mempool);
}

/*
 * Assumption: Calling function holds the timer lock
 */
void _mio_add_timer(mio_timer mt)
{
    /* May as well do it the easy way -- insert at head */
    mt->next = G_head;
    mt->prev = NULL;

    if(G_head != NULL)
    {
	    G_head->prev = mt;
    }

    G_head = mt;
}

/* 
 * Check all mio's for which we've registered a timeout.  If any of them
 * have expired, let their callback know about it
 */
result _timeout_heartbeat(void *arg)
{
    mio_timer mt, next_mt;

    _get_timer_lock();
    
    /* 
     * It has been a second since we were last called.  For every mio_timer in the 
     * global list, decrement their timer and, if it has expired, notify the callback
     * and remove it from the timer list
     */
    mt = G_head;
    while(mt != NULL) 
    {
	    /* Get the next item now before we (possibly) remove mt */
	    next_mt = mt->next; 
	    mt->time_left--; /* decrement timer */

	    if (mt->time_left <= 0)
        { /* It has expired */
            if(mt->m->cb != NULL)
	            (*(mio_cb)mt->m->cb)(mt->m, MIO_TIMEOUT, mt->m->cb_arg, NULL, 0);
	        _mio_remove_timer(mt);
	    }

	    mt = next_mt;
    }

    _release_timer_lock();
    return r_DONE;
}


/*
 * callback for Heartbeat, increments karma, and signals the
 * select loop, whenever a socket's punishment is over
 */
result _karma_heartbeat(void*arg)
{
    mio cur;
    int was_negative = 0;

    /* if there is nothing to do, just return */
    if(mio__data==NULL || mio__data->master__list == NULL) 
        return r_DONE;

    /* loop through the list, and add karma where appropriate */
    for(cur = mio__data->master__list; cur != NULL; cur = cur->next)
    {
        /* don't update if we are closing, or pre-initilized */
        if(cur->state == state_CLOSE || cur->k.val == KARMA_INIT) 
            continue;

        /* if we are being punished, set the flag */
        if(cur->k.val < 0) was_negative = 1; 

        /* possibly increment the karma */
        karma_increment( &cur->k );

        /* punishment is over */
        if(was_negative && cur->k.val == cur->k.restore)  
            pth_raise(mio__data->t, SIGUSR2);
    }

    /* always return r_DONE, to keep getting heartbeats */
    return r_DONE;
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

        /* setup the write */
        switch(cur->type)
        {
            case queue_XMLNODE:
                /* if not already done, set the data to write */
                if(cur->data == NULL)
                {
                    cur->data = xmlnode2str(cur->x);
                    if(cur->data == NULL) cur->len = 0;
                    else cur->len = strlen(cur->data);
                }
            case queue_CDATA:
                /* set the current write position */
                if(cur->cur == NULL) cur->cur = cur->data;
                break;
            default:
                log_alert(NULL,"MIO unable to write buffer type: %d", cur->type);
                break;
        }

        log_debug(ZONE, "write_dump writing data: %s", cur->cur);

        /* write a bit from the current buffer */
        len = pth_write(m->fd, cur->cur, cur->len);
        if(len == 0)
        {
            /* bounce the queue */
            if(m->cb != NULL)
                (*(mio_cb)m->cb)(m, MIO_ERROR, m->cb_arg, NULL, 0); 
            return -1;
        }
        /* we had an error on the write */
        else if(len < 0)
        { 
            /* if we have an error, that isn't a blocking issue */ 
            if(errno != EWOULDBLOCK && errno != EINTR && errno != EAGAIN)
            { 
                /* bounce the queue */
                if(m->cb != NULL)
                    (*(mio_cb)m->cb)(m, MIO_ERROR, m->cb_arg, NULL, 0);
                return -1;
            }

            /* blocking issue.. return that there is more to write */
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

    /* if we didn't write it all, bounce the current queue */
    if(ret == 1) 
        if(m->cb != NULL)
            (*(mio_cb)m->cb)(m, MIO_ERROR, m->cb_arg, NULL, 0);

    /* notify of the close */
    if(m->cb != NULL)
        (*(mio_cb)m->cb)(m, MIO_CLOSED, m->cb_arg, NULL, 0);

    /* close the socket, and free all memory */
    close(m->fd);

    if(m->rated) 
        jlimit_free(m->rate);

    /* cleanup the write queue */
    while((cur = mio_cleanup(m)) != NULL)
    {
        xmlnode_free(cur);
    }

    pool_free(m->p);

    log_debug(ZONE,"freed MIO socket");
}

/* 
 * accept an incoming connection from a listen sock 
 */
mio _mio_accept(mio m)
{
    struct sockaddr_in sa;
    size_t sa_size = sizeof(sa);
    int fd;
    mio new;

    log_debug(ZONE, "_mio_accept calling accept on fd #%d", m->fd);

    /* pull a socket off the accept queue */
    fd = accept(m->fd, (struct sockaddr*)&sa, (int*)&sa_size);
    if(fd <= 0)
    { 
        /* this will try again eventually, 
         * if it's a blocking issue */
        return NULL; 
    }

    /* make sure that we aren't rate limiting this IP */
    if(m->rated && jlimit_check(m->rate, inet_ntoa(sa.sin_addr), 1))
    {
        log_warn("io_select", "%s is being connection rate limited", inet_ntoa(sa.sin_addr));
        close(fd);
        return NULL;
    }

    log_debug(ZONE, "new socket accepted (fd: %d, ip: %s, port: %d)", fd, inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));

    /* create a new sock object for this connection */
    new        = mio_new(fd, m->cb, m->cb_arg);
    new->ip    = pstrdup(new->p, inet_ntoa(sa.sin_addr));

    if(m->parser != NULL)
    { /* if the listener was xml based, make the child that way */
        _mio_xstream_init(new);
    }

    mio_karma2(new, &m->k);
    return new;
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
    pth_event_t wevt;       /* pth event ring for signal   */
    sigset_t    sigs;       /* signal set to catch SIGUSR2 */
    mio         cur,
                temp;    
    char        buff[8192]; /* max socket read */
    int         len,
                sig,        /* needed to catch signal      */
                maxlen,     /* most data to read from sock */
                retval,
                maxfd=0;

    log_debug(ZONE, "MIO is starting up");

    /* init the signal junk */
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGUSR2);
    pth_sigmask(SIG_BLOCK, &sigs, NULL);

    /* init the socket junk */
    maxfd = 0;
    FD_ZERO(&all_wfds);
    FD_ZERO(&all_rfds);
    
    /* init the pth event */
    wevt = pth_event(PTH_EVENT_SIGS, &sigs, &sig);

    /* loop forever -- will only exit when
     * mio__data->master__list is NULL */
    while (1)
    {
        rfds = all_rfds;
        wfds = all_wfds;

        /* if we are closing down, exit the loop */
        if(mio__data->shutdown == 1 && mio__data->master__list == NULL)
            break;

        log_debug(ZONE, "mio_main Entering Select");
        /* wait for a socket event */
        retval = pth_select_ev(maxfd+1, &rfds, &wfds, NULL, NULL, wevt);
        /* if retval is -1, fd sets are undefined across all platforms */

        /* reset maxfd, in case it changes */
        maxfd=0;

        log_debug(ZONE,"mio_main checking sockets");

        /* loop through the sockets, check for stuff to do */
        for(cur = mio__data->master__list; cur != NULL;)
        {

            /* if this socket needs to close */
            if(cur->state == state_CLOSE)
            {
                log_debug(ZONE, "closing socket");
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

            /* if this socket needs to be read from */
            if(FD_ISSET(cur->fd, &rfds) && retval != -1) /* do not read if select returned error */
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
                        if(m->cb != NULL)
                            (*(mio_cb)m->cb)(m, MIO_NEW, m->cb_arg, NULL, 0);
                        FD_SET(m->fd, &all_rfds);
                        if(m->fd > maxfd)
                            maxfd=m->fd;
                    }

                    cur = cur->next;
                    continue;
                }

                /* we need to read from a socket */
                maxlen = KARMA_READ_MAX(cur->k.val);

                /* leave room for the NULL */
                if(maxlen > 8191) maxlen = 8191; 

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
                    _mio_close(temp);
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
                        _mio_close(temp);
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
                            log_notice("io_select", "socket from %s is out of karma", cur->ip);
                            /* pay the penence */
                            FD_CLR(cur->fd, &all_rfds); 
                            /* let them process this read */
                        }
                    }
                    buff[len] = '\0';

                    /* if this MIO object has a parser available, pass
                     * the data into the parser */
                    if(cur->parser != NULL)
                    {
                        /* if the parse fails, fire the callback with an
                         * error event */
                        if(XML_Parse(cur->parser, buff, len, 0) < 0)
                        {
                            if(cur->cb != NULL)
                                (*(mio_xml_cb)cur->cb)(cur, MIO_XML_ERROR, cur->cb_arg, NULL);
                        }
                    }
                    else
                    {
                        if(cur->cb != NULL)
                            (*(mio_cb)cur->cb)(cur, MIO_BUFFER, cur->cb_arg, buff, len);
                    }
                }
            } 
            /* if we need to write to this socket */
            if((FD_ISSET(cur->fd, &wfds) || cur->queue != NULL) && retval != -1) /* do not write if select returned error */
            {   
                /* write the current buffer */
                int ret = _mio_write_dump(cur);
                /* if an error occured */
                if(ret == -1)
                {
                    temp = cur;
                    cur = cur->next;
                    FD_CLR(temp->fd, &all_rfds);
                    FD_CLR(temp->fd, &all_wfds);
                    _mio_close(temp);
                    continue;
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
            {
                temp = cur;
                cur = cur->next;
                FD_CLR(temp->fd, &all_rfds);
                FD_CLR(temp->fd, &all_wfds);
                _mio_close(temp);
                continue;
            }

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


    if(mio__data == NULL)
    {
        register_beat(KARMA_HEARTBEAT, _karma_heartbeat, NULL);
        register_beat(1, _timeout_heartbeat, NULL);

        /* malloc our instance object */
        p            = pool_new();
        mio__data    = pmalloco(p, sizeof(_ios));
        mio__data->p = p;

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
    mio cur;

    log_debug(ZONE, "MIO is shutting down");

    /* no need to do anything if mio__data hasn't been used yet */
    if(mio__data == NULL) 
        return;

    /* flag that it is okay to exit the loop */
    mio__data->shutdown = 1;

    /* loop each socket, and close it */
    for(cur = mio__data->master__list; cur != NULL; cur = cur->next)
    {
        _mio_close(cur);
    }

    /* signal the loop to end */
    pth_abort(mio__data->t);

    pool_free(mio__data->p);
    mio__data = NULL;
}

/* 
   creates a new mio object from a file descriptor
*/
mio mio_new(int fd, mio_cb cb, void *arg)
{
    mio  new            = NULL;
    pool p              = NULL;
    int flags           = 0;

    if(fd <= 0) 
        return NULL;
    
    /* create the new MIO object */
    p           = pool_heap(8192);
    new         = pmalloco(p, sizeof(_mio));
    new->p      = p;
    new->type   = type_NORMAL;
    new->state  = state_ACTIVE;
    new->fd     = fd;
    new->cb     = (void*)cb;
    new->cb_arg = arg;

    /* set the default karma values */
    mio_karma(new, KARMA_INIT, KARMA_MAX, KARMA_INC, KARMA_DEC, KARMA_PENALTY, KARMA_RESTORE);
    
    /* set the socket to non-blocking */
    flags =  fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);

    /* add to the select loop */
    _mio_link(new);

    /* notify the select loop */
    if(mio__data != NULL)
        pth_raise(mio__data->t, SIGUSR2);

    return new;
}

/*
   resets the callback function
*/
mio mio_reset(mio m, mio_cb cb, void *arg)
{
    if(m == NULL) 
        return NULL;

    m->cb     = (void*)cb;
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
        pth_raise(mio__data->t, SIGUSR2);
}

/* 
 * writes a str, or xmlnode to the client socket 
 */
void mio_write(mio m, xmlnode x, char *buffer, int len)
{
    mio_wbq new;
    pool p;

    log_debug(ZONE, "mio_write called on x: %X buffer: %s", x, buffer);

    if(m == NULL) 
        return;

    /* if there is nothing to write */
    if(x == NULL && buffer == NULL)
        return;

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
    }
    else
    {
        new->type = queue_XMLNODE;
    }

    /* assign values */
    new->x    = x;
    new->data = pstrdup(new->p, buffer);
    new->cur  = new->data;
    
    /* find the len of the queue item */
    if(len == -1 && buffer != NULL)
    {
        new->len = strlen(buffer);
    }
    /* if this is an xmlnode, this len gets set by the xml2str len prior to writing */
    else
    {
        new->len = len;
    }

    /* put at end of queue */
    if(m->tail == NULL)
    {
        m->queue = new;
        m->tail = new;
    }
    else
    {
        m->tail->next = new;
        m->tail = new;
    }

    /* notify the select loop that a packet needs writing */
    if(mio__data != NULL)
        pth_raise(mio__data->t, SIGUSR2);
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

    m->k.val     = k->val;
    m->k.max     = k->max;
    m->k.inc     = k->inc;
    m->k.dec     = k->dec;
    m->k.penalty = k->penalty;
    m->k.restore = k->restore;
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
}

/*
   pops the last xmlnode from the queue 
*/
xmlnode mio_cleanup(mio m)
{
    mio_wbq     cur;
    
    if(m == NULL) 
        return NULL;

    /* find the first queue item with a xmlnode attached */
    for(cur = m->queue; cur != NULL;)
    {
        /* if there is no node attached */
        if(cur->x == NULL)
        {
            /* just kill this item, and move on..
             * only pop xmlnodes 
             */
            mio_wbq next = cur->next;
            pool_free(cur->p);
            cur = next;
            continue;
        }

        /* move the queue up */
        m->queue = cur->next;

        /* set the tail pointer if needed */
        if(m->queue == NULL)
            m->tail = NULL;

        /* and pop this xmlnode */
        return cur->x;
    }

    /* no xmlnodes found */
    return NULL;
}

/* 
 * request to connect to a remote host 
 */
mio mio_connect(char *host, int port, mio_cb cb, int timeout, void *arg)
{
    mio                new  = NULL;
    pth_event_t        evt;
    struct sockaddr_in sa;
    struct in_addr     *saddr;
    int                fd,
                       flag = 1;

    log_debug(ZONE, "mio_connect Connecting to host: %s:%d", host, port);

    bzero((void*)&sa, sizeof(struct sockaddr_in));

    /* create a socket to connect with */
    fd = socket(AF_INET, SOCK_STREAM,0);

    /* set socket options */
    if(fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&flag, sizeof(flag)) < 0)
        return NULL;

    saddr = make_addr(host);
    if(saddr == NULL)
        return NULL;

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = saddr->s_addr;

    /* wait a max of 5 seconds for this connect */
    evt = pth_event(PTH_EVENT_TIME, pth_timeout(timeout,0));

    /* attempt to connect to the remote host */
    if(pth_connect_ev(fd, (struct sockaddr*)&sa, sizeof sa, evt) < 0)
    {
        log_debug(ZONE, "io_select connect failed to connect to: %s", host);
        close(fd);
        return NULL;
    }

    /* make sure we got a valid fd */
    if(fd <= 0)
    {
        log_debug(ZONE, "io_select connect failed to connect to: %s", host);
        close(fd);
        return NULL;
    }

    /* create the mio for this socket */
    new = mio_new(fd, cb, arg);

    /* notify the client that the socket is born */
    if(new->cb != NULL)
        (*(mio_cb)new->cb)(new, MIO_NEW, new->cb_arg, NULL, 0);

    return new;
}

/* 
 * call to start listening with select 
 */
mio mio_listen(int port, char *listen_host, mio_cb cb, void *arg)
{
    mio        new;
    int        fd;

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
    new       = mio_new(fd, cb, arg);
    new->type = type_LISTEN;

    log_debug(ZONE, "io_select starting to listen on %d [%s]", port, listen_host);

    return new;
}

void mio_add_timer(mio m, int seconds)
{
    pool p = pool_new();
    mio_timer mt = pmalloco(p, sizeof(_mio_timer));

    mt->mempool = p;
    mt->time_left = seconds;
    mt->m = m;

    _get_timer_lock();
    _mio_add_timer(mt);
    _release_timer_lock();
}

void mio_remove_timer(mio m)
{
    mio_timer mt;
    _get_timer_lock();
    /* While there's stuff in the list and the current one isn't the one we're looking
       for, keep walking */
    for (mt = G_head; (mt != NULL) && (mt->m != m); mt = mt->next); /*empty statement*/
    if (mt != NULL) 
    { /* Found it! */
	_mio_remove_timer(mt);
    }
    _release_timer_lock();
}

/* Create a new MIO object based on existing FD */
mio mio_new_xml(int fd, mio_xml_cb cb, void* cb_arg)
{
    mio result = mio_new(fd, (mio_cb)cb, cb_arg);

    return _mio_xstream_init(result);
}

/* Create a new MIO object by opening a TCP connection */
mio mio_connect_xml(char* host, int port, mio_xml_cb cb, int timeout, void* cb_arg)
{
    mio result = mio_connect(host, port, (mio_cb)cb, timeout, cb_arg);
    
    return _mio_xstream_init(result);
}

/* Create a new MIO object that listens on a TCP port */
mio mio_listen_xml(int port, char* sourceip, mio_xml_cb cb, void* cb_arg)
{
    mio result = mio_listen(port, sourceip, (mio_cb)cb, cb_arg);

    return _mio_xstream_init(result);
}

