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

#include "io.h"

pth_mutex_t m_sync=PTH_MUTEX_INIT;

typedef struct io_st
{
    pool p;
    int master_fd;
    sock master__list;
    io_cb cb;
    void *cb_arg;
    void *arg;
    pth_msgport_t wmp;
} _ios,*ios;

sock io_select_get_list(iosi io_instance)
{
    return ((ios)io_instance)->master__list;
}

int _io_write_dump(sock c)
{
    int len,retval;
    wbq q;

    pth_mutex_acquire(&m_sync,0,NULL);
    if(c->wbuffer==NULL) {
        if(c->xbuffer!=NULL) xmlnode_free(c->xbuffer);
        q=(wbq)pth_msgport_get(c->queue);
        if(q==NULL) return 0;
        c->xbuffer=q->x;
        c->wbuffer=xmlnode2str(c->xbuffer);
        c->cbuffer=c->wbuffer;
    }

    while(1) /* while there is more in the queue */
    {
        len=write(c->fd,c->cbuffer,strlen(c->cbuffer));
        log_debug(ZONE,"dumped %d bytes of %d",len,strlen(c->wbuffer));
        if(len<=0)
        { /* error occured while writing the packet */
            if(errno!=EWOULDBLOCK)
            { /* error writing to the socket, bounce the queue */
                (*(io_cb)c->cb)(c,NULL,0,IO_ERROR,c->cb_arg);
            }
            pth_mutex_release(&m_sync);
            return -1;
        }
        else if(len<strlen(c->cbuffer))
        { /* we didn't write the whole thing.. wait till later */
            c->cbuffer+=len;
            pth_mutex_release(&m_sync);
            return 1;
        } 
        else
        { /* current write buffer is empty, keep going */
            xmlnode_free(c->xbuffer);
            q=(wbq)pth_msgport_get(c->queue);
            if(q==NULL)
            {
                c->xbuffer=NULL;
                c->wbuffer=c->cbuffer=NULL;
                pth_mutex_release(&m_sync);
                return 0;
            }
            c->xbuffer=q->x;
            c->wbuffer=xmlnode2str(c->xbuffer);
            c->cbuffer=c->wbuffer;
        }
    }

    pth_mutex_release(&m_sync);
    return retval;
}

void io_unlink(sock c)
{
    ios io_data=(ios)c->iodata;
    log_debug(ZONE,"Unlinking sock %d from master__list",c->fd);

    if(io_data->master__list==c) io_data->master__list=io_data->master__list->next;
    if(c->prev!=NULL) c->prev->next=c->next;
    if(c->next!=NULL) c->next->prev=c->prev;
}

void io_link(sock c)
{
    ios io_data=(ios)c->iodata;

    pth_mutex_acquire(&m_sync,0,NULL);
    log_debug(ZONE,"Linking %d, welcome aboard!",c->fd);
    c->next=io_data->master__list;
    c->prev=NULL;
    io_data->master__list=c;
    pth_mutex_release(&m_sync);
}

void io_close(sock c) 
{
    log_debug(ZONE,"client requesting close socket %d",c->fd);
    c->state=state_CLOSE;
}

void _io_close(sock c)
{
    c->state=state_UNKNOWN;
    pth_mutex_acquire(&m_sync,0,NULL);
    io_unlink(c);
    log_debug(ZONE,"closing socket '%d'",c->fd);

    /* if we still have packets in our buffer, bounce them */
    if(c->xbuffer!=NULL)
        (*(io_cb)c->cb)(c,NULL,0,IO_ERROR,c->cb_arg);

    (*(io_cb)c->cb)(c,NULL,0,IO_CLOSED,c->cb_arg);

    write(c->fd,"</stream:stream>",16);

    close(c->fd);
    pool_free(c->p);
    pth_mutex_release(&m_sync);
}

/* write a str to the client socket */
void io_write_str(sock c,char *buffer)
{
    pool p=pool_heap(2*1024);
    drop d=pmalloco(p,sizeof(_drop));
    d->p=p;

    d->x=NULL;
    d->c=c;
    pth_mutex_acquire(&m_sync,0,NULL);
    if(c->wbuffer!=NULL) _io_write_dump(c);
    write(c->fd,buffer,strlen(buffer));
    pth_mutex_release(&m_sync);
}

/* write an xmlnode */
void io_write(sock c,xmlnode x)
{
    ios io_data=(ios)c->iodata;
    wbq q;

    q=pmalloco(xmlnode_pool(x),sizeof(_wbq));
    if(c->xbuffer!=NULL)
    {
        q->x=x;
        pth_msgport_put(c->queue,(void*)q); /* write packet to queue */
    }
    else
    {
        c->xbuffer=x;
        c->wbuffer=xmlnode2str(x);
        c->cbuffer=c->wbuffer;
    }
    pth_msgport_put(io_data->wmp,(void*)q); /* notify select */
}

typedef struct connect_st
{
    pool p;
    sock c;
    char *host;
    int port;
} _conn_st, *conn_st;

void _io_select_connect(void *arg)
{
    conn_st cst=(conn_st)arg;
    sock c=cst->c;
    ios io_data=(ios)c->iodata;
    pth_event_t evt;
    struct sockaddr_in sa;
    struct in_addr *saddr;
    int fd,flag=1;
    int flags;
    drop d;
    pool p;

    log_debug(ZONE,"_io_select_connect HOST: %s",cst->host);

    bzero((void*)&sa,sizeof(struct sockaddr_in));

    if((fd=socket(AF_INET,SOCK_STREAM,0))<0)
    {
        (*(io_cb)c->cb)(c,NULL,0,IO_ERROR,c->cb_arg);
        return;
    }
    if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,(char*)&flag,sizeof(flag))<0)
    {
        (*(io_cb)c->cb)(c,NULL,0,IO_ERROR,c->cb_arg);
        return;
    }

    saddr=make_addr(cst->host);
    if(saddr==NULL)
    {
        (*(io_cb)c->cb)(c,NULL,0,IO_ERROR,c->cb_arg);
        return;
    }

    sa.sin_family=AF_INET;
    sa.sin_port=htons(cst->port);
    sa.sin_addr.s_addr=saddr->s_addr;

    /* wait a max of 10 seconds for this connect */
    evt=pth_event(PTH_EVENT_TIME,pth_timeout(10,0));
    if(pth_connect_ev(fd,(struct sockaddr*)&sa,sizeof sa,evt) < 0)
    {
        log_debug(ZONE,"io_select connect failed to connect to: %s",cst->host);
        close(fd);
        (*(io_cb)c->cb)(c,NULL,0,IO_ERROR,c->cb_arg);
        return;
    }
    else
    {
        /* set to non-blocking */
        flags=fcntl(fd,F_GETFL,0);
        flags|=O_NONBLOCK;
        fcntl(fd,F_SETFL,flags);
        c->fd=fd;
        io_link(c);
        (*(io_cb)c->cb)(c,NULL,0,IO_NEW,c->cb_arg);
    }
    /* notify the select loop */
    p=pool_heap(2*1024);
    d=pmalloco(p,sizeof(_drop));
    d->p=p;
    d->x=NULL;
    d->c=c;
    pth_msgport_put(io_data->wmp,(void*)d);
}

void io_select_connect(iosi io_instance,char *host, int port,void *arg)
{
    sock c;
    ios io_data=(ios)io_instance;
    pool p=pool_heap(2*1024);
    conn_st cst=pmalloco(p,sizeof(_conn_st));
    cst->host=pstrdup(p,host);
    cst->port=port;
    c=pmalloco(p,sizeof(_sock));
    c->p=p;
    c->arg=arg;
    c->cb=io_data->cb;
    c->cb_arg=io_data->cb_arg;
    c->iodata=io_data;
    cst->c=c;
    
    pth_spawn(PTH_ATTR_DEFAULT,(void*)_io_select_connect,(void*)cst);
}

sock _io_sock(int fd)
{
    pool p;
    sock c;

    p = pool_heap(2*1024);
    c = pmalloco(p, sizeof(_sock));
    c->p = p;
    c->fd = fd;
    c->state = state_UNKNOWN;

    log_debug(ZONE,"new socket created for fd: %d",fd);

    return c;
}

sock _io_accept(ios io_data,int asock)
{
    struct sockaddr_in sa;
    size_t sa_size = sizeof(sa);
    int fd,flags;
    sock c;
    pth_mutex_acquire(&m_sync,0,NULL);
    fd = accept(asock,(struct sockaddr*)&sa,(int*)&sa_size);
    if(fd < 0)
    {
        pth_mutex_release(&m_sync);
        return NULL; 
    }

    flags=fcntl(fd,F_GETFL,0);
    flags|=O_NONBLOCK;
    fcntl(fd,F_SETFL,flags);

    log_debug(ZONE,"pthsock_client: new socket accepted (fd: %d, ip: %s, port: %d)",fd,inet_ntoa(sa.sin_addr),ntohs(sa.sin_port));

    c = _io_sock(fd);
    c->iodata=(void*)io_data;
    c->cb=io_data->cb;
    c->cb_arg=io_data->cb_arg;
    if(c!=NULL) io_link(c);
    pth_mutex_release(&m_sync);
    return c;
}

void _io_main(void *arg)
{
    ios io_data=(ios)arg;
    pth_event_t wevt;       /* the pth event for the mp */
    fd_set wfds,rfds, all_wfds,all_rfds; /* writes, reads, all */
    sock cur, c,temp;    
    drop d;
    char buff[1024];
    int len, asock;
    int maxfd=0;

    asock = io_data->master_fd;
    maxfd=asock;

    FD_ZERO(&all_wfds);
    FD_ZERO(&all_rfds);
    FD_SET(asock,&all_rfds);

    wevt = pth_event(PTH_EVENT_MSG,io_data->wmp);

    (*(io_cb)io_data->cb)(NULL,NULL,0,IO_INIT,NULL); 

    while (1)
    {
        log_debug(ZONE,"%d:%d Watching %d total sockets",asock,maxfd,maxfd-asock);
        rfds=all_rfds;
        wfds=all_wfds;
        pth_select_ev(maxfd+1,&rfds,&wfds,NULL,NULL,wevt);

        pth_mutex_acquire(&m_sync,0,NULL); 

        /* handle packets that need to be written */
        if (pth_event_occurred(wevt))
        {
            log_debug(ZONE,"Select notified of a write waiting");
            /* do nothing, this was just to get out of select */
            while ((d=(drop)pth_msgport_get(io_data->wmp))!=NULL);
        }

        maxfd=asock;

        FD_ZERO(&all_rfds); /* reset our "all" set */
        FD_SET(asock,&all_rfds);

        if (FD_ISSET(asock,&rfds)) /* new connection */
        {
            c=_io_accept(io_data,asock);
            if(c!=NULL) 
            {
               (*(io_cb)c->cb)(c,NULL,0,IO_NEW,c->cb_arg);
               FD_SET(c->fd,&all_rfds);           
               if(c->fd>maxfd)maxfd=c->fd;
            }
        }

        cur = io_data->master__list;
        log_debug(ZONE,"looping through sockets");
        while(cur != NULL)
        {
            log_debug(ZONE,"Checking socket %d",cur->fd);
            FD_SET(cur->fd,&all_rfds);
            if(cur->state==state_CLOSE)
            {
                temp=cur;
                cur=cur->next;
                _io_close(temp);
                FD_CLR(temp->fd,&all_rfds);
                FD_CLR(temp->fd,&all_wfds);
                continue;
            }
            if (FD_ISSET(cur->fd,&rfds))
            { /* we need to read from a socket */
                log_debug(ZONE,"read event for %d",cur->fd);
                len = read(cur->fd,buff,sizeof(buff));
                if(len<=0)
                {
                    if(errno==EWOULDBLOCK){log_debug(ZONE,"Not Blocking read");}
                    else
                    {
                        temp=cur;
                        cur=cur->next;
                        log_debug(ZONE,"Error reading on '%d', %s",temp->fd,strerror(errno));
                        FD_CLR(temp->fd,&all_rfds);
                        FD_CLR(temp->fd,&all_wfds);
                        _io_close(temp);
                        continue;
                    }
                }
                else
                {
                    log_debug(ZONE,"read %d bytes: %s",len,buff);
                    (*(io_cb)cur->cb)(cur,buff,len,IO_NORMAL,cur->cb_arg);
                }
                if(cur->state==state_CLOSE)
                {
                    temp=cur;
                    cur=cur->next;
                    _io_close(temp);
                    FD_CLR(temp->fd,&all_rfds);
                    FD_CLR(temp->fd,&all_wfds);
                    continue;
                }
            }
            else if(FD_ISSET(cur->fd,&wfds))
            { /* ooo, we are ready to dump the rest of the data */
                int ret=_io_write_dump(cur);
                if(ret<0)
                {
                    if(errno==EWOULDBLOCK) FD_SET(cur->fd,&all_wfds);
                    else
                    {
                        temp=cur;
                        cur=cur->next;
                        log_debug(ZONE,"error writing to socket %d:%s",temp->fd,strerror(errno));
                        FD_CLR(temp->fd,&all_rfds);
                        FD_CLR(temp->fd,&all_wfds);
                        _io_close(temp);
                        continue;
                    }
                }
                else if(!ret) FD_CLR(cur->fd,&all_wfds);
                else FD_SET(cur->fd,&all_wfds);
            }

            if(cur->wbuffer!=NULL) FD_SET(cur->fd,&all_wfds);
            else FD_CLR(cur->fd,&all_wfds);
            if(cur->fd>maxfd)maxfd=cur->fd;
            cur = cur->next;
        }
        pth_mutex_release(&m_sync);
    }
    log_debug(ZONE,"This will never get here");
    pth_event_free(wevt,PTH_FREE_THIS);
}

/* everything starts here */
iosi io_select(int port,io_cb cb,void *arg)
{
    ios io_data;
    iosi ret;
    pool p=pool_heap(2*1024);
    pth_attr_t attr;
    int fd;
    int flags;

    log_debug(ZONE,"io_select to listen on %d [%X]",port,(void*)cb);

    io_data = pmalloco(p,sizeof(_ios));

    /* write mp */
    io_data->wmp=pth_msgport_create("io_master__wmp");
    io_data->p=p;
    io_data->cb=cb;
    io_data->cb_arg=arg;

    fd = make_netsocket(port,NULL,NETSOCKET_SERVER);
    if(fd < 0)
    {
        log_error(NULL,"io_select is unable to listen on %d",port);
        pool_free(p);
        return NULL;
    }

    if(listen(fd,10) < 0)
    {
        log_error(NULL,"io_select is unable to listen on %d",port);
        pool_free(p);
        return NULL;
    }

    (flags=fcntl(fd,F_GETFL,0));
    flags|=O_NONBLOCK;
    fcntl(fd,F_SETFL,flags);

    io_data->master_fd = fd;

    attr = pth_attr_new();
    pth_attr_set(attr,PTH_ATTR_JOINABLE,FALSE);

    /* start main accept/read/write thread */
    pth_spawn(attr,(void*)_io_main,(void*)io_data);

    pth_attr_destroy(attr);

    ret=pmalloco(p,sizeof(iosi));
    ret=(iosi)io_data;

    return ret;
}
