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


typedef struct io_st
{
    pool p;
    int master_fd;
    sock master__list;
    pth_t t;
    io_cb cb;
    void *cb_arg;
    void *arg;
} _ios,*ios;

sock io_select_get_list(iosi io_instance)
{
    return ((ios)io_instance)->master__list;
}

int _io_write_dump(sock c)
{
    int len;
    wbq q;

    log_debug(ZONE,"IO WRITE DUMP FOR SOCK %X",c);
    /* if there is nothing currently being written... */
    if(c->xbuffer==NULL) {
        log_debug(ZONE,"Current xbuffer NULL");
        /* grab the next packet from the queue */
        c->wbuffer=c->cbuffer=NULL;
        q=(wbq)pth_msgport_get(c->queue);
        log_debug(ZONE,"Grabbed %X queue item",q);
        if(q==NULL) return 0;
        log_debug(ZONE,"Making %X packet current xbuffer",q->x);
        c->xbuffer=q->x;
        c->wbuffer=xmlnode2str(c->xbuffer);
        c->cbuffer=c->wbuffer;
    }
    else
    {
        log_debug(ZONE,"packet %X is already in queue",c->xbuffer);
        /* if we haven't started writing, setup to write */
        if(c->wbuffer==NULL) c->wbuffer=xmlnode2str(c->xbuffer);
        if(c->cbuffer==NULL) c->cbuffer=c->wbuffer;
    }

    while(1)
    {
        log_debug(ZONE,"Calling write on %X",c->xbuffer);
        /* write a bit from the current buffer */
        len=write(c->fd,c->cbuffer,strlen(c->cbuffer));
        if(len<=0)
        { 
            log_debug(ZONE,"Error while writing %X",c->xbuffer);
            if(errno!=EWOULDBLOCK)
            { /* if we have an error, that isn't a blocking issue */ 
                log_debug(ZONE,"bouncing queue");
                (*(io_cb)c->cb)(c,NULL,0,IO_ERROR,c->cb_arg); /* bounce the queue */
            }
            return -1;
        }
        else if(len<strlen(c->cbuffer))
        {  /* we didnt' write it all, move the current buffer up */
            log_debug(ZONE,"Not finished writing %X",c->xbuffer);
            c->cbuffer+=len;
            return 1;
        } 
        else
        {  /* all this was written, kill this node */
            log_debug(ZONE,"Freeing %X, pool %X",c->xbuffer,xmlnode_pool(c->xbuffer));
            xmlnode_free(c->xbuffer);
            /* and grab the next... */
            log_debug(ZONE,"Looking for more packets");
            q=(wbq)pth_msgport_get(c->queue);
            log_debug(ZONE,"Grabbed queue item %X",q);
            if(q==NULL)
            { /* we are done writing nodes */
                log_debug(ZONE,"Done with io dump");
                c->xbuffer=NULL;
                c->wbuffer=c->cbuffer=NULL;
                return 0;
            }
            log_debug(ZONE,"current packet set to %X",q->x);
            c->xbuffer=q->x;
            c->wbuffer=xmlnode2str(c->xbuffer);
            c->cbuffer=c->wbuffer;
        }
    }
}

void io_unlink(sock c)
{
    ios io_data=(ios)c->iodata;

    if(io_data->master__list==c) io_data->master__list=io_data->master__list->next;
    if(c->prev!=NULL) c->prev->next=c->next;
    if(c->next!=NULL) c->next->prev=c->prev;

}

void io_link(sock c)
{
    ios io_data=(ios)c->iodata;

    c->next=io_data->master__list;
    c->prev=NULL;
    if(io_data->master__list!=NULL) io_data->master__list->prev=c;
    io_data->master__list=c;
}

void io_close(sock c) 
{
    c->state=state_CLOSE;
}

void _io_close(sock c)
{
    io_unlink(c);
    log_debug(ZONE,"closing socket %X",c);

    /* bounce the current queue */
    if(c->xbuffer!=NULL)
        (*(io_cb)c->cb)(c,NULL,0,IO_ERROR,c->cb_arg);

    /* notify of the close */
    (*(io_cb)c->cb)(c,NULL,0,IO_CLOSED,c->cb_arg);

    write(c->fd,"</stream:stream>",16);

    close(c->fd);
    pool_free(c->p);
}

/* write a str to the client socket */
void io_write_str(sock c,char *buffer)
{
    /* write a string Immediatly to the socket */
    /* flush the current queue first, if not empty */
    log_debug(ZONE,"io_write_str called while wbuffer is %X",c->wbuffer);
    if(c->wbuffer!=NULL)_io_write_dump(c);
    log_debug(ZONE,"wbuffer is %X after dump",c->wbuffer);
    write(c->fd,buffer,strlen(buffer));
}

/* write an xmlnode */
void io_write(sock c,xmlnode x)
{
    ios io_data=(ios)c->iodata;
    wbq q;

    log_debug(ZONE,"IO_WRITE CALLED ON %X",x);
    if(c->xbuffer!=NULL)
    { /* if there is alredy a packet being written */
        log_debug(ZONE,"Data in xbuffer already, adding %X to queue",x);
        q=pmalloco(xmlnode_pool(x),sizeof(_wbq));
        q->x=x;
        /* add it to the queue */
        pth_msgport_put(c->queue,(void*)q); 
    }
    else
    { /* otherwise, just make it our current packet */
        log_debug(ZONE,"No xbuffer, making %X current xbuffer",x);
        c->xbuffer=x;
    }
    /* notify the select loop that a packet needs writing */
    pth_raise(io_data->t,SIGINT);
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

    log_debug(ZONE,"io_select Connecting to host: %s",cst->host);

    bzero((void*)&sa,sizeof(struct sockaddr_in));

    if((fd=socket(AF_INET,SOCK_STREAM,0))<0)
    {
        (*(io_cb)c->cb)(c,NULL,0,IO_ERROR,c->cb_arg);
        (*(io_cb)c->cb)(c,NULL,0,IO_CLOSED,c->cb_arg);
        pool_free(c->p);
        return;
    }
    if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,(char*)&flag,sizeof(flag))<0)
    {
        (*(io_cb)c->cb)(c,NULL,0,IO_ERROR,c->cb_arg);
        (*(io_cb)c->cb)(c,NULL,0,IO_CLOSED,c->cb_arg);
        pool_free(c->p);
        return;
    }

    saddr=make_addr(cst->host);
    if(saddr==NULL)
    {
        (*(io_cb)c->cb)(c,NULL,0,IO_ERROR,c->cb_arg);
        (*(io_cb)c->cb)(c,NULL,0,IO_CLOSED,c->cb_arg);
        pool_free(c->p);
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
        (*(io_cb)c->cb)(c,NULL,0,IO_ERROR,c->cb_arg);
        (*(io_cb)c->cb)(c,NULL,0,IO_CLOSED,c->cb_arg);
        close(fd);
        pool_free(c->p);
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
    pth_raise(io_data->t,SIGINT);
}

void io_select_connect(iosi io_instance,char *host, int port,void *arg)
{
    sock c;
    ios io_data=(ios)io_instance;
    pool p=pool_new();
    conn_st cst=pmalloco(p,sizeof(_conn_st));
    cst->host=pstrdup(p,host);
    cst->port=port;
    c=pmalloco(p,sizeof(_sock));
    c->queue=pth_msgport_create("queue");
    c->p=p;
    c->arg=arg;
    c->cb=io_data->cb;
    c->cb_arg=io_data->cb_arg;
    c->iodata=io_data;
    cst->c=c;
    
    pth_spawn(PTH_ATTR_DEFAULT,(void*)_io_select_connect,(void*)cst);
}

sock _io_accept(ios io_data,int asock)
{
    struct sockaddr_in sa;
    size_t sa_size = sizeof(sa);
    int fd,flags;
    sock c;
    pool p;

    fd = accept(asock,(struct sockaddr*)&sa,(int*)&sa_size);
    if(fd <= 0)
    {
        return NULL; 
    }

    flags=fcntl(fd,F_GETFL,0);
    flags|=O_NONBLOCK;
    fcntl(fd,F_SETFL,flags);

    log_debug(ZONE,"pthsock_client: new socket accepted (fd: %d, ip: %s, port: %d)",fd,inet_ntoa(sa.sin_addr),ntohs(sa.sin_port));


    p = pool_new();
    c = pmalloco(p, sizeof(_sock));
    log_debug(ZONE,"new sock created as %X",c);
    c->queue=pth_msgport_create("queue");
    c->p = p;
    c->fd = fd;
    c->state = state_UNKNOWN;
    c->iodata=(void*)io_data;
    c->cb=io_data->cb;
    c->cb_arg=io_data->cb_arg;
    io_link(c);
    c->p = p;
    return c;
}

void _io_main(void *arg)
{
    ios io_data=(ios)arg;
    pth_event_t wevt;
    fd_set wfds,rfds, all_wfds,all_rfds; /* writes, reads, all */
    sigset_t sigs;
    int sig;
    sock cur, c,temp;    
    char buff[1024];
    int len, asock;
    int maxfd=0;

    asock = io_data->master_fd;
    maxfd=asock;

    FD_ZERO(&all_wfds);
    FD_ZERO(&all_rfds);
    FD_SET(asock,&all_rfds);

    sigemptyset(&sigs);
    sigaddset(&sigs,SIGINT);
    wevt=pth_event(PTH_EVENT_SIGS,&sigs,&sig);

    (*(io_cb)io_data->cb)(NULL,NULL,0,IO_INIT,NULL); 

    while (1)
    {
        rfds=all_rfds;
        wfds=all_wfds;
        pth_select_ev(maxfd+1,&rfds,&wfds,NULL,NULL,wevt);

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
        while(cur != NULL)
        {
            if(cur->state==state_CLOSE)
            {
                temp=cur;
                cur=cur->next;
                FD_CLR(temp->fd,&all_rfds);
                FD_CLR(temp->fd,&all_wfds);
                _io_close(temp);
                continue;
            }
            FD_SET(cur->fd,&all_rfds);
            if (FD_ISSET(cur->fd,&rfds))
            { /* we need to read from a socket */
                len = read(cur->fd,buff,sizeof(buff));
                if(len<=0)
                {
                    if(errno==EWOULDBLOCK) FD_SET(cur->fd,&all_rfds);
                    else
                    {
                        temp=cur;
                        cur=cur->next;
                        FD_CLR(temp->fd,&all_rfds);
                        FD_CLR(temp->fd,&all_wfds);
                        _io_close(temp);
                        continue;
                    }
                }
                else
                {
                    buff[len]='\0';
                    (*(io_cb)cur->cb)(cur,buff,len,IO_NORMAL,cur->cb_arg);
                }
            }
            else if(FD_ISSET(cur->fd,&wfds)||cur->xbuffer!=NULL)
            { 
                /* write the current buffer */
                int ret=_io_write_dump(cur);
                if(ret<0)
                {
                    if(errno==EWOULDBLOCK) FD_SET(cur->fd,&all_wfds);
                    else
                    {
                        temp=cur;
                        cur=cur->next;
                        FD_CLR(temp->fd,&all_rfds);
                        FD_CLR(temp->fd,&all_wfds);
                        _io_close(temp);
                        continue;
                    }
                }
                else if(!ret) FD_CLR(cur->fd,&all_wfds);
                else FD_SET(cur->fd,&all_wfds);
            }
            /* we may have wanted the socket closed after this operation */
            if(cur->state==state_CLOSE)
            {
                temp=cur;
                cur=cur->next;
                FD_CLR(temp->fd,&all_rfds);
                FD_CLR(temp->fd,&all_wfds);
                _io_close(temp);
                continue;
            }
            /* if there are packets to be written, wait for a write slot */
            if(cur->xbuffer!=NULL) FD_SET(cur->fd,&all_wfds);
            else FD_CLR(cur->fd,&all_wfds);

            if(cur->fd>maxfd)maxfd=cur->fd;
            cur = cur->next;
        }
    }
    pth_event_free(wevt,PTH_FREE_THIS);
}

/* everything starts here */
iosi io_select(int port,io_cb cb,void *arg)
{
    ios io_data;
    iosi ret;
    pool p=pool_new();
    pth_attr_t attr;
    int fd;
    int flags;

    log_debug(ZONE,"io_select to listen on %d [%X]",port,(void*)cb);

    io_data = pmalloco(p,sizeof(_ios));

    /* write mp */
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
    io_data->t=pth_spawn(attr,(void*)_io_main,(void*)io_data);

    pth_attr_destroy(attr);

    ret=pmalloco(p,sizeof(iosi));
    ret=(iosi)io_data;

    return ret;
}
