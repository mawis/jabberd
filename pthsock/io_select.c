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
 *  Copyright (C) 1998-2000 The Jabber Team http://jabber.org/
 */

#include "io.h"

/* struct to hold data for our instance */
typedef struct io_st
{
    pool p;             /* pool to hold this data */
    sock master__list;  /* a list of all the socks */
    pth_t t;            /* a pointer to thread for signaling */
    void *arg;          /* hanging data */
} _ios,*ios;

ios io__data=NULL;

/* returns a list of all the sockets in this instance */
sock io_select_get_list(void)
{
    if(io__data==NULL) return NULL;
    return io__data->master__list;
}

/* dump as much of the write queue as we can */
int _io_write_dump(sock c)
{
    int len;
    wbq q;

    /* if there is nothing currently being written... */
    if(c->xbuffer==NULL) {
        /* grab the next packet from the queue */
        c->wbuffer=c->cbuffer=NULL;
        q=(wbq)pth_msgport_get(c->queue);
        if(q==NULL) return 0;
        c->xbuffer=q->x;
        c->wbuffer=xmlnode2str(c->xbuffer);
        c->cbuffer=c->wbuffer;
    }
    else if(((int)c->xbuffer)!=-1)
    {
        /* if we haven't started writing, setup to write */
        if(c->wbuffer==NULL) c->wbuffer=xmlnode2str(c->xbuffer);
        if(c->cbuffer==NULL) c->cbuffer=c->wbuffer;
    }

    while(1)
    {
        /* write a bit from the current buffer */
        len=write(c->fd,c->cbuffer,strlen(c->cbuffer));
        if(len==0)
        {
            (*(io_cb)c->cb)(c,NULL,0,IO_ERROR,c->cb_arg); /* bounce the queue */
            return -1;
        }
        if(len<0)
        { 
            if(errno!=EWOULDBLOCK&&errno!=EINTR&&errno!=EAGAIN)
            { /* if we have an error, that isn't a blocking issue */ 
                (*(io_cb)c->cb)(c,NULL,0,IO_ERROR,c->cb_arg); /* bounce the queue */
            }
            return -1;
        }
        else if(len<strlen(c->cbuffer))
        {  /* we didnt' write it all, move the current buffer up */
            c->cbuffer+=len;
            return 1;
        } 
        else
        {  /* all this was written, kill this node */
            pool_free(c->pbuffer);
            /* and grab the next... */
            q=(wbq)pth_msgport_get(c->queue);
            if(q==NULL)
            { /* we are done writing nodes */
                c->xbuffer=NULL;
                c->wbuffer=c->cbuffer=NULL;
                return 0;
            }
            if(q->type==queue_XMLNODE)
            {
                c->xbuffer=q->x;
                c->wbuffer=xmlnode2str(c->xbuffer);
                c->pbuffer=xmlnode_pool(q->x);
            }
            else /* if type is queue_TEXT */
            {
                ((int)c->xbuffer)=-1;
                c->wbuffer=q->data;
                c->pbuffer=q->p;
            }
            c->cbuffer=c->wbuffer;
        }
    }
}

/* unlink this socket from the master list */
void io_unlink(sock c)
{
    if(io__data->master__list==c) io__data->master__list=io__data->master__list->next;
    if(c->prev!=NULL) c->prev->next=c->next;
    if(c->next!=NULL) c->next->prev=c->prev;
}

/* link a socket to the master list */
void io_link(sock c)
{
    if(io__data!=NULL)
        c->next=io__data->master__list;
    else
        c->next=NULL;
    c->prev=NULL;
    if(io__data->master__list!=NULL) io__data->master__list->prev=c;
    io__data->master__list=c;
}

/* client call to close the socket */
void io_close(sock c) 
{
    /* XXX should this signal the select loop?? */
    c->state=state_CLOSE;
}

/* internal close function */
void _io_close(sock c)
{
    io_unlink(c);

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
    wbq q;
    pool p=pool_new();
    if(c->wbuffer!=NULL)
    {
        q=pmalloco(p,sizeof(_wbq));
        q->data=pstrdup(p,buffer);
        q->p=p;
        q->type=queue_TEXT;
        pth_msgport_put(c->queue,(void*)q); 
    }
    else
    { /* otherwise, just make it our current packet */
        ((int)c->xbuffer)=-1; /* hack to write text, so xbuffer != NULL */
        c->wbuffer=pstrdup(p,buffer);
        c->cbuffer=c->wbuffer;
        c->pbuffer=p;
    }
    /* notify the select loop that a packet needs writing */
    pth_raise(io__data->t,SIGUSR2);
}

/* adds an xmlnode to the write buffer */
void io_write(sock c,xmlnode x)
{
    wbq q;

    if(c->xbuffer!=NULL)
    { /* if there is alredy a packet being written */
        q=pmalloco(xmlnode_pool(x),sizeof(_wbq));
        q->type=queue_XMLNODE;
        q->p=xmlnode_pool(x);
        q->x=x;
        /* add it to the queue */
        pth_msgport_put(c->queue,(void*)q); 
    }
    else
    { /* otherwise, just make it our current packet */
        c->xbuffer=x;
        c->pbuffer=xmlnode_pool(x);
    }
    /* notify the select loop that a packet needs writing */
    pth_raise(io__data->t,SIGUSR2);
}

/* struct passed to the connecting thread */
typedef struct connect_st
{
    pool p;
    sock c;
    char *host;
    int port;
} _conn_st, *conn_st;


/* accept an incoming connection from a listen sock */
sock _io_accept(sock s)
{
    struct sockaddr_in sa;
    size_t sa_size = sizeof(sa);
    int fd,flags;
    sock c;
    pool p;

    fd = accept(s->fd,(struct sockaddr*)&sa,(int*)&sa_size);
    if(fd <= 0)
    { /* this will try again eventually */
        return NULL; 
    }

    flags=fcntl(fd,F_GETFL,0);
    flags|=O_NONBLOCK;
    fcntl(fd,F_SETFL,flags);

    log_debug(ZONE,"new socket accepted (fd: %d, ip: %s, port: %d)",fd,inet_ntoa(sa.sin_addr),ntohs(sa.sin_port));

    p = pool_new();
    c = pmalloco(p, sizeof(_sock));
    c->queue=pth_msgport_create("queue");
    c->p = p;
    c->fd = fd;
    c->state = state_ACTIVE;
    c->type=type_NORMAL;
    c->cb=s->cb;
    c->cb_arg=s->cb_arg;
    io_link(c);
    c->p = p;
    return c;
}

/* main select loop thread */
void _io_main(void *arg)
{
    fd_set wfds,rfds, all_wfds,all_rfds; /* writes, reads, all */
    pth_event_t wevt;
    sigset_t sigs;
    int sig;
    sock cur, c,temp;    
    char buff[1024];
    int len;
    int maxfd=0;

    /* init the signal junk */
    sigemptyset(&sigs);
    sigaddset(&sigs,SIGUSR2);
    pth_sigmask(SIG_BLOCK,&sigs,NULL);

    /* init the socket junk */
    maxfd=0;
    if(io__data->master__list!=NULL)maxfd=io__data->master__list->fd;
    FD_ZERO(&all_wfds);
    FD_ZERO(&all_rfds);
    if(maxfd!=0)FD_SET(maxfd,&all_rfds);
    
    wevt=pth_event(PTH_EVENT_SIGS,&sigs,&sig);

    /* init the client */
    if(io__data->master__list!=NULL)
        (*(io_cb)io__data->master__list->cb)(NULL,NULL,0,IO_INIT,NULL); 

    while (1)
    {
        rfds=all_rfds;
        wfds=all_wfds;
        pth_select_ev(maxfd+1,&rfds,&wfds,NULL,NULL,wevt);

        maxfd=0;
        FD_ZERO(&all_rfds); /* reset our "all" set */

        cur=io__data->master__list;
        while(cur != NULL)
        {
            FD_SET(cur->fd,&all_rfds);
            if(cur->state==state_CLOSE)
            {
                temp=cur;
                cur=cur->next;
                FD_CLR(temp->fd,&all_rfds);
                FD_CLR(temp->fd,&all_wfds);
                _io_close(temp);
                continue;
            }
            else if(FD_ISSET(cur->fd,&rfds)&&cur->type==type_LISTEN) /* new connection */
            {
                c=_io_accept(cur);
                if(c!=NULL) 
                {
                    (*(io_cb)c->cb)(c,NULL,0,IO_NEW,c->cb_arg);
                    FD_SET(c->fd,&all_rfds);           
                    if(c->fd>maxfd)maxfd=c->fd;
                }
            }
            else if (FD_ISSET(cur->fd,&rfds))
            { /* we need to read from a socket */
                len = read(cur->fd,buff,sizeof(buff));
                if(len==0)
                { /* i don't care what the errno is.. */
                  /* if we read 0, you're outta here! */
                    temp=cur;
                    cur=cur->next;
                    FD_CLR(temp->fd,&all_rfds);
                    FD_CLR(temp->fd,&all_wfds);
                    _io_close(temp);
                    continue;
                }
                if(len<0)
                { /* only check errno if -1 returned.. */
                  /* errno is undefined otherwise      */
                    if(errno==EWOULDBLOCK||errno==EINTR||errno==EAGAIN) 
                        FD_SET(cur->fd,&all_rfds);
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
                    if(errno==EWOULDBLOCK||errno==EINTR) FD_SET(cur->fd,&all_wfds);
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
}

/* pth thread to connect to a remote host */
/* if this were using pthreads, this wouldn't block the server */
void _io_select_connect(void *arg)
{
    conn_st cst=(conn_st)arg;
    sock c=cst->c;
    pth_event_t evt;
    struct sockaddr_in sa;
    struct in_addr *saddr;
    pool p;
    pth_attr_t attr;
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
    }

    if(io__data==NULL)
    {
        p=pool_new();
        io__data = pmalloco(p,sizeof(_ios));
        io__data->p=p;
        attr = pth_attr_new();
        pth_attr_set(attr,PTH_ATTR_JOINABLE,FALSE);

        /* start main accept/read/write thread */
        io__data->t=pth_spawn(attr,(void*)_io_main,(void*)io__data);
        pth_attr_destroy(attr);
        pth_yield(NULL);
    }

    io_link(c);
    (*(io_cb)c->cb)(c,NULL,0,IO_NEW,c->cb_arg);
    /* notify the select loop */
    pth_raise(io__data->t,SIGUSR2);
}

/* request to connect to a remote host */
void io_select_connect(char *host, int port,void* arg,io_cb cb,void *cb_arg)
{
    sock c;
    pool p=pool_new();
    conn_st cst=pmalloco(p,sizeof(_conn_st));
    cst->host=pstrdup(p,host);
    cst->port=port;
    c=pmalloco(p,sizeof(_sock));
    c->queue=pth_msgport_create("queue");
    c->type=type_NORMAL;
    c->state=state_ACTIVE;
    c->p=p;
    c->arg=arg;
    c->cb_arg=cb_arg;
    c->cb=cb;
    c->arg=arg;
    cst->c=c;
    
    pth_spawn(PTH_ATTR_DEFAULT,(void*)_io_select_connect,(void*)cst);
}

/* call to start listening with select */
void io_select_listen(int port,char *listen_host,io_cb cb,void *arg)
{
    sock new;
    pool p;
    pth_attr_t attr;
    int fd;
    int flags;

    log_debug(ZONE,"io_select to listen on %d [%s]",port,listen_host);


    fd = make_netsocket(port,listen_host,NETSOCKET_SERVER);
    if(fd < 0)
    {
        log_alert(NULL,"io_select is unable to listen on %d [%s]",port,listen_host);
        return;
    }

    if(listen(fd,10) < 0)
    {
        log_alert(NULL,"io_select is unable to listen on %d [%s]",port,listen_host);
        return;
    }

    (flags=fcntl(fd,F_GETFL,0));
    flags|=O_NONBLOCK;
    fcntl(fd,F_SETFL,flags);

    p=pool_new();
    new=pmalloco(p,sizeof(_sock));
    new->fd=fd;
    new->p=p;
    new->type=type_LISTEN;
    new->state=state_ACTIVE;
    new->queue=pth_msgport_create("queue");
    new->cb=cb;
    new->cb_arg=arg;


    log_notice(NULL,"io_select starting to listen on %d [%s]",port,listen_host);
    if(io__data==NULL)
    {
        p=pool_new();
        io__data = pmalloco(p,sizeof(_ios));
        io__data->p=p;
        attr = pth_attr_new();
        pth_attr_set(attr,PTH_ATTR_JOINABLE,FALSE);

        /* start main accept/read/write thread */
        io__data->t=pth_spawn(attr,(void*)_io_main,(void*)io__data);
        pth_attr_destroy(attr);
        pth_yield(NULL);
    }
    io_link(new);
    pth_raise(io__data->t,SIGUSR2); /* notify the select loop */
}
