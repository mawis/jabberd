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
} _ios,*ios;

ios io__data=NULL;

result karma_heartbeat(void*arg)
{
    sock cur;
    if(io__data==NULL||io__data->master__list==NULL) return r_DONE;
    for(cur=io__data->master__list;cur!=NULL;cur=cur->next)
    {
        if(cur->state==state_CLOSE) continue;
        cur->karma++;
        if(cur->karma>0)cur->read_bytes-=(cur->karma*100);
        if(cur->read_bytes<0)cur->read_bytes=0;
        if(cur->karma==0) 
            pth_raise(io__data->t,SIGUSR2);
        if(cur->karma>10)cur->karma=10; /* can only be so good */
        if(cur->karma<0)log_notice("karma","sock %d is getting karma, now %d",cur->fd,cur->karma);
    }
    return r_DONE;
}


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
    if(io__data==NULL) return;
    if(io__data->master__list==c)
       io__data->master__list=io__data->master__list->next;
    if(c->prev!=NULL) c->prev->next=c->next;
    if(c->next!=NULL) c->next->prev=c->prev;
}

/* link a socket to the master list */
void io_link(sock c)
{
    if(io__data==NULL) return;
    c->next=io__data->master__list;
    c->prev=NULL;
    if(io__data->master__list!=NULL) io__data->master__list->prev=c;
    io__data->master__list=c;
}

/* client call to close the socket */
void io_close(sock c) 
{
    c->state=state_CLOSE;
    if(io__data!=NULL)pth_raise(io__data->t,SIGUSR2);
}

/* internal close function */
void _io_close(sock c)
{
    int ret=0;
    c->state=state_CLOSE;
    io_unlink(c);

    /* try to write what's in the queue */
    if(c->xbuffer!=NULL) ret=_io_write_dump(c);

    /* if we didn't write it all, bounce the current queue */
    if(ret==1) (*(io_cb)c->cb)(c,NULL,0,IO_ERROR,c->cb_arg);

    /* notify of the close */
    (*(io_cb)c->cb)(c,NULL,0,IO_CLOSED,c->cb_arg);

    write(c->fd,"</stream:stream>",16);

    close(c->fd);
    if(c->rated) jlimit_free(c->rate);
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


    if(s->rated&&jlimit_check(s->rate,inet_ntoa(sa.sin_addr),1))
    {
        log_warn("io_select","%s is being connection rate limited",inet_ntoa(sa.sin_addr));
        close(fd);
        return NULL;
    }

    log_debug(ZONE,"new socket accepted (fd: %d, ip: %s, port: %d)",fd,inet_ntoa(sa.sin_addr),ntohs(sa.sin_port));

    p = pool_new();
    c = pmalloco(p, sizeof(_sock));
    c->karma=-10;
    c->queue=pth_msgport_create("queue");
    c->p = p;
    c->fd = fd;
    c->state = state_ACTIVE;
    c->type=type_NORMAL;
    c->cb=s->cb;
    c->cb_arg=s->cb_arg;
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
    int len,maxlen;
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

        cur=io__data->master__list;
        while(cur != NULL)
        {
            if((!FD_ISSET(cur->fd,&all_rfds)&&cur->karma==0)||cur->karma==-10)
            {
                cur->karma=5;
                log_notice("io_select","socket #%d has karma again",cur->fd);
                FD_SET(cur->fd,&all_rfds); /* they can read again */
            }
            pth_yield(NULL);
            if(cur->state==state_CLOSE)
            {
                temp=cur;
                cur=cur->next;
                FD_CLR(temp->fd,&all_rfds);
                FD_CLR(temp->fd,&all_wfds);
                _io_close(temp);
                continue;
            }
            else if(FD_ISSET(cur->fd,&rfds)&&cur->type==type_LISTEN) 
            {   /* new connection */
                c=_io_accept(cur);
                if(c!=NULL) 
                {
                    (*(io_cb)c->cb)(c,NULL,0,IO_NEW,c->cb_arg);
                    io_link(c);
                    FD_SET(c->fd,&all_rfds);           
                    if(c->fd>maxfd)maxfd=c->fd;
                }
            }
            else if (FD_ISSET(cur->fd,&rfds))
            { /* we need to read from a socket */
                maxlen=cur->karma*100;
                len = read(cur->fd,buff,maxlen);
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
                    log_notice("io_select","%d: read: %d, max: %d, karma: %d, read_bytes: %d",cur->fd,len,maxlen,cur->karma,cur->read_bytes);
                    cur->read_bytes+=len;
                    if(cur->read_bytes>=maxlen)
                    { /* they read the max, tsk tsk */
                        cur->karma--;
                        if(cur->karma<=0) /* ran out of karma */
                        {
                            log_notice("io_select","socket #%d is out of karma",cur->fd);
                            cur->karma=-5; /* pay the penence */
                            FD_CLR(cur->fd,&all_rfds); 
                        }
                        log_notice("karma","sock %d lost karma, now %d",cur->fd,cur->karma);
                    }
                    buff[len]='\0';
                    (*(io_cb)cur->cb)(cur,buff,len,IO_NORMAL,cur->cb_arg);
                }
            }
            else if(FD_ISSET(cur->fd,&wfds)||cur->xbuffer!=NULL)
            {   /* write the current buffer */
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

/* struct passed to the connecting thread */
typedef struct connect_st
{
    pool p;
    sock c;
    char *host;
    int port;
} _conn_st, *conn_st;

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

    fd=socket(AF_INET,SOCK_STREAM,0);
    if(fd<0||setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,(char*)&flag,sizeof(flag))<0)
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

    /* wait a max of 5 seconds for this connect */
    evt=pth_event(PTH_EVENT_TIME,pth_timeout(5,0));
    if(pth_connect_ev(fd,(struct sockaddr*)&sa,sizeof sa,evt)<0)
    {
        log_debug(ZONE,"io_select connect failed to connect to: %s",cst->host);
        (*(io_cb)c->cb)(c,NULL,0,IO_ERROR,c->cb_arg);
        (*(io_cb)c->cb)(c,NULL,0,IO_CLOSED,c->cb_arg);
        close(fd);
        pool_free(c->p);
        return;
    }

    /* make sure we got a valid fd */
    if(fd<=0)
    {
        log_debug(ZONE,"io_select connect failed to connect to: %s",cst->host);
        (*(io_cb)c->cb)(c,NULL,0,IO_ERROR,c->cb_arg);
        (*(io_cb)c->cb)(c,NULL,0,IO_CLOSED,c->cb_arg);
        close(fd);
        pool_free(c->p);
        return;
    }

    /* set to non-blocking */
    flags=fcntl(fd,F_GETFL,0);
    flags|=O_NONBLOCK;
    fcntl(fd,F_SETFL,flags);
    c->fd=fd;

    if(io__data==NULL)
    {
        register_beat(2,karma_heartbeat,NULL);
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

    (*(io_cb)c->cb)(c,NULL,0,IO_NEW,c->cb_arg);
    io_link(c); /* link after we call new, to avoid race conditions */
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
    c->karma=-10;
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
void io_select_listen(int port,char *listen_host,io_cb cb,void *arg,int rate_time,int max_points)
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
        log_alert(NULL,"io_select unable to listen on %d [%s]",port,listen_host);
        return;
    }

    if(listen(fd,10) < 0)
    {
        log_alert(NULL,"io_select unable to listen on %d [%s]",port,listen_host);
        return;
    }

    (flags=fcntl(fd,F_GETFL,0));
    flags|=O_NONBLOCK;
    fcntl(fd,F_SETFL,flags);

    p=pool_new();
    new=pmalloco(p,sizeof(_sock));
    new->karma=-10;
    new->fd=fd;
    new->p=p;
    new->type=type_LISTEN;
    new->state=state_ACTIVE;
    new->queue=pth_msgport_create("queue");
    new->cb=cb;
    new->cb_arg=arg;
    if(rate_time!=0)
    {
        new->rated=1;
        new->rate=jlimit_new(rate_time,max_points);
    }

    log_notice(NULL,"io_select starting to listen on %d [%s]",port,listen_host);
    if(io__data==NULL)
    {
        register_beat(2,karma_heartbeat,NULL);
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
