#include <jabberd.h>

#define PSBACKLOG 10
#define PSTHREAD_MAX 10
#define PSBUFFSZ 1024

typedef struct __stream
{
    struct __stream *next;
    pool p;
    int fd;
    pth_event_t fdevt;
    xstream xs;
} _stream, *stream;

typedef struct __smsg
{
    pth_message_t head;
    stream s;
    void *data;
    int sz;
} _smsg, *smsg;

typedef struct _stnode
{
    pth_msgport_t mp;
    struct _stnode *next;
} *stnode;

stnode sthead;
int stsz;
int stsz_max = PSTHREAD_MAX;
pth_attr_t default_attr;

void pthsockman_mpsend(smsg m)
{
    static pth_msgport_t write_mp = NULL;

    if (write_mp == NULL) write_mp = pth_msgport_find("pthsockman_main");
    pth_msgport_put(write_mp,(void *) m);     /* send to main thread */
}

int pthsockman_write(stream s, void *data, int sz)
{
    smsg m;

    if(data == NULL || sz == 0 || s == NULL)
    {
        printf("pthsockman_write(): Programing error, NULL arguments\n");
        return 0;
    }

    if (s->fd < 0)
    {
        printf("pthsockman can't write data socket is closed\n");
        return 0;
    }

    if(sz < 0) sz = strlen(data);

    m = malloc(sizeof(_smsg));
    m->s = s;
    m->data = strdup(data);
    m->sz = sz;

    pthsockman_mpsend(m);
    return 1;
}

void pthsockman_close(stream s)
{
    smsg m;

    if (s->fd == -1) return;   /* already closed */

    m = malloc(sizeof(_smsg));
    m->s = s;
    m->data = NULL;
    m->sz = 0;    /* hack to signal close */

    pthsockman_mpsend(m);
}

void pthsockman_xread(int type, xmlnode x, void *arg)
{
    stream s = (stream) arg;

    printf("xread %d\n",s->fd);

    switch(type)
    {
    case XSTREAM_ERR:
        printf("xstream error\n");
        pthsockman_close(s);
        break;
    case XSTREAM_CLOSE:
        printf("xstream close\n");
        pthsockman_close(s);
        break;
    case XSTREAM_ROOT:
        printf("xstream root: %s\n",xmlnode2str(x));
        xmlnode_free(x);
        break;
    case XSTREAM_NODE:
        printf("xstream node: %s\n",xmlnode2str(x));
        pthsockman_write(s,"<node/>",-1);
        xmlnode_free(x);
        break;
    }
}

stream pthsockman_accecpt(int fd)
{
    pool p;
    stream s;

    p = pool_new();
    s = pmalloc(p,sizeof(_stream));
    memset(s, '\0',sizeof(_stream));

    s->fd = fd;
    s->p = p;
    s->fdevt = NULL;
    s->xs = xstream_new(p, pthsockman_xread,(void *)s);   /* XXX xstream callback hardcoded */

    return s;
}

/* This thread listen's on a port and accepts new connections.  it then notifies
   the main thread when there is a new connections so it can be added to the main
   thread's list of connections */
void pthsockman_acceptor(void *arg)
{
    stream s;
    smsg m;
    pth_msgport_t mp;
    struct sockaddr_in sa;
    size_t sa_size = sizeof(sa);
    int sock, fd;

    sock = (int) arg;
    printf("pthsockman listening on %d\n",sock);

    mp = pth_msgport_find("pthsockman_main_add");
    while (1)
    {
        fd = pth_accept(sock,(struct sockaddr *) &sa,(int *)&sa_size);
        if(fd < 0)
        {
            printf("Error occured while accepting new connection\n");
            /* XXX What now?? */
            break;
        }

        printf("pthsockman new connection:%d\n",fd);

        s = pthsockman_accecpt(fd);
        m = (smsg) malloc(sizeof(_smsg));
        m->s = s;
        pth_msgport_put(mp,(void *) m);
    }
}

/* this thread is used to parse received XML in */
void pthsockman_stmain(void *arg)
{
    pth_msgport_t mp = (pth_msgport_t) arg;
    pth_event_t ev_msg;
    smsg m;
    stnode cur;
    int exit;

    ev_msg = pth_event(PTH_EVENT_MSG, mp);

    printf("stmain[%X] starting\n",(int)mp);

    while (1)
    {
        pth_wait(ev_msg);

        printf("stmain[%X] event\n",(int)mp);

        while (1)
        {
            m = (smsg) pth_msgport_get(mp);
            if (m == NULL) break;

            xstream_eat(m->s->xs,(char*)m->data,m->sz);

            free(m);
        }

        printf("stmain[%X] done\n",(int)mp);

        exit = 1;
        if (stsz != stsz_max)
            for (cur = sthead;cur != NULL; cur = cur->next)   /* Try to add to the idle thread pool */
                if (cur->mp == NULL)
                {
                    ++stsz;
                    cur->mp = mp;
                    exit = 0;
                    break;
                }

        if (exit == 1) break;   /* Idle pool is full */
    }

    printf("stmain[%X] exiting\n",(int)mp);

    pth_msgport_destroy(mp);
    pth_event_free(ev_msg, PTH_FREE_ALL);
}

pth_msgport_t pthsockman_stget(void)
{
    pth_msgport_t mp;
    stnode cur;

    /* Check the idle thread pool first */
    for (cur = sthead; cur != NULL; cur = cur->next)
        if (cur->mp != NULL)
        {
            --stsz;
            mp = cur->mp;
            cur->mp = NULL;
            return mp;
        }

    mp = pth_msgport_create("__sthread_port");
    pth_spawn(default_attr, (void *) pthsockman_stmain, (void *) mp);

    return mp;
}

void pthsockman_main(void *arg)
{
    stream shead, cur, s, prev;
    pth_msgport_t mp, write_mp, add_mp;
    pth_event_t wevt, aevt, evt_ring;
    char *data;
    ssize_t sz;
    int fd, occurc, write_flag, rmcount;
    smsg m;

    printf("pthsockman_main starting\n");

    shead = NULL;
    write_mp = pth_msgport_create("pthsockman_main");
    add_mp = pth_msgport_create("pthsockman_main_add");
    wevt = pth_event(PTH_EVENT_MSG,write_mp);
    aevt = pth_event(PTH_EVENT_MSG,add_mp);
    evt_ring = pth_event_concat(wevt,aevt,NULL);
    write_flag = rmcount = 0;
    data = malloc(PSBUFFSZ);

    while (1)
    {
        occurc = pth_wait(evt_ring);

        if (pth_event_occurred(aevt))
        {
            --occurc;
            while (1)   /* Add accecpted connections */
            {
                m = (smsg) pth_msgport_get(add_mp);
                if (m == NULL) break;

                printf("accept event\n");

                s = m->s;
                s->fdevt = pth_event(PTH_EVENT_FD | PTH_UNTIL_FD_READABLE,s->fd);
                pth_event_concat(evt_ring,s->fdevt,NULL);

                s->next = shead;
                shead = s;
                break;
            }
            if (!occurc) continue;
        }

        if (pth_event_occurred(wevt))
        {
            --occurc;
            write_flag = 1;
        }

        if (occurc || rmcount)   /* read */
            for (cur = shead, prev = NULL; cur != NULL;  prev = cur, cur = cur->next)
            {
                fd = cur->fd;
                if (fd == -1)   /* this stream is closed and needs to be removed */
                {
                    stream temp;
                    printf("pthsockman removing connection\n");
                    
                    --rmcount;
                    temp = cur;
                    if (prev == NULL)
                    {
                        shead = cur->next;
                        if (shead == NULL) break;
                        cur = cur->next;
                    }
                    else
                    {
                        prev->next = cur->next;
                        if (prev->next == NULL) break;   /* this is the end */
                        cur = prev->next;
                    }
                    pool_free(temp->p);

                    if (!occurc && !rmcount)   /* Nothing left to do */
                        break;

                    continue;
                }

                if (!occurc) continue; /* There is no data to read, but streams to remove */

                if (pth_event_occurred(cur->fdevt))
                {
                    sz = pth_read(cur->fd, data,PSBUFFSZ - 1);
                    if (sz > 0)
                    {
                        data[sz] = '\0';
                        printf("read event: %d bytes\n",sz);

                        m = (smsg) malloc(sizeof(_smsg));
                        m->s = cur;
                        m->data = data;
                        m->sz = sz;
                        mp = pthsockman_stget();
                        pth_msgport_put(mp,(void*)m);
                    }
                    else
                    {
                        if (sz < 0)
                            printf("socket '%d' error '%s'\n",fd,strerror(errno));
                        else
                            printf("socket '%d' closed\n", cur->fd);

                        ++rmcount;
                        pth_event_free(cur->fdevt,PTH_FREE_THIS);
                        cur->fd = -1;
                        break;
                    }
                }
            }  /* end read */

        if (!write_flag) continue;
        write_flag = 0;

        while (1)   /* write */
        {
            m = (smsg) pth_msgport_get(write_mp);
            if (m == NULL) break;

            s = m->s;
            if (s->fd == -1)
            {
                printf("pthsockman socket already closed!\n");   
                /* XXX bounce?? */
            }
            else if(m->sz == 0)
            {
                printf("pthsockman closing socket\n");

                ++rmcount;
                pth_event_free(s->fdevt,PTH_FREE_THIS);
                close(s->fd);
                s->fd = -1; /* mark this stream for removal/closed */
            }
            else
            {
                int sent = 0;
                while (sent != m->sz)
                {
                    sz = pth_write(s->fd, m->data + sent,m->sz - sent);
                    if(sz < 0)
                    {
                        printf("stream write error '%s' on socket: %d\n",strerror(errno),s->fd);

                        ++rmcount;
                        pth_event_free(s->fdevt,PTH_FREE_THIS);
                        s->fd = -1;
                        break;
                    }
                    else
                        sent += sz;
                }
            }
            free(m);
        }
    }    /* End main loop */
}

int pthsockman_listen(char *host, u_short port)
{
    int sock;
    static int flag = 0;

    sock = make_netsocket(port, host, NETSOCKET_SERVER);

    if (listen(sock,PSBACKLOG) < 0)
    {
        printf("Error listening on %s:%d '%s'\n",host,port,strerror(errno));
        return -1;
    }

    if (flag == 0)
    {
        default_attr = pth_attr_new();
        pth_attr_set(default_attr, PTH_ATTR_JOINABLE, FALSE);
        pth_spawn(default_attr, (void *)pthsockman_main, NULL);
        flag = 1;
        pth_yield(NULL);
    }

    pth_spawn(default_attr, (void *)pthsockman_acceptor, (void *)sock);
    return 0;
}

#ifdef PSM_TEST

int main()
{
    sigset_t set;
    int sig;

    pth_init();
    pthsockman_listen(NULL,5222);

    sigemptyset(&set);
    sigaddset(&set,SIGTERM);
    pth_sigmask(SIG_UNBLOCK,&set,NULL);

    pth_sigwait(&set,&sig);

    return 0;
}

#endif
