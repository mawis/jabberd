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

#include <dlfcn.h>

#include "jabberd.h"

xmlnode base_load__cache = NULL;

/* process entire load element, loading each one (unless already cached) */
/* if all loaded, exec each one in order */

/* they register a handler to accept incoming xmlnodes that get delivered to them */
/* base_load sends packets on when it receives them */

void *base_load_loader(char *file)
{
    void *so_h;
    char *dlerr;

    /* load the dso */
    so_h = dlopen(file,RTLD_LAZY);

    /* check for a load error */
    dlerr = dlerror();
    if(dlerr != NULL)
    {
        fprintf(stderr,"Loading %s failed: '%s'\n",file,dlerr);
        return NULL;
    }

    xmlnode_put_vattrib(base_load__cache, file, so_h); /* fun hack! yes, it's just a nice name-based void* array :) */
    return so_h;
}

void *base_load_symbol(char *func, char *file)
{
    void (*func_h)(instance i, void *arg);
    void *so_h;
    char *dlerr;

    if(func == NULL || file == NULL)
        return NULL;

    if((so_h = xmlnode_get_vattrib(base_load__cache, file)) == NULL && (so_h = base_load_loader(file)) == NULL)
        return NULL;

    /* resolve a reference to the dso's init function */
    func_h = dlsym(so_h, func);

    /* check for error */
    dlerr = dlerror();
    if(dlerr != NULL)
    {
        fprintf(stderr,"Executing %s() in %s failed: '%s'\n",func,file,dlerr);
        return NULL;
    }

    return func_h;
}

result base_load_config(instance id, xmlnode x, void *arg)
{
    xmlnode so;
    char *init = xmlnode_get_attrib(x,"main");
    void *f;
    int flag = 0;

    if(id != NULL)
    { /* execution phase */
        f = xmlnode_get_vattrib(x, init);
        ((base_load_init)f)(id, x); /* fire up the main function for this extension */
        return r_PASS;
    }

    log_debug(ZONE,"base_load_config processing configuration %s\n",xmlnode2str(x));

    for(so = xmlnode_get_firstchild(x); so != NULL; so = xmlnode_get_nextsibling(so))
    {
        if(xmlnode_get_type(so) != NTYPE_TAG) continue;

        if(init == NULL && flag)
            return r_ERR; /* you can't have two elements in a load w/o a main attrib */

        f = base_load_symbol(xmlnode_get_name(so), xmlnode_get_data(so));
        if(f == NULL)
            return r_ERR;
        xmlnode_put_vattrib(x, xmlnode_get_name(so), f); /* hide the function pointer in the <load> element for later use */
        flag = 1;

        /* if there's only one .so loaded, it's the default, unless overridden */
        if(init == NULL)
            xmlnode_put_attrib(x,"main",xmlnode_get_name(so));
    }

    if(!flag) return r_ERR; /* we didn't DO anything, duh */

    return r_PASS;
}

void base_load(void)
{
    log_debug(ZONE,"base_load loading...\n");

    /* init global cache */
    base_load__cache = xmlnode_new_tag("so_cache");

    register_config("load",base_load_config,NULL);
}



/************ BELOW IS UTILITY SYMBOLS FOR LOADED MODULES ***************/

/* CREATE an xdb blocked ring
each entry has a new int and is placed as the id="int" value
incoming results are intercepted and that entry is unblocked
some sort of timer that scans the ring oldest to newest, resending stale requests
timeout xdb requests after a while, unblock and newx.data is still NULL
start sending logs depending on length of staleness
*/

result xdb_results(instance id, dpacket p, void *arg)
{
    xdbcache xc = (xdbcache)arg;
    xdbcache curx;
    int idnum;
    char *idstr;

    if(p->type != p_NORM || *(xmlnode_get_name(p->x)) != 'x') return r_PASS;

    log_debug(ZONE,"xdb_results checking xdb packet %s",xmlnode2str(p->x));

    if((idstr = xmlnode_get_attrib(p->x,"id")) == NULL) return r_ERR;

    idnum = atoi(idstr);

    for(curx = xc->next; curx->id != idnum && curx != xc; curx = curx->next); /* spin till we are where we started or find our id# */

    /* we got an id we didn't have cached, could be a dup, ignore and move on */
    if(curx->id != idnum)
    {
        pool_free(p->p);
        return r_DONE;
    }

    /* associte packet w/ waiting cache */
    curx->data = p->x;

    /* remove from ring */
    curx->prev->next = curx->next;
    curx->next->prev = curx->prev;

    /* free the thread! */
    curx->preblock = 0;
    if(curx->cond != NULL)
        pth_cond_notify(curx->cond, FALSE);

    return r_DONE; /* we processed it */
}

xdbcache xdb_cache(instance id)
{
    xdbcache newx;

    if(id == NULL)
    {
        fprintf(stderr,"Programming Error: xdb_cache() called with NULL\n");
        return NULL;
    }

    newx = pmalloco(id->p, sizeof(_xdbcache));
    newx->i = id; /* flags it as the top of the ring too */
    newx->next = newx->prev = newx; /* init ring */

    /* register the handler in the instance to filter out xdb results */
    register_phandler(id, o_PRECOND, xdb_results, (void *)newx);

    return newx;
}

/* blocks until namespace is retrieved, host must map back to this service! */
xmlnode xdb_get(xdbcache xc, char *host, jid owner, char *ns)
{
    _xdbcache newx;
    xmlnode x;
    char ids[9];
    pth_mutex_t mutex = PTH_MUTEX_INIT;
    pth_cond_t cond = PTH_COND_INIT;
    jid dude;

    if(xc == NULL || owner == NULL || ns == NULL)
    {
        fprintf(stderr,"Programming Error: xdb_get() called with NULL\n");
        return NULL;
    }

    /* init this newx */
    newx.i = NULL;
    newx.data = NULL;
    newx.host = host;
    newx.ns = ns;
    newx.owner = owner;
    newx.sent = time(NULL);
    newx.preblock = 1; /* flag */
    newx.cond = NULL;

    /* in the future w/ real threads, would need to lock xc to make these changes to the ring */
    newx.id = xc->id++;
    newx.next = xc->next;
    newx.prev = xc;
    newx.next->prev = &newx;
    xc->next = &newx;

    /* create the xml and deliver the xdb get request */
    x = xmlnode_new_tag("xdb");
    dude = jid_new(xmlnode_pool(x),jid_full(owner));
    jid_set(dude,ns,JID_RESOURCE);
    xmlnode_put_attrib(x,"type","get");
    xmlnode_put_attrib(x,"to",jid_full(dude));
    xmlnode_put_attrib(x,"from",host);
    sprintf(ids,"%d",newx.id);
    xmlnode_put_attrib(x,"id",ids); /* to track response */
    deliver(dpacket_new(x), xc->i);

    /* if it hasn't already returned, we should block here until it returns */
    if(newx.preblock)
    {
        newx.cond = &cond;
        pth_mutex_acquire(&mutex, FALSE, NULL);
        pth_cond_await(&cond, &mutex, NULL); /* blocks thread */
    }

    /* newx.data is now the returned xml packet */

    /* return the xmlnode inside <xdb>...</xdb> */
    for(x = xmlnode_get_firstchild(newx.data); x != NULL && xmlnode_get_type(x) != NTYPE_TAG; x = xmlnode_get_nextsibling(x));

    /* there were no children (results) to the xdb request, free the packet */
    if(x == NULL)
        xmlnode_free(newx.data);

    return x;
}

/* sends new xml to replace old, data is NOT freed, app responsible for freeing it */
int xdb_set(xdbcache xc, char *host, jid owner, char *ns, xmlnode data)
{
    _xdbcache newx;
    xmlnode x;
    char ids[9];
    pth_mutex_t mutex = PTH_MUTEX_INIT;
    pth_cond_t cond = PTH_COND_INIT;
    jid dude;

    if(xc == NULL || host == NULL || owner == NULL || ns == NULL || data == NULL)
    {
        fprintf(stderr,"Programming Error: xdb_set() called with NULL\n");
        return 1;
    }

    /* init this newx */
    newx.i = NULL;
    newx.data = data;
    newx.host = host;
    newx.ns = ns;
    newx.owner = owner;
    newx.sent = time(NULL);
    newx.preblock = 1; /* flag */
    newx.cond = NULL;

    /* in the future w/ real threads, would need to lock xc to make these changes to the ring */
    newx.id = xc->id++;
    newx.next = xc->next;
    newx.prev = xc;
    newx.next->prev = &newx;
    xc->next = &newx;

    /* create the xml and deliver the xdb get request */
    x = xmlnode_new_tag("xdb");
    dude = jid_new(xmlnode_pool(x),jid_full(owner));
    jid_set(dude,ns,JID_RESOURCE);
    xmlnode_put_attrib(x,"type","set");
    xmlnode_put_attrib(x,"to",jid_full(owner));
    xmlnode_put_attrib(x,"from",host);
    sprintf(ids,"%d",newx.id);
    xmlnode_put_attrib(x,"id",ids); /* to track response */
    xmlnode_insert_tag_node(x,data); /* copy in the data */
    deliver(dpacket_new(x), xc->i);

    /* if it hasn't already returned, we should block here until it returns */
    if(newx.preblock)
    {
        newx.cond = &cond;
        pth_mutex_acquire(&mutex, FALSE, NULL);
        pth_cond_await(&cond, &mutex, NULL); /* blocks thread */
    }

    /* newx.data is now the returned xml packet or NULL if it was unsuccessful */

    /* if it didn't actually get set, flag that */
    if(newx.data == NULL)
        return 1;

    xmlnode_free(newx.data);
    return 0;
}

/*** mtq is Managed Thread Queues ***/
/* they queue calls to be run sequentially on a thread, that comes from a system pool of threads */

/* cleanup a queue when it get's free'd */
void mtq_cleanup(void *arg)
{
    mtq q = (mtq)arg;

    /* if there's a thread using us, make sure we disassociate ourselves with them */
    if(q->t != NULL)
        q->t->q = NULL;
}

/* public queue creation function, queue lives as long as the pool */
mtq mtq_new(pool p)
{
    mtq q;

    if(p == NULL) return NULL;

    /* create queue */
    q = pmalloco(p, sizeof(_mtq));

    /* register cleanup handler */
    pool_cleanup(p, mtq_cleanup, (void *)q);

    return q;
}

typedef struct mtqcall_struct
{
    pth_message_t head; /* the standard pth message header */
    mtq_callback f; /* function to run within the thread */
    void *arg; /* the data for this call */
} _mtqcall, *mtqcall;

void *mtq_main(void *arg);

/* manage a master list of available threads */
mth mtq_threads(mth context)
{
    static mth avail[MTQ_THREADS];
    static int init = 1;
    int n;
    mth t;
    pool p;

    if(init)
    { /* initialize the array the first time we enter the function */
        for(n=0;n<MTQ_THREADS;n++)
            avail[n] = NULL;
        init = 0;
    }

    /* NULL means that this is a query for a waiting thread */
    if(context == NULL)
    {
        for(n=0;n<MTQ_THREADS;n++)
            if(avail[n] != NULL)
            { /* got a waiting thread, clear and return it */
                t = avail[n];
                avail[n] = NULL;
                return t;
            }

        /* make a new thread */
        p = pool_new();
        t = pmalloco(p, sizeof(_mth));
        t->p = p;
        t->mp = pth_msgport_create("mth");
        pth_spawn(PTH_ATTR_DEFAULT, mtq_main, (void *)t);
        return t;
    }

    /* if we're here, context is a thread looking to go back into the avail array */

    /* scan the avail list for an open spot */
    for(n=0;n<MTQ_THREADS && avail[n] != NULL; n++);

    /* if we couldn't get it put back in, return it to flag an exit */
    if(n+1 == MTQ_THREADS)
        return context;

    avail[n] = context;
    return NULL;
}

/* main slave thread */
void *mtq_main(void *arg)
{
    mth t = (mth)arg;
    pth_event_t mpevt;
    mtqcall c;

    log_debug(ZONE,"THREAD:WORKER %X starting",t->mp);

    /* create an event ring for receiving messges */
    mpevt = pth_event(PTH_EVENT_MSG,t->mp);

    /* loop */
    while(1)
    {
    
        /* debug: note that we're waiting for a message */
        log_debug(ZONE,"MTQ(%X)->pth",t->mp);

        /* wait for a message on the port */
        pth_wait(mpevt);

        /* debug: note that we found one */
        log_debug(ZONE,"pth->MTQ(%X)",t->mp);

        /* process the waiting packets */
        while((c = (mtqcall)pth_msgport_get(t->mp)) != NULL)
        {
            (*(c->f))(c->arg);
        }

        /* disassociate the thread and queue since we processed all the packets */
        /* XXX future pthreads note: mtq_send() could have put another call on the queue since we exited the while, that would be bad */
        if(t->q != NULL)
        {
            t->q->t = NULL;
            t->q = NULL;
        }

        /* return to pool or exit */
        if(mtq_threads(t) == t)
            break;
    }

    log_debug(ZONE,"THREAD:WORKER %X exiting",t->mp);

    /* free all memory stuff associated with the thread */
    pth_event_free(mpevt,PTH_FREE_ALL);
    pth_msgport_destroy(t->mp);
    pool_free(t->p);
    return NULL;
}

void mtq_send(mtq q, pool p, mtq_callback f, void *arg)
{
    mtqcall c;
    mth t = NULL;

    /* track this call */
    c = pmalloco(p, sizeof(_mtqcall));
    c->f = f;
    c->arg = arg;

    /* go thread huntin' */
    if(q != NULL)
    {
        /* if the queue already knows it's thread */
        if(q->t != NULL)
            t = q->t;
        else
            t = q->t = mtq_threads(NULL);

        /* make sure the thread knows it's queue */
        t->q = q;
    }else{
        t = mtq_threads(NULL);
    }

    /* send call to the queue */
    pth_msgport_put(t->mp, (pth_message_t *)c);
}

